//! Streaming secret redaction for child stdout/stderr.
//!
//! This is a best-effort data-loss-prevention layer, not a sandbox. It replaces
//! injected secret values (and common encodings: percent-encoded, base64,
//! JSON-escaped, hex) with `[VELT_REDACTED:KEY]`.
//!
//! Limitations (documented and intentional):
//! - Values shorter than 4 bytes are not redacted; doing so would corrupt
//!   ordinary output such as `true` or `dev`.
//! - Arbitrary transformations (hashing, chunking, encryption, character-wise
//!   printing) can evade any output filter. Do not treat redaction as a
//!   confinement boundary.
//! - The child can write to files or network sockets. Use OS sandboxing for
//!   hard guarantees.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use zeroize::Zeroizing;

const MIN_REDACT_BYTES: usize = 4;
const MAX_REDACT_SECRET_BYTES: usize = 64 * 1024;
const MAX_PATTERNS: usize = 4096;

/// Precomputed needles and replacement markers.
#[derive(Clone, Debug, Default)]
pub struct SecretPatterns {
    needles: Vec<Vec<u8>>,
    markers: Vec<Vec<u8>>,
    max_len: usize,
    pub skipped: usize,
}

impl SecretPatterns {
    pub fn from_pairs(pairs: &[(String, Zeroizing<String>)]) -> Self {
        let mut map: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut skipped = 0usize;

        for (name, value) in pairs {
            let raw = value.as_bytes();
            if raw.len() < MIN_REDACT_BYTES {
                continue;
            }
            if raw.len() > MAX_REDACT_SECRET_BYTES {
                skipped += 1;
                continue;
            }
            let marker = format!("[VELT_REDACTED:{name}]").into_bytes();
            map.entry(raw.to_vec()).or_insert_with(|| marker.clone());
            for variant in variants(value) {
                if variant.len() >= MIN_REDACT_BYTES && variant != raw {
                    map.entry(variant).or_insert_with(|| marker.clone());
                }
            }
            if map.len() >= MAX_PATTERNS {
                break;
            }
        }

        let mut needles = Vec::with_capacity(map.len());
        let mut markers = Vec::with_capacity(map.len());
        let mut max_len = 0usize;
        for (needle, marker) in map {
            max_len = max_len.max(needle.len());
            needles.push(needle);
            markers.push(marker);
        }
        Self {
            needles,
            markers,
            max_len,
            skipped,
        }
    }
}

fn variants(value: &str) -> Vec<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut variants = Vec::new();

    let percent = percent_encode(bytes);
    if percent != bytes {
        variants.push(percent);
    }

    variants.push(STANDARD.encode(bytes).into_bytes());
    variants.push(STANDARD_NO_PAD.encode(bytes).into_bytes());
    variants.push(URL_SAFE_NO_PAD.encode(bytes).into_bytes());

    if let Ok(json) = serde_json::to_string(value) {
        let escaped = json.trim_matches('"').as_bytes().to_vec();
        if escaped != bytes {
            variants.push(escaped);
        }
    }

    if bytes.len() >= 8 {
        variants.push(hex::encode(bytes).into_bytes());
    }

    variants
}

fn percent_encode(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = Vec::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(*byte);
        } else {
            encoded.push(b'%');
            encoded.push(HEX[(byte >> 4) as usize]);
            encoded.push(HEX[(byte & 0x0f) as usize]);
        }
    }
    encoded
}

/// Incremental streaming redactor with a carry buffer for patterns split across
/// read boundaries.
pub struct StreamRedactor {
    automaton: Option<AhoCorasick>,
    markers: Vec<Vec<u8>>,
    max_len: usize,
    buffer: Vec<u8>,
}

impl StreamRedactor {
    pub fn new(patterns: &SecretPatterns) -> Self {
        let automaton = if patterns.needles.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns.needles)
                .ok()
        };
        let max_len = if automaton.is_some() {
            patterns.max_len
        } else {
            0
        };
        Self {
            automaton,
            markers: patterns.markers.clone(),
            max_len,
            buffer: Vec::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        self.buffer.extend_from_slice(chunk);
        let Some(automaton) = &self.automaton else {
            out.extend_from_slice(&self.buffer);
            self.buffer.clear();
            return;
        };
        if self.max_len == 0 {
            out.extend_from_slice(&self.buffer);
            self.buffer.clear();
            return;
        }
        loop {
            let Some(found) = automaton.find(&self.buffer) else {
                let keep = self.max_len.saturating_sub(1);
                if self.buffer.len() > keep {
                    let emit = self.buffer.len() - keep;
                    out.extend_from_slice(&self.buffer[..emit]);
                    self.buffer.drain(..emit);
                }
                return;
            };

            // A match near the end may be a prefix of a longer pattern that
            // continues in the next chunk. Retain it until more data arrives.
            if self.buffer.len() - found.start() < self.max_len {
                if found.start() > 0 {
                    out.extend_from_slice(&self.buffer[..found.start()]);
                    self.buffer.drain(..found.start());
                }
                return;
            }

            out.extend_from_slice(&self.buffer[..found.start()]);
            out.extend_from_slice(&self.markers[found.pattern().as_usize()]);
            self.buffer.drain(..found.end());
        }
    }

    pub fn finish(mut self, out: &mut Vec<u8>) {
        let Some(automaton) = self.automaton.take() else {
            out.extend_from_slice(&self.buffer);
            return;
        };
        loop {
            let Some(found) = automaton.find(&self.buffer) else {
                out.extend_from_slice(&self.buffer);
                self.buffer.clear();
                return;
            };
            out.extend_from_slice(&self.buffer[..found.start()]);
            out.extend_from_slice(&self.markers[found.pattern().as_usize()]);
            self.buffer.drain(..found.end());
        }
    }
}

/// Copy `reader` to `writer`, redacting known secrets.
pub fn stream_scrubbed<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    patterns: &SecretPatterns,
) -> io::Result<()> {
    let mut redactor = StreamRedactor::new(patterns);
    let mut input = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut input)?;
        if read == 0 {
            break;
        }
        let mut output = Vec::with_capacity(read + 64);
        redactor.push(&input[..read], &mut output);
        if !output.is_empty() {
            writer.write_all(&output)?;
            writer.flush()?;
        }
    }
    let mut tail = Vec::new();
    redactor.finish(&mut tail);
    if !tail.is_empty() {
        writer.write_all(&tail)?;
        writer.flush()?;
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct CapturedOutput {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// Read all of `reader`, redacting secrets and retaining at most `limit` bytes.
pub fn capture_scrubbed<R: Read>(
    mut reader: R,
    patterns: &SecretPatterns,
    limit: usize,
) -> io::Result<CapturedOutput> {
    let mut redactor = StreamRedactor::new(patterns);
    let mut output = CapturedOutput::default();
    let mut input = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut input)?;
        if read == 0 {
            break;
        }
        let mut chunk = Vec::with_capacity(read + 64);
        redactor.push(&input[..read], &mut chunk);
        append_limited(&mut output, &chunk, limit);
    }
    let mut tail = Vec::new();
    redactor.finish(&mut tail);
    append_limited(&mut output, &tail, limit);
    Ok(output)
}

fn append_limited(output: &mut CapturedOutput, chunk: &[u8], limit: usize) {
    if output.bytes.len() >= limit {
        output.truncated = output.truncated || !chunk.is_empty();
        return;
    }
    let remaining = limit - output.bytes.len();
    if chunk.len() <= remaining {
        output.bytes.extend_from_slice(chunk);
    } else {
        output.bytes.extend_from_slice(&chunk[..remaining]);
        output.truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(values: &[(&str, &str)]) -> Vec<(String, Zeroizing<String>)> {
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Zeroizing::new((*value).to_owned())))
            .collect()
    }

    fn scrub(patterns: &SecretPatterns, chunks: &[&[u8]]) -> String {
        let mut redactor = StreamRedactor::new(patterns);
        let mut out = Vec::new();
        for chunk in chunks {
            redactor.push(chunk, &mut out);
        }
        redactor.finish(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn redacts_raw_values() {
        let patterns = SecretPatterns::from_pairs(&pairs(&[("API_KEY", "super-secret-value")]));
        let output = scrub(&patterns, &[b"token=super-secret-value\n"]);
        assert_eq!(output, "token=[VELT_REDACTED:API_KEY]\n");
    }

    #[test]
    fn redacts_across_chunk_boundaries() {
        let patterns = SecretPatterns::from_pairs(&pairs(&[("TOKEN", "abcdef123456")]));
        let output = scrub(&patterns, &[b"prefix abcd", b"ef123456 suffix"]);
        assert!(output.contains("[VELT_REDACTED:TOKEN]"));
        assert!(!output.contains("abcdef123456"));
    }

    #[test]
    fn redacts_encodings() {
        let secret = "secret with spaces";
        let encoded = percent_encode(secret.as_bytes());
        let encoded = String::from_utf8(encoded).unwrap();
        let patterns = SecretPatterns::from_pairs(&pairs(&[("TOKEN", secret)]));
        let output = scrub(&patterns, &[encoded.as_bytes()]);
        assert!(output.contains("[VELT_REDACTED:TOKEN]"));

        let b64 = STANDARD.encode(secret.as_bytes());
        let output = scrub(&patterns, &[b64.as_bytes()]);
        assert!(output.contains("[VELT_REDACTED:TOKEN]"));
    }

    #[test]
    fn short_values_are_not_redacted() {
        let patterns = SecretPatterns::from_pairs(&pairs(&[("MODE", "dev")]));
        assert!(patterns.max_len == 0);
        let output = scrub(&patterns, &[b"development"]);
        assert_eq!(output, "development");
    }

    #[test]
    fn capture_is_capped() {
        let patterns = SecretPatterns::from_pairs(&pairs(&[("TOKEN", "super-secret-value")]));
        let input = "x".repeat(100);
        let captured = capture_scrubbed(input.as_bytes(), &patterns, 10).unwrap();
        assert_eq!(captured.bytes.len(), 10);
        assert!(captured.truncated);
    }

    #[test]
    fn longest_match_wins() {
        let patterns = SecretPatterns::from_pairs(&pairs(&[
            ("A", "secret-value"),
            ("B", "secret-value-extra"),
        ]));
        let output = scrub(&patterns, &[b"secret-value-extra"]);
        assert!(output.contains("[VELT_REDACTED:B]"));
    }
}
