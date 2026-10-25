//! `.env` import parser used by `velt init`.
//!
//! Supports comments, `export KEY=value`, single/double quoting, basic escape
//! sequences and inline comments on unquoted values. It deliberately does not
//! evaluate `${VAR}` substitutions: the literal value is preserved so the vault
//! remains a faithful snapshot.

use std::fs;
use std::path::Path;

use velt_core::secret::SecretValue;
use velt_core::vault::validate_name;

use crate::error::{CliError, Result};

const MAX_ENV_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default)]
pub struct ParsedEnv {
    pub entries: Vec<(String, SecretValue)>,
    pub skipped: Vec<String>,
}

pub fn parse_file(path: &Path) -> Result<ParsedEnv> {
    let metadata = fs::metadata(path).map_err(|err| CliError::io(path, err))?;
    if metadata.len() > MAX_ENV_FILE_BYTES {
        return Err(CliError::msg(format!(
            "{} exceeds the 1 MiB .env import limit",
            path.display()
        )));
    }
    let contents = fs::read_to_string(path).map_err(|err| CliError::io(path, err))?;
    Ok(parse_contents(&contents))
}

pub fn parse_contents(contents: &str) -> ParsedEnv {
    let mut parsed = ParsedEnv::default();
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    for line in contents.lines().take(20_000) {
        let mut line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim_start();
        }
        let Some((name, raw_value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if validate_name(name).is_err() {
            if !name.is_empty() {
                parsed.skipped.push(name.to_owned());
            }
            continue;
        }
        let Some(value) = parse_value(raw_value) else {
            parsed.skipped.push(name.to_owned());
            continue;
        };
        parsed
            .entries
            .push((name.to_owned(), SecretValue::new(value)));
    }
    parsed
}

fn parse_value(raw: &str) -> Option<String> {
    let raw = raw.trim_start();
    if let Some(rest) = raw.strip_prefix('"') {
        let mut value = String::new();
        let mut characters = rest.chars();
        while let Some(character) = characters.next() {
            match character {
                '"' => return Some(value),
                '\\' => match characters.next()? {
                    'n' => value.push('\n'),
                    'r' => value.push('\r'),
                    't' => value.push('\t'),
                    '"' => value.push('"'),
                    '\\' => value.push('\\'),
                    '$' => value.push('$'),
                    other => {
                        value.push('\\');
                        value.push(other);
                    }
                },
                other => value.push(other),
            }
        }
        // Unterminated quote: skip the entry rather than guess.
        return None;
    }
    if let Some(rest) = raw.strip_prefix('\'') {
        let end = rest.find('\'')?;
        return Some(rest[..end].to_owned());
    }
    // Unquoted value: strip an inline comment introduced by whitespace + '#'.
    let mut end = raw.len();
    let bytes = raw.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] == b'#'
            && index > 0
            && (bytes[index - 1] == b' ' || bytes[index - 1] == b'\t')
        {
            end = index;
            break;
        }
    }
    Some(raw[..end].trim_end().to_owned())
}

/// Best-effort shredding of a plaintext `.env` file.
///
/// This overwrites the file contents with random bytes and unlinks it. On
/// copy-on-write filesystems, SSDs with wear levelling, or filesystems with
/// snapshots, physical erasure is not guaranteed. The caller must warn the
/// user; this function only does the honest software-level best effort.
pub fn shred(path: &Path) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let metadata = fs::metadata(path).map_err(|err| CliError::io(path, err))?;
    let length = metadata.len();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| CliError::io(path, err))?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut remaining = length;
    file.seek(SeekFrom::Start(0))
        .map_err(|err| CliError::io(path, err))?;
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        velt_core::crypto::fill_random(&mut buffer[..chunk])?;
        file.write_all(&buffer[..chunk])
            .map_err(|err| CliError::io(path, err))?;
        remaining -= chunk as u64;
    }
    file.sync_all().map_err(|err| CliError::io(path, err))?;
    drop(file);
    fs::remove_file(path).map_err(|err| CliError::io(path, err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_syntax() {
        let parsed = parse_contents(
            r#"
# comment
DATABASE_URL=postgres://localhost/app
export API_KEY="sk_live_abc123"
SINGLE='literal value'
EMPTY=
WITH_COMMENT=value # trailing comment
HASH_IN_VALUE=abc#def
ESCAPED="line1\nline2"
BAD-NAME=nope
"#,
        );
        let map: std::collections::BTreeMap<_, _> = parsed
            .entries
            .iter()
            .map(|(name, value)| (name.as_str(), value.expose().to_owned()))
            .collect();
        assert_eq!(map["DATABASE_URL"], "postgres://localhost/app");
        assert_eq!(map["API_KEY"], "sk_live_abc123");
        assert_eq!(map["SINGLE"], "literal value");
        assert_eq!(map["EMPTY"], "");
        assert_eq!(map["WITH_COMMENT"], "value");
        assert_eq!(map["HASH_IN_VALUE"], "abc#def");
        assert_eq!(map["ESCAPED"], "line1\nline2");
        assert!(parsed.skipped.iter().any(|name| name == "BAD-NAME"));
    }

    #[test]
    fn unterminated_quotes_are_skipped() {
        let parsed = parse_contents("BROKEN=\"unterminated\n");
        assert!(parsed.entries.is_empty());
        assert_eq!(parsed.skipped, vec!["BROKEN"]);
    }
}
