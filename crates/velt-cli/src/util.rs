//! CLI utilities: output, timestamps, expiry parsing and secure input.

use std::io::{self, IsTerminal, Read, Write};

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{CliError, Result};

#[derive(Clone, Copy, Debug)]
pub struct Output;

impl Output {
    pub fn new(_json: bool) -> Self {
        Self
    }

    pub fn data<T: Serialize>(&self, value: &T) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(value)?);
        Ok(())
    }

    pub fn text(&self, text: &str) {
        println!("{text}");
    }
}

pub fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub fn format_timestamp(timestamp: i64) -> String {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_else(|| timestamp.to_string())
}

/// Parse an expiry specification.
///
/// Accepts:
/// - `never`
/// - durations: `90s`, `15m`, `12h`, `30d`, `2w`, and combinations like `1h30m`
/// - RFC 3339 timestamps: `2027-01-01T00:00:00Z`
/// - dates: `2027-01-01` (end of day UTC)
/// - Unix seconds
pub fn parse_expiry(value: &str) -> Result<Option<i64>> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("never") || value.eq_ignore_ascii_case("none")
    {
        return Ok(None);
    }
    if let Some(seconds) = parse_duration_seconds(value)? {
        return Ok(Some(now_unix().saturating_add(seconds)));
    }
    if value.chars().all(|character| character.is_ascii_digit()) {
        let timestamp: i64 = value
            .parse()
            .map_err(|_| CliError::msg("expiry timestamp is out of range"))?;
        return Ok(Some(timestamp));
    }
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(Some(timestamp.unix_timestamp()));
    }
    let date = format!("{value}T23:59:59Z");
    if let Ok(timestamp) = OffsetDateTime::parse(&date, &Rfc3339) {
        return Ok(Some(timestamp.unix_timestamp()));
    }
    Err(CliError::msg(
        "invalid expiry; use a duration (30d, 12h, 90m), an RFC 3339 timestamp, a date, or `never`",
    ))
}

/// Parse a duration such as `10m`, `1h30m`, `30d`, or `45s`.
pub fn parse_duration_seconds(value: &str) -> Result<Option<i64>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let mut total: i64 = 0;
    let mut number: i64 = 0;
    let mut digits = 0usize;
    for character in value.chars() {
        if character.is_ascii_whitespace() {
            continue;
        }
        if character.is_ascii_digit() {
            number = number
                .checked_mul(10)
                .and_then(|value| value.checked_add(character.to_digit(10)? as i64))
                .ok_or_else(|| CliError::msg("duration is out of range"))?;
            digits += 1;
            continue;
        }
        if digits == 0 {
            return Ok(None);
        }
        let multiplier = match character.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Ok(None),
        };
        total = total
            .checked_add(
                number
                    .checked_mul(multiplier)
                    .ok_or_else(|| CliError::msg("duration is out of range"))?,
            )
            .ok_or_else(|| CliError::msg("duration is out of range"))?;
        number = 0;
        digits = 0;
    }
    if digits != 0 {
        // Bare numbers are seconds.
        total = total
            .checked_add(number)
            .ok_or_else(|| CliError::msg("duration is out of range"))?;
    }
    if total <= 0 {
        return Err(CliError::msg("duration must be positive"));
    }
    Ok(Some(total))
}

/// Read a secret value from an argument, stdin, or an interactive prompt.
pub fn read_secret(value: Option<&str>, from_stdin: bool, prompt: &str) -> Result<String> {
    if let Some(value) = value {
        if from_stdin {
            return Err(CliError::msg(
                "provide either a value argument or --stdin, not both",
            ));
        }
        return Ok(value.to_owned());
    }
    if from_stdin {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|err| CliError::io("<stdin>", err))?;
        return Ok(trim_one_newline(buffer));
    }
    if io::stdin().is_terminal() {
        let value = rpassword::prompt_password(prompt)
            .map_err(|err| CliError::Terminal(err.to_string()))?;
        return Ok(value);
    }
    let mut buffer = String::new();
    io::stdin()
        .read_line(&mut buffer)
        .map_err(|err| CliError::io("<stdin>", err))?;
    Ok(trim_one_newline(buffer))
}

fn trim_one_newline(mut value: String) -> String {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.truncate(value.len() - 1);
    }
    value
}

pub fn confirm(prompt: &str) -> Result<bool> {
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    print!("{prompt} [y/N] ");
    io::stdout()
        .flush()
        .map_err(|err| CliError::io("<stdout>", err))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|err| CliError::io("<stdin>", err))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Print a simple aligned table.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index < widths.len() {
                widths[index] = widths[index].max(cell.chars().count());
            }
        }
    }
    let render = |cells: &[String]| {
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                if index + 1 == cells.len() {
                    cell.clone()
                } else {
                    format!("{cell:<width$}", width = widths[index])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let header_cells: Vec<String> = headers.iter().map(|header| (*header).to_owned()).collect();
    println!("{}", render(&header_cells));
    for row in rows {
        println!("{}", render(row));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration_seconds("90s").unwrap(), Some(90));
        assert_eq!(parse_duration_seconds("15m").unwrap(), Some(900));
        assert_eq!(parse_duration_seconds("1h30m").unwrap(), Some(5400));
        assert_eq!(parse_duration_seconds("2d").unwrap(), Some(172_800));
        assert_eq!(parse_duration_seconds("bad").unwrap(), None);
    }

    #[test]
    fn expiry_variants() {
        assert_eq!(parse_expiry("never").unwrap(), None);
        assert!(parse_expiry("30d").unwrap().unwrap() > now_unix());
        assert!(parse_expiry("2027-01-01").unwrap().is_some());
        assert!(parse_expiry("2027-01-01T00:00:00Z").unwrap().is_some());
        assert!(parse_expiry("nonsense").is_err());
    }

    #[test]
    fn newline_trimming() {
        assert_eq!(trim_one_newline("value\n".to_owned()), "value");
        assert_eq!(trim_one_newline("value\r\n".to_owned()), "value");
        assert_eq!(trim_one_newline("value\n\n".to_owned()), "value\n");
    }
}
