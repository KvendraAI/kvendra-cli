//! TTL duration parsing, formatting and cap enforcement for the local
//! session blob. Per REQ-KVD-CLI-011 AC-SESSION-3 + AC-SESSION-19.

use crate::error::{KvendraError, KvendraResult};
use std::time::Duration;

/// Default TTL applied when `kvendra unlock` runs without `--ttl`.
pub const DEFAULT_TTL_SECONDS: u64 = 4 * 60 * 60; // 4h

/// Default upper bound configurable via `kvendra config set session.max_ttl`.
pub const DEFAULT_MAX_TTL_SECONDS: u64 = 24 * 60 * 60; // 24h

/// Minimum TTL the CLI will accept. Anything below would defeat the purpose
/// (constant re-prompts) and is rejected with a clear error.
pub const MIN_TTL_SECONDS: u64 = 5 * 60; // 5m

/// Hard upper bound for `session.max_ttl`. Even with renew-on-activity,
/// keeping a session alive >7 days is policy-rejected.
pub const MAX_CONFIGURABLE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60; // 7d

/// Parse a duration string like `30m`, `4h`, `8h`, `1d`. The suffix is one
/// of `s`, `m`, `h`, `d` (case-insensitive). Negative, zero and missing
/// suffixes are rejected.
pub fn parse_ttl(input: &str) -> KvendraResult<Duration> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(KvendraError::InvalidArgs("empty TTL".into()));
    }
    let bytes = trimmed.as_bytes();
    let last = bytes[bytes.len() - 1];
    let (number, mult) = match last {
        b's' | b'S' => (&trimmed[..trimmed.len() - 1], 1u64),
        b'm' | b'M' => (&trimmed[..trimmed.len() - 1], 60u64),
        b'h' | b'H' => (&trimmed[..trimmed.len() - 1], 3600u64),
        b'd' | b'D' => (&trimmed[..trimmed.len() - 1], 86_400u64),
        _ => {
            return Err(KvendraError::InvalidArgs(format!(
                "TTL '{input}' missing suffix (use s, m, h or d)"
            )));
        }
    };
    let n: u64 = number.parse().map_err(|_| {
        KvendraError::InvalidArgs(format!("TTL '{input}' is not a non-negative integer"))
    })?;
    if n == 0 {
        return Err(KvendraError::InvalidArgs(format!(
            "TTL '{input}' must be > 0"
        )));
    }
    let total = n
        .checked_mul(mult)
        .ok_or_else(|| KvendraError::InvalidArgs(format!("TTL '{input}' overflows u64 seconds")))?;
    Ok(Duration::from_secs(total))
}

/// Render a duration as a compact human-readable string. Examples:
/// `5m`, `1h 30m`, `4h`, `1d 2h`, `7d`. Sub-minute remainders are
/// rounded down to keep the output stable.
pub fn format_ttl(d: Duration) -> String {
    let total = d.as_secs();
    if total < 60 {
        return format!("{total}s");
    }
    let days = total / 86_400;
    let hours = (total % 86_400) / 3600;
    let minutes = (total % 3600) / 60;
    let mut parts: Vec<String> = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if parts.is_empty() {
        return "0s".to_string();
    }
    parts.join(" ")
}

/// Enforce the configurable cap. Returns the requested duration verbatim if
/// it fits, else an `InvalidArgs` describing the breach. The minimum lower
/// bound `MIN_TTL_SECONDS` is also enforced here.
pub fn cap_ttl(requested: Duration, max: Duration) -> KvendraResult<Duration> {
    let req_s = requested.as_secs();
    let max_s = max.as_secs();
    if req_s < MIN_TTL_SECONDS {
        return Err(KvendraError::InvalidArgs(format!(
            "TTL {} is below minimum {} ({})",
            format_ttl(requested),
            format_ttl(Duration::from_secs(MIN_TTL_SECONDS)),
            MIN_TTL_SECONDS
        )));
    }
    if req_s > max_s {
        return Err(KvendraError::InvalidArgs(format!(
            "TTL {} exceeds configured max {} (raise `session.max_ttl` to override)",
            format_ttl(requested),
            format_ttl(max)
        )));
    }
    Ok(requested)
}

/// Validate a value before it lands in `session.max_ttl`. Rejects anything
/// below `MIN_TTL_SECONDS` or above `MAX_CONFIGURABLE_TTL_SECONDS`.
pub fn validate_max_ttl(value: Duration) -> KvendraResult<Duration> {
    let s = value.as_secs();
    if s < MIN_TTL_SECONDS {
        return Err(KvendraError::InvalidArgs(format!(
            "session.max_ttl {} is below minimum {}",
            format_ttl(value),
            format_ttl(Duration::from_secs(MIN_TTL_SECONDS))
        )));
    }
    if s > MAX_CONFIGURABLE_TTL_SECONDS {
        return Err(KvendraError::InvalidArgs(format!(
            "session.max_ttl {} exceeds hard maximum {}",
            format_ttl(value),
            format_ttl(Duration::from_secs(MAX_CONFIGURABLE_TTL_SECONDS))
        )));
    }
    Ok(value)
}

// Compile-time invariants for the TTL constants above. Replaces the
// previous runtime `defaults_are_in_canonical_range` test (lifted out
// of `mod tests` to avoid `clippy::assertions_on_constants`).
const _: () = {
    assert!(DEFAULT_TTL_SECONDS >= MIN_TTL_SECONDS);
    assert!(DEFAULT_TTL_SECONDS <= DEFAULT_MAX_TTL_SECONDS);
    assert!(DEFAULT_MAX_TTL_SECONDS <= MAX_CONFIGURABLE_TTL_SECONDS);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_suffixes() {
        assert_eq!(parse_ttl("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_ttl("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_ttl("4h").unwrap(), Duration::from_secs(14_400));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::from_secs(86_400));
    }

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(parse_ttl("4H").unwrap(), Duration::from_secs(14_400));
        assert_eq!(parse_ttl("1D").unwrap(), Duration::from_secs(86_400));
    }

    #[test]
    fn parse_rejects_empty_and_zero_and_missing_suffix() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("   ").is_err());
        assert!(parse_ttl("0s").is_err());
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("4").is_err()); // no suffix
        assert!(parse_ttl("4x").is_err()); // invalid suffix
        assert!(parse_ttl("-1h").is_err()); // negative
    }

    #[test]
    fn format_matches_canonical_strings() {
        assert_eq!(format_ttl(Duration::from_secs(45)), "45s");
        assert_eq!(format_ttl(Duration::from_secs(5 * 60)), "5m");
        assert_eq!(format_ttl(Duration::from_secs(4 * 3600)), "4h");
        assert_eq!(format_ttl(Duration::from_secs(86_400)), "1d");
        assert_eq!(format_ttl(Duration::from_secs(86_400 + 2 * 3600)), "1d 2h");
        assert_eq!(format_ttl(Duration::from_secs(3600 + 30 * 60)), "1h 30m");
    }

    #[test]
    fn cap_accepts_request_within_bounds() {
        let req = Duration::from_secs(4 * 3600);
        let max = Duration::from_secs(8 * 3600);
        assert_eq!(cap_ttl(req, max).unwrap(), req);
    }

    #[test]
    fn cap_rejects_request_below_minimum() {
        let req = Duration::from_secs(60); // 1m
        let max = Duration::from_secs(8 * 3600);
        assert!(cap_ttl(req, max).is_err());
    }

    #[test]
    fn cap_rejects_request_above_max() {
        let req = Duration::from_secs(12 * 3600);
        let max = Duration::from_secs(8 * 3600);
        assert!(cap_ttl(req, max).is_err());
    }

    #[test]
    fn validate_max_ttl_rejects_extremes() {
        assert!(validate_max_ttl(Duration::from_secs(MIN_TTL_SECONDS)).is_ok());
        assert!(validate_max_ttl(Duration::from_secs(MIN_TTL_SECONDS - 1)).is_err());
        assert!(validate_max_ttl(Duration::from_secs(MAX_CONFIGURABLE_TTL_SECONDS)).is_ok());
        assert!(validate_max_ttl(Duration::from_secs(MAX_CONFIGURABLE_TTL_SECONDS + 1)).is_err());
    }
}
