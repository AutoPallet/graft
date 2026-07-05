//! `GRAFT_DEBUG` — comma-separated debug flags, e.g.
//! `GRAFT_DEBUG=preserve-icf-inputs,dump-graph=/tmp/g.tsv`. Strict
//! parse: an unknown flag is a hard error, never a silent no-op (same
//! policy as `GRAFT` and `GRAFT_ICF` — a typo'd debug flag that
//! silently does nothing is worse than no flag at all).
//!
//! A token is either a bare `flag` (boolean) or `flag=value`. Both
//! forms count as "present" for [`enabled`]; [`value`] returns the
//! `value` part (or `Some("")` for a bare flag).

use anyhow::{Result, anyhow, bail};

pub const ENV: &str = "GRAFT_DEBUG";

/// Every recognized flag. Add new ones here; the parser rejects
/// anything else. Each entry documents its own form + meaning.
pub const KNOWN: &[&str] = &[
    // boolean — keep the `<output>.graft-icf/` rewritten-input dir
    // after a successful base link instead of deleting it.
    "preserve-icf-inputs",
    // `dump-graph=<path>` — write the closure graph (one line per scan
    // node, stable cross-scan keys) to <path> from base and overlay
    // links. See debug_dump.rs.
    "dump-graph",
    // boolean — dump the per-phase scan wall-time breakdown to stderr.
    "scan-timings",
    // `icf-limit=<N>` — fold only the first N sorted ICF groups
    // (bisect knob). Numeric; parsed at the use site.
    "icf-limit",
    // `mismatch=<path>` — append one line per closure node that missed
    // a base-section match to <path>.
    "mismatch",
];

/// Parse `GRAFT_DEBUG`'s value into `(name, value)` tokens, validating
/// every flag name against [`KNOWN`]. `value` is `Some` when the token
/// was `name=value` (the value may be empty for `name=`), `None` for a
/// bare `name`. An unknown flag name is a hard error listing the known
/// flags.
fn tokens(raw: &str) -> Result<Vec<(&str, Option<&str>)>> {
    let mut out = Vec::new();
    for tok in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let (name, val) = match tok.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v)),
            None => (tok, None),
        };
        if !KNOWN.contains(&name) {
            bail!(
                "{ENV}={raw:?}: unknown flag {name:?} (known: {}). Refusing to guess.",
                KNOWN.join(", ")
            );
        }
        out.push((name, val));
    }
    Ok(out)
}

/// Is `flag` (which must be in [`KNOWN`]) present in `GRAFT_DEBUG`?
/// True for both a bare `flag` and a `flag=value` token.
pub fn enabled(flag: &str) -> Result<bool> {
    debug_assert!(KNOWN.contains(&flag), "query for unregistered flag {flag:?}");
    match std::env::var(ENV) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(e) => Err(anyhow!("{ENV}: {e}")),
        Ok(v) => Ok(tokens(&v)?.iter().any(|(n, _)| *n == flag)),
    }
}

/// The value of `flag` (which must be in [`KNOWN`]) in `GRAFT_DEBUG`:
/// `None` if the flag is absent, `Some(value)` for `flag=value`, and
/// `Some("")` for a bare `flag`. A bare flag where a value was expected
/// yields `Some("")` — the caller validates.
pub fn value(flag: &str) -> Result<Option<String>> {
    debug_assert!(KNOWN.contains(&flag), "query for unregistered flag {flag:?}");
    match std::env::var(ENV) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(anyhow!("{ENV}: {e}")),
        Ok(v) => Ok(tokens(&v)?
            .iter()
            .find(|(n, _)| *n == flag)
            .map(|(_, val)| val.unwrap_or("").to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(raw: &str, flag: &str) -> Result<bool> {
        Ok(tokens(raw)?.iter().any(|(n, _)| *n == flag))
    }
    fn val(raw: &str, flag: &str) -> Result<Option<String>> {
        Ok(tokens(raw)?
            .iter()
            .find(|(n, _)| *n == flag)
            .map(|(_, v)| v.unwrap_or("").to_string()))
    }

    #[test]
    fn parse_accepts_known_rejects_unknown() {
        assert!(has("preserve-icf-inputs", "preserve-icf-inputs").unwrap());
        assert!(!has("", "preserve-icf-inputs").unwrap());
        assert!(has(" preserve-icf-inputs ,", "preserve-icf-inputs").unwrap());
        assert!(has("presrve-icf-inputs", "preserve-icf-inputs").is_err());
    }

    #[test]
    fn flag_with_value() {
        assert_eq!(
            val("dump-graph=/tmp/g.tsv", "dump-graph").unwrap(),
            Some("/tmp/g.tsv".to_string())
        );
        assert_eq!(val("icf-limit=5", "icf-limit").unwrap(), Some("5".to_string()));
        // bare flag → Some("")
        assert_eq!(val("mismatch", "mismatch").unwrap(), Some(String::new()));
        // absent → None
        assert_eq!(val("scan-timings", "dump-graph").unwrap(), None);
        // a `flag=value` token still counts as enabled
        assert!(has("dump-graph=/x,scan-timings", "scan-timings").unwrap());
        // unknown flag with a value is still rejected
        assert!(val("bogus=1", "dump-graph").is_err());
    }
}
