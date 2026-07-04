//! `GRAFT_DEBUG` — comma-separated debug flags, e.g.
//! `GRAFT_DEBUG=preserve-icf-inputs`. Strict parse: an unknown flag is
//! a hard error, never a silent no-op (same policy as `GRAFT` and
//! `GRAFT_ICF` — a typo'd debug flag that silently does nothing is
//! worse than no flag at all).

use anyhow::{Result, anyhow, bail};

pub const ENV: &str = "GRAFT_DEBUG";

/// Every recognized flag. Add new ones here; `enabled` rejects
/// anything else.
pub const KNOWN: &[&str] = &[
    // Keep the `<output>.graft-icf/` rewritten-input dir after a
    // successful base link instead of deleting it.
    "preserve-icf-inputs",
];

/// Is `flag` (which must be in [`KNOWN`]) present in `GRAFT_DEBUG`?
pub fn enabled(flag: &str) -> Result<bool> {
    debug_assert!(KNOWN.contains(&flag), "query for unregistered flag {flag:?}");
    match std::env::var(ENV) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(e) => Err(anyhow!("{ENV}: {e}")),
        Ok(v) => parse(&v, flag),
    }
}

fn parse(value: &str, flag: &str) -> Result<bool> {
    let mut hit = false;
    for tok in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if !KNOWN.contains(&tok) {
            bail!(
                "{ENV}={value:?}: unknown flag {tok:?} (known: {}). Refusing to guess.",
                KNOWN.join(", ")
            );
        }
        hit |= tok == flag;
    }
    Ok(hit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_known_rejects_unknown() {
        assert!(parse("preserve-icf-inputs", "preserve-icf-inputs").unwrap());
        assert!(!parse("", "preserve-icf-inputs").unwrap());
        assert!(parse(" preserve-icf-inputs ,", "preserve-icf-inputs").unwrap());
        assert!(parse("presrve-icf-inputs", "preserve-icf-inputs").is_err());
    }
}
