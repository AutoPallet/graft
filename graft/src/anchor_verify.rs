//! Overlay-side anchor byte-check: the twin of `GRAFT_ICF_VERIFY` for
//! channel-2 positional anchors (`resolve::Resolver::positional_anchor`).
//!
//! Channel 2 anchors an overlay reloc into base *positionally*, purely by
//! `trans_hash`: base's section table maps `trans_hash → address`, and
//! the reloc is bound at `address + offset` with NO byte comparison. The
//! soundness argument is "equal trans_hash ⇒ base's placed bytes are
//! byte-identical to overlay's input" — but that argument silently fails
//! if base.elf is corrupt or stale, if the table and the image disagree,
//! or if a `trans_hash` collision lies. In every such case the overlay
//! would bind to wrong bytes with no link-time symptom.
//!
//! This pass re-derives the claim from raw bytes, exactly as
//! `icf::verify_interchangeable` does on the base side. For every DISTINCT
//! node that received a channel-2 positional anchor (deduped per node, not
//! per reloc), it compares the overlay input section's bytes against
//! base.elf's placed bytes at the anchored address:
//!
//! - **Non-relaxing targets (x86):** direct masked compare. The compare
//!   ignores bytes covered by the section's own relocations (base wrote
//!   resolved values there; the input carries addends) — the hole mask is
//!   built by the *same* `relax::verify::input_view` base-time
//!   verification used, so the masking is bit-identical to what recorded
//!   the placement in the first place (a divergent mask would itself be a
//!   bug). Any unmasked byte that differs is a refusal.
//! - **Relaxing targets (xtensa):** the relax walker already reconciles
//!   input↔placed bytes to translate interior offsets; a node the walk
//!   verified (Identity or a source-grounded fate vector) counts as
//!   byte-checked. A walk refusal here would already have been handled
//!   upstream by the closure fixpoint (dispose bails before prune), so by
//!   the time this pass runs every anchored xtensa node reconciles.
//!
//! NOBITS / byteless nodes are skipped (nothing to compare; nominal
//! identity already keeps distinct mutable variables' hashes apart).
//!
//! Default ON (`GRAFT_ANCHOR_VERIFY`); a mismatch fails the overlay link
//! loudly rather than shipping an unverified bind — CLAUDE.md's "loud
//! refusal, never a guess".

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use object::Object;

use crate::graph::{NodeId, SegmentRef};
use crate::hash::TransHash;
use crate::metadata::Placed;
use crate::relax::engine::masked_compare;
use crate::relax::verify::{LinkedImage, input_view};
use crate::relax::walker::Walker;
use crate::scan::ScanResult;

pub const ENV: &str = "GRAFT_ANCHOR_VERIFY";

/// Parse `GRAFT_ANCHOR_VERIFY` (default ON): `""`/`1`/`on` → on,
/// `0`/`off` → off, anything else is a hard error (same shape as
/// `GRAFT_ICF_VERIFY` — never a silent fallthrough).
pub fn enabled() -> Result<bool> {
    match std::env::var(ENV) {
        Err(std::env::VarError::NotPresent) => Ok(true),
        Err(e) => Err(anyhow!("{ENV}: {e}")),
        Ok(v) => parse(&v),
    }
}

fn parse(v: &str) -> Result<bool> {
    match v {
        "" | "1" | "on" => Ok(true),
        "0" | "off" => Ok(false),
        other => bail!(
            "{ENV}={other:?} is not a recognized mode (expected `1`, `on`, \
             `0`, or `off`). Refusing to guess."
        ),
    }
}

/// Byte-check every channel-2 positionally-anchored node in `nodes`
/// against `base_elf_bytes`. `walker` is the (xtensa-only) relax walker;
/// `None` on non-relaxing targets. Logs one telemetry line on success and
/// bails on the first mismatch.
#[allow(clippy::too_many_arguments)]
pub fn run(
    enabled: bool,
    scan: &ScanResult,
    by_section: &HashMap<TransHash, Placed>,
    base_elf_bytes: &[u8],
    arch: object::Architecture,
    nodes: &HashSet<NodeId>,
    walker: Option<&Walker<'_>>,
    output: &Path,
) -> Result<()> {
    if !enabled || nodes.is_empty() {
        return Ok(());
    }
    let t = std::time::Instant::now();
    let image = LinkedImage::new(base_elf_bytes)
        .map_err(|e| anyhow!("anchor-verify: parse base.elf image: {e}"))?;
    let is_relaxing = arch == object::Architecture::Xtensa;
    let empty_lit: HashMap<String, u64> = HashMap::new();
    // Parsed input objects cached across nodes (a deep edit can anchor
    // many nodes into the same object).
    let mut file_cache: HashMap<u32, object::File<'_>> = HashMap::new();

    let mut sorted: Vec<NodeId> = nodes.iter().copied().collect();
    sorted.sort_unstable();
    let mut checked = 0usize;

    for nid in sorted {
        let th = scan.trans_hash[nid as usize];
        let node = &scan.graph.nodes[nid as usize];
        // Channel-2 anchors are single-segment, whole-section nodes; a
        // multi-segment or sub-range node never reaches positional_anchor.
        let [seg] = node.segments.as_slice() else { continue };
        if seg.range.is_some() {
            continue;
        }
        let sec = &scan.objects[seg.object as usize].sections[seg.section as usize];
        if sec.bytes.is_empty() {
            continue; // NOBITS / byteless: nothing to compare.
        }
        let Placed { addr, out_size } = *by_section.get(&th).ok_or_else(|| {
            anyhow!(
                "anchor-verify: {} has no base placement for its trans_hash — \
                 internal inconsistency (a node in the channel-2 set must have one)",
                seg_label(scan, seg)
            )
        })?;

        // xtensa: reuse the relax walker's already-cached verdict.
        if is_relaxing && let Some(w) = walker {
            w.byte_check(nid)
                .map_err(|why| mismatch(scan, seg, &th, addr, None, &why))?;
            checked += 1;
            continue;
        }

        // Non-relaxing: direct masked compare of the whole section.
        let out = image.slice(addr, out_size).ok_or_else(|| {
            anyhow!(
                "anchor-verify REFUSED: {} th={} anchored at base {addr:#x}+{out_size:#x} \
                 but base.elf has no placed bytes there — section table / image mismatch. \
                 Set {ENV}=0 to bypass (ships an unverified bind).",
                seg_label(scan, seg),
                hex16(&th),
            )
        })?;
        let file = match file_cache.entry(seg.object) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let f = object::File::parse(scan.inputs[seg.object as usize].bytes.as_slice())
                    .map_err(|err| {
                        anyhow!(
                            "anchor-verify: re-parse {}: {err}",
                            scan.inputs[seg.object as usize].label()
                        )
                    })?;
                e.insert(f)
            }
        };
        let osec = file
            .section_by_index(object::SectionIndex(seg.section as usize + 1))
            .map_err(|e| anyhow!("anchor-verify: input section lookup: {e}"))?;
        let input = input_view(arch, file, &osec, &empty_lit)
            .map_err(|e| anyhow!("anchor-verify: input extraction for {}: {e}", seg_label(scan, seg)))?;
        match masked_compare(&input, out) {
            Ok(()) => checked += 1,
            Err(runs) => {
                let first = runs.first().map(|r| r.in_off);
                return Err(mismatch(
                    scan,
                    seg,
                    &th,
                    addr,
                    first,
                    "base.elf's placed bytes differ from overlay's input for this \
                     content-keyed anchor (corrupt/stale base.elf, or a trans_hash lie)",
                ));
            }
        }
    }

    crate::telemetry::note(
        output,
        &format!(
            "graft anchor-verify: {checked} anchored nodes byte-checked in {:.1?}",
            t.elapsed()
        ),
    );
    Ok(())
}

/// The refusal, naming the node's symbols, trans_hash, base address, and
/// (where known) the first differing offset, plus the bypass hint.
fn mismatch(
    scan: &ScanResult,
    seg: &SegmentRef,
    th: &TransHash,
    addr: u64,
    first_off: Option<usize>,
    why: &str,
) -> anyhow::Error {
    let syms = node_symbols(scan, seg);
    let syms = if syms.is_empty() { "<none>".to_string() } else { syms.join(", ") };
    let at = match first_off {
        Some(o) => format!(" (first differing offset +{o:#x})"),
        None => String::new(),
    };
    anyhow!(
        "anchor-verify REFUSED: {} (symbols: {syms}) th={} anchored at base \
         {addr:#x}: {why}{at}. Refusing to bind overlay to unverified base bytes. \
         Set {ENV}=0 to bypass (ships an unverified bind).",
        seg_label(scan, seg),
        hex16(th),
    )
}

fn seg_label(scan: &ScanResult, seg: &SegmentRef) -> String {
    format!(
        "{}::{}",
        scan.inputs[seg.object as usize].label(),
        scan.objects[seg.object as usize].sections[seg.section as usize].name
    )
}

/// Up to six symbol names the node's section defines — for diagnosis.
fn node_symbols(scan: &ScanResult, seg: &SegmentRef) -> Vec<String> {
    scan.objects[seg.object as usize]
        .symbols
        .iter()
        .filter(|s| s.defining_section == Some(seg.section as usize) && !s.name.is_empty())
        .map(|s| s.name.clone())
        .take(6)
        .collect()
}

fn hex16(th: &TransHash) -> String {
    th.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parse_modes() {
        assert!(parse("").unwrap());
        assert!(parse("1").unwrap());
        assert!(parse("on").unwrap());
        assert!(!parse("0").unwrap());
        assert!(!parse("off").unwrap());
        assert!(parse("yes").is_err());
        assert!(parse("2").is_err());
    }
}
