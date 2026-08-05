//! Merge base's and overlay's `.eh_frame_hdr` binary-search tables.
//!
//! Overlay code gets real unwind coverage in the combined image (hosted
//! x86 only): prune keeps each pruned object's `.eh_frame` /
//! `.gcc_except_table*`, the overlay layout script places them in the
//! rodata slack, and the forwarded `-Wl,--eh-frame-hdr` makes ld build a
//! sorted lookup table over the overlay's FDEs — with every pointer
//! already correct at final addresses. The only thing the runtime can't
//! use as-is is the *lookup* path: `PT_GNU_EH_FRAME` names exactly one
//! table per object, and base's (built at base link, immovable in place)
//! doesn't know the overlay's FDEs.
//!
//! So combine merges: decode base's table (via `PT_GNU_EH_FRAME`) and
//! overlay's (its spliced `.eh_frame_hdr`), keep only overlay entries
//! whose pc lies in the text slack — every re-emitted function (new or
//! changed) lives there, while entries for base-anchored pcs duplicate
//! coverage base's own FDEs already provide (an rcgu's `.eh_frame` is
//! object-granular, so kept-but-unchanged functions' FDEs resolve to
//! base addresses; base's CUs are NOT a superset of overlay's, but
//! slack membership — not base coverage — is the filter, so novel code
//! is kept by construction) — then write one merged, sorted table into
//! free rodata slack and repoint `PT_GNU_EH_FRAME` at it.
//!
//! Everything here is the trivial fixed-encoding subset GNU ld actually
//! emits for `.eh_frame_hdr` (version 1, `pcrel|sdata4` frame pointer,
//! `udata4` count, `datarel|sdata4` table). Anything else refuses
//! loudly — a wrong unwind table is worse than a missing one.

use anyhow::{Result, bail};

/// DW_EH_PE_pcrel | DW_EH_PE_sdata4
const ENC_PCREL_SDATA4: u8 = 0x1b;
/// DW_EH_PE_udata4
const ENC_UDATA4: u8 = 0x03;
/// DW_EH_PE_datarel | DW_EH_PE_sdata4
const ENC_DATAREL_SDATA4: u8 = 0x3b;

/// A decoded `.eh_frame_hdr`: the advertised `.eh_frame` address plus
/// `(pc, fde)` absolute-vaddr pairs, sorted by pc (ld's invariant).
#[derive(Debug)]
pub struct HdrTable {
    pub eh_frame_ptr: u64,
    pub entries: Vec<(u64, u64)>,
}

fn i32_at(b: &[u8], off: usize) -> Result<i64> {
    let Some(w) = b.get(off..off + 4) else {
        bail!("truncated .eh_frame_hdr at offset {off}");
    };
    Ok(i64::from(i32::from_le_bytes(w.try_into().unwrap())))
}

/// Decode an `.eh_frame_hdr` located at `hdr_vaddr`.
pub fn parse_hdr(hdr: &[u8], hdr_vaddr: u64) -> Result<HdrTable> {
    if hdr.len() < 12 {
        bail!(".eh_frame_hdr too short ({} bytes)", hdr.len());
    }
    let (version, ptr_enc, count_enc, table_enc) = (hdr[0], hdr[1], hdr[2], hdr[3]);
    if version != 1
        || ptr_enc != ENC_PCREL_SDATA4
        || count_enc != ENC_UDATA4
        || table_enc != ENC_DATAREL_SDATA4
    {
        bail!(
            ".eh_frame_hdr encodings {version}/{ptr_enc:#04x}/{count_enc:#04x}/{table_enc:#04x} \
             are not the GNU-ld shape (1/0x1b/0x03/0x3b) — refusing to merge unwind tables"
        );
    }
    let eh_frame_ptr = (hdr_vaddr + 4).wrapping_add_signed(i32_at(hdr, 4)?);
    let count = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as usize;
    if hdr.len() < 12 + count * 8 {
        bail!(".eh_frame_hdr claims {count} entries but is {} bytes", hdr.len());
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let pc = hdr_vaddr.wrapping_add_signed(i32_at(hdr, 12 + i * 8)?);
        let fde = hdr_vaddr.wrapping_add_signed(i32_at(hdr, 16 + i * 8)?);
        entries.push((pc, fde));
    }
    Ok(HdrTable { eh_frame_ptr, entries })
}

/// Encode a table (same GNU-ld shape) to be placed at `table_vaddr`.
/// `entries` must be sorted by pc and duplicate-free — callers merge
/// two already-sorted tables, so a violation means overlapping pc
/// coverage and is refused rather than resolved arbitrarily.
pub fn build_hdr(eh_frame_ptr: u64, entries: &[(u64, u64)], table_vaddr: u64) -> Result<Vec<u8>> {
    let delta32 = |target: u64, field_base: u64, what: &str| -> Result<i32> {
        let d = i128::from(target) - i128::from(field_base);
        i32::try_from(d).map_err(|_| {
            anyhow::anyhow!("{what} delta {d:#x} does not fit sdata4 in merged .eh_frame_hdr")
        })
    };
    let mut out = Vec::with_capacity(12 + entries.len() * 8);
    out.extend_from_slice(&[1, ENC_PCREL_SDATA4, ENC_UDATA4, ENC_DATAREL_SDATA4]);
    out.extend_from_slice(&delta32(eh_frame_ptr, table_vaddr + 4, "eh_frame_ptr")?.to_le_bytes());
    out.extend_from_slice(&u32::try_from(entries.len())?.to_le_bytes());
    let mut prev: Option<u64> = None;
    for &(pc, fde) in entries {
        if let Some(p) = prev
            && pc <= p
        {
            bail!(
                "merged .eh_frame_hdr entries not strictly increasing at pc {pc:#x} \
                 (previous {p:#x}) — overlapping FDE coverage between base and overlay"
            );
        }
        prev = Some(pc);
        out.extend_from_slice(&delta32(pc, table_vaddr, "pc")?.to_le_bytes());
        out.extend_from_slice(&delta32(fde, table_vaddr, "fde")?.to_le_bytes());
    }
    Ok(out)
}

/// Merge already-sorted base and overlay entry lists.
pub fn merge_entries(base: &[(u64, u64)], overlay: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut all: Vec<(u64, u64)> = base.iter().chain(overlay.iter()).copied().collect();
    all.sort_unstable_by_key(|&(pc, _)| pc);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_merge() {
        let base = vec![(0x401000u64, 0x48f000u64), (0x402000, 0x48f020)];
        let overlay = vec![(0x45d600u64, 0x47b400u64)];
        let merged = merge_entries(&base, &overlay);
        let table_vaddr = 0x47c000;
        let bytes = build_hdr(0x48f000, &merged, table_vaddr).unwrap();
        let back = parse_hdr(&bytes, table_vaddr).unwrap();
        assert_eq!(back.eh_frame_ptr, 0x48f000);
        assert_eq!(back.entries, vec![
            (0x401000, 0x48f000),
            (0x402000, 0x48f020),
            (0x45d600, 0x47b400),
        ]);
    }

    #[test]
    fn duplicate_pc_refuses() {
        let entries = vec![(0x401000u64, 0x48f000u64), (0x401000, 0x48f020)];
        let err = build_hdr(0x48f000, &entries, 0x47c000).unwrap_err().to_string();
        assert!(err.contains("strictly increasing"), "{err}");
    }

    #[test]
    fn foreign_encodings_refuse() {
        // absptr table encoding instead of datarel|sdata4.
        let hdr = [1u8, 0x1b, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = parse_hdr(&hdr, 0x1000).unwrap_err().to_string();
        assert!(err.contains("GNU-ld shape"), "{err}");
    }
}
