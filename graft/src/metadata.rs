//! Sidecar layout file written next to base.elf on a clean link, read
//! back by incremental links so they can pin sections to the same
//! addresses they had in base.
//!
//! The companion `<output>.graft-base.elf` is the actual reference ELF
//! kept around verbatim. This file just records what graft cares about
//! cheaply (avoids reparsing every section header on every link).

use serde::{Deserialize, Serialize};

pub const GRAFT_MAGIC: [u8; 4] = *b"GRFT";
pub const SCHEMA_VERSION: u16 = 2;

/// Layout snapshot saved by base mode and consumed by incremental mode.
/// JSON-on-disk so it's eyeballable; small enough that re-encoding cost
/// is irrelevant.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BaseLayout {
    pub magic: [u8; 4],
    pub version: u16,
    /// Toolchain identifier ("rustc -Vv" commit hash) — incremental mode
    /// refuses to mix layouts across toolchains.
    pub toolchain_stamp: String,
    /// Per-section record, ordered by vaddr. Only sections relevant to
    /// flash layout are kept (alloc'd loaded sections — anything that
    /// will end up in the .img).
    pub sections: Vec<SectionLayout>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SectionLayout {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    /// Raw `sh_flags` so incremental mode knows alloc/exec/write/etc
    /// without reparsing flags into named bits.
    pub sh_flags: u64,
    /// blake3-128 of the section bytes as written into base.elf — lets
    /// incremental mode short-circuit "did this section actually change?"
    /// without re-running the linker.
    pub content_hash: [u8; 16],
}

pub fn encode_layout(layout: &BaseLayout) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec_pretty(layout).map_err(|e| anyhow::anyhow!("encode layout: {e}"))
}

pub fn decode_layout(bytes: &[u8]) -> anyhow::Result<BaseLayout> {
    serde_json::from_slice(bytes).map_err(|e| anyhow::anyhow!("decode layout: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_roundtrip() {
        let l = BaseLayout {
            magic: GRAFT_MAGIC,
            version: SCHEMA_VERSION,
            toolchain_stamp: "rustc-1.94.1".into(),
            sections: vec![SectionLayout {
                name: ".text.main".into(),
                vaddr: 0x42010100,
                size: 0x40,
                sh_flags: 0x6,
                content_hash: [0xAB; 16],
            }],
        };
        let bytes = encode_layout(&l).unwrap();
        let back = decode_layout(&bytes).unwrap();
        assert_eq!(l, back);
    }
}
