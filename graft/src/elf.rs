//! Parse a single object file into graft's normalized form.
//!
//! The output is deliberately allocation-heavy (owned Strings, Vecs) so
//! downstream passes can juggle objects in parallel without lifetime
//! contortions. Parsing a 100 KB `.rcgu.o` is microseconds anyway —
//! the real work is in hashing and the reloc graph.

use anyhow::{Context, Result, bail};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, SectionFlags,
    SectionIndex, SectionKind as ObjSectionKind, SymbolIndex, SymbolKind, SymbolScope,
    elf::R_X86_64_NONE,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ParsedObject {
    /// `tu_id = blake3(first STT_FILE symbol name)[:8]`, per the M0.25
    /// findings. See `probes/rustc-stability/`.
    pub tu_id: [u8; 8],
    /// Human-friendly name (from the first STT_FILE symbol). For logging.
    pub tu_name: String,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub kind: SectionKind,
    pub alloc: bool,
    /// Raw ELF `sh_flags`. Used by root-finding to detect SHF_GNU_RETAIN
    /// (`R` flag) and anything else ld treats as "always keep."
    pub sh_flags: u64,
    /// Section contents, or empty for NOBITS sections (.bss).
    pub bytes: Vec<u8>,
    /// Forward relocations from this section, canonicalized and sorted by
    /// `(offset, target_name, r_type, addend)` — stable regardless of
    /// the original `.o`'s internal symbol-index ordering.
    pub relocs: Vec<CanonicalReloc>,
}

impl SectionInfo {
    /// True iff this section's identity can be its *content* — the basis
    /// for positional (trans_hash-keyed) resolution against base.
    ///
    /// Mirrors what ld itself is willing to content-fold: read-only data
    /// and code, never writable data. Two byte-identical mutable sections
    /// (`.bss.A` / `.bss.B`, zero-init `.data.X` / `.data.Y`) are
    /// *distinct variables* that merely look alike — binding a reference
    /// to "an interchangeable copy" silently aliases program state (the
    /// M2 xtensa call-to-0: three `.bss` statics and `esp_println::LOCK`
    /// all collapsed onto one base address). NOBITS and zero-size
    /// sections have no bytes at all, so their content hash is fully
    /// degenerate. Non-content-addressable sections get a *nominal*
    /// identity instead: `hash::compute` salts their leaf hash with the
    /// sorted (symbol, offset) pairs they define.
    ///
    /// RAM-resident code (`.rwtext`, SHF_WRITE|SHF_EXECINSTR placement
    /// artifacts) stays content-addressable: code is immutable content
    /// regardless of segment writability.
    pub fn content_addressable(&self) -> bool {
        use object::elf::{SHF_EXECINSTR, SHF_WRITE};
        !self.bytes.is_empty()
            && (self.sh_flags & u64::from(SHF_WRITE) == 0
                || self.sh_flags & u64::from(SHF_EXECINSTR) != 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Text,
    Rodata,
    Data,
    Bss,
    Other,
}

#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub bind: SymbolBind,
    pub kind: SymbolKind,
    /// Index into `ParsedObject::sections`, or `None` for undefined /
    /// absolute / section symbols.
    pub defining_section: Option<usize>,
    pub size: u64,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBind {
    Local,
    Global,
    Weak,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalReloc {
    pub offset: u64,
    /// Symbol name, or `<section:<name>>` for section-target relocs.
    pub target: String,
    pub r_type: u32,
    pub addend: i64,
    /// For section-target relocs: the target's 0-based section index.
    /// Section NAMES legally repeat within one object (the esp32s3
    /// rcgu carries two `.rwtext` inputs), so name-keyed lookup can
    /// pick the wrong section — the index is the physical truth and
    /// is what edge building and reloc resolution key on.
    /// `hash::encode_relocs` clears this before hashing (indexes shift
    /// under CGU repartition; the canonicalized `target` fingerprint
    /// is the hash-stable identity).
    pub target_section: Option<u32>,
}

pub fn parse(bytes: &[u8]) -> Result<ParsedObject> {
    let obj = object::File::parse(bytes).context("parse ELF")?;

    // Build the symbol list first so sections can record defined-symbol
    // indexes as we go.
    let mut symbols: Vec<SymbolInfo> = Vec::new();
    let mut sym_index_of: std::collections::HashMap<SymbolIndex, usize> = Default::default();
    let mut tu_name: Option<String> = None;

    for sym in obj.symbols() {
        let name = sym.name().unwrap_or("").to_string();
        if matches!(sym.kind(), SymbolKind::File) {
            if tu_name.is_none() {
                tu_name = Some(name.clone());
            }
            // File symbols are local-scope metadata; skip further processing.
            continue;
        }
        let bind = classify_bind(&sym);
        let defining_section = match sym.section_index() {
            Some(SectionIndex(idx)) => Some(idx.saturating_sub(1)),
            None => None,
        };
        let idx = symbols.len();
        sym_index_of.insert(sym.index(), idx);
        symbols.push(SymbolInfo {
            name,
            bind,
            kind: sym.kind(),
            defining_section,
            size: sym.size(),
            value: sym.address(),
        });
    }

    let tu_name = tu_name.unwrap_or_default();
    let tu_id = {
        let mut h = blake3::Hasher::new();
        h.update(tu_name.as_bytes());
        let digest = *h.finalize().as_bytes();
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    };

    // Now walk sections, collecting canonical relocs.
    let mut sections: Vec<SectionInfo> = Vec::new();
    for sec in obj.sections() {
        let name = sec.name().unwrap_or("").to_string();
        let alloc = matches!(sec.kind(),
            ObjSectionKind::Text | ObjSectionKind::Data | ObjSectionKind::ReadOnlyData
            | ObjSectionKind::UninitializedData | ObjSectionKind::ReadOnlyString
            | ObjSectionKind::Tls | ObjSectionKind::UninitializedTls);
        let kind = match sec.kind() {
            ObjSectionKind::Text => SectionKind::Text,
            ObjSectionKind::Data => SectionKind::Data,
            ObjSectionKind::ReadOnlyData | ObjSectionKind::ReadOnlyString => SectionKind::Rodata,
            ObjSectionKind::UninitializedData => SectionKind::Bss,
            _ => SectionKind::Other,
        };
        let bytes = match sec.data() {
            Ok(d) => d.to_vec(),
            Err(_) => Vec::new(),
        };
        let sh_flags = match sec.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags,
            _ => 0,
        };

        // Canonical relocs.
        let mut relocs: Vec<CanonicalReloc> = Vec::new();
        for (offset, r) in sec.relocations() {
            let r_type = match r.flags() {
                RelocationFlags::Elf { r_type } => r_type,
                _ => 0, // non-ELF shouldn't show up; placeholder
            };
            // Skip R_*_NONE — they're padding/annotation, no runtime effect.
            if r_type == R_X86_64_NONE { continue; }
            // 1-based object::read index → our 0-based section index,
            // with name kept for the hash-stable canonical form.
            let section_target = |s_i: usize| -> Result<(String, Option<u32>)> {
                let sec = obj.section_by_index(SectionIndex(s_i))
                    .map_err(|e| anyhow::anyhow!("reloc target section: {e}"))?;
                Ok((
                    format!("<section:{}>", sec.name().unwrap_or("")),
                    Some(s_i.saturating_sub(1) as u32),
                ))
            };
            let (target_name, target_section) = match r.target() {
                RelocationTarget::Symbol(sidx) => {
                    let sym = obj.symbol_by_index(sidx)
                        .map_err(|e| anyhow::anyhow!("resolve reloc target {sidx:?}: {e}"))?;
                    if matches!(sym.kind(), SymbolKind::Section) {
                        // STT_SECTION: the symbol's name is empty; key
                        // on its defining section.
                        match sym.section_index() {
                            Some(SectionIndex(s_i)) => section_target(s_i)?,
                            None => ("<section:?>".into(), None),
                        }
                    } else {
                        (sym.name().unwrap_or("").to_string(), None)
                    }
                }
                RelocationTarget::Section(SectionIndex(s_i)) => section_target(s_i)?,
                RelocationTarget::Absolute => ("<absolute>".into(), None),
                other => bail!("unsupported reloc target: {other:?}"),
            };
            relocs.push(CanonicalReloc {
                offset,
                target: target_name,
                r_type,
                addend: r.addend(),
                target_section,
            });
        }
        relocs.sort();
        relocs.dedup();

        sections.push(SectionInfo {
            name,
            kind,
            alloc,
            sh_flags,
            bytes,
            relocs,
        });
    }

    Ok(ParsedObject { tu_id, tu_name, sections, symbols })
}

fn classify_bind<'data, 'file>(sym: &object::Symbol<'data, 'file, &'data [u8]>) -> SymbolBind {
    if sym.is_weak() {
        return SymbolBind::Weak;
    }
    // UND symbols in well-formed `.o`s are STB_GLOBAL (or STB_WEAK,
    // handled above): the linker resolves them by name from another
    // input. The `object` crate maps UND to `SymbolScope::Unknown`,
    // which `scope()`-based classification would collapse into
    // `Local` — wrong for demand-load (scan/scan.rs filters
    // archive-pull candidates on `Global | Weak` bind, so misclassed
    // UND refs would silently skip pulling their defining archive
    // members like libunwind.a's `_Unwind_Resume`).
    if sym.is_undefined() {
        return SymbolBind::Global;
    }
    match sym.scope() {
        SymbolScope::Compilation => SymbolBind::Local,
        SymbolScope::Linkage | SymbolScope::Dynamic => SymbolBind::Global,
        SymbolScope::Unknown => SymbolBind::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-crafted parse of `/bin/ls` wouldn't teach us much about `.o`
    /// parsing — relocs are gone after link. We exercise parse() against
    /// real rustc output in the integration test harness (M0.5.f).
    /// This unit test just asserts parse() doesn't panic on an empty-ish
    /// input and produces a lenient error.
    #[test]
    fn empty_bytes_fails_cleanly() {
        let err = parse(&[]).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("parse"),
            "unexpected err: {err}");
    }
}
