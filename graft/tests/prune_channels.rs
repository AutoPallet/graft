//! Channel-resolution coverage for `prune::prune_object`.
//!
//! Builds a minimal relocatable `.o` whose `.text.foo` carries one reloc
//! to an external global `bar`, then drives `prune_object` through each
//! of its base-resolution channels by configuring the `BaseResolver`
//! maps directly. Locks in the soundness fixes:
//!
//!   - channel 1 (target in overlay's closure)  → UND, no anchor
//!   - channel 2 (content-match against base)    → anchor, no verify
//!   - channel 3 (overlay never saw it)          → anchor + verify name
//!   - A1: overlay saw it, content differs, not in closure → BAIL
//!         (must NOT silently fall through to base's stale address)
//!   - A2: base defines the name at multiple addresses     → BAIL

use std::collections::{HashMap, HashSet};

use graft::hash::Symhash;
use graft::metadata::SymHashEntry;
use graft::prune::{self, BaseResolver};
use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    Object as _, ObjectSection, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

/// A relocatable ELF: `.text.foo` (16 bytes) with one 64-bit reloc at
/// offset 4 pointing at an undefined global `bar`.
fn synth_obj_ref_bar() -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    let text_id = obj.add_section(Vec::new(), b".text.foo".to_vec(), SectionKind::Text);
    obj.set_section_data(text_id, vec![0xccu8; 16], 4);
    obj.add_symbol(Symbol {
        name: b"foo".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text_id),
        flags: SymbolFlags::None,
    });
    let bar = obj.add_symbol(Symbol {
        name: b"bar".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Unknown,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    obj.add_relocation(
        text_id,
        Relocation {
            offset: 4,
            symbol: bar,
            addend: 0,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Absolute,
                encoding: RelocationEncoding::Generic,
                size: 64,
            },
        },
    )
    .expect("add reloc to bar");

    obj.write().expect("emit ELF")
}

/// 0-based `keep` set for `.text.foo` (object::read indexes are 1-based;
/// `ParsedObject`/`prune` use 0-based).
fn keep_text_foo(bytes: &[u8]) -> HashSet<u32> {
    let f = object::File::parse(bytes).expect("parse synth .o");
    let idx0 = f
        .sections()
        .find(|s| s.name().unwrap_or("") == ".text.foo")
        .map(|s| s.index().0 as u32 - 1)
        .expect(".text.foo present");
    HashSet::from([idx0])
}

/// Builder for a `BaseResolver` whose backing maps we own. Borrows are
/// tied to the struct's lifetime so the resolver can reference them.
#[derive(Default)]
struct Tables {
    by_symhash: HashMap<Symhash, SymHashEntry>,
    overlay_globals: HashMap<String, Symhash>,
    overlay_locals: HashMap<(String, [u8; 8]), Symhash>,
    overlay_locals_any_tu: HashMap<String, Symhash>,
    wrapped: HashSet<String>,
    base_symtab: HashMap<String, u64>,
    base_symtab_ambiguous: HashSet<String>,
    closure_symhashes: HashSet<Symhash>,
}

impl Tables {
    fn resolver(&self) -> BaseResolver<'_> {
        BaseResolver {
            by_symhash: &self.by_symhash,
            overlay_symhash_globals: &self.overlay_globals,
            overlay_symhash_locals: &self.overlay_locals,
            overlay_symhash_locals_any_tu: &self.overlay_locals_any_tu,
            wrapped: &self.wrapped,
            base_symtab: &self.base_symtab,
            base_symtab_ambiguous: &self.base_symtab_ambiguous,
            closure_symhashes: &self.closure_symhashes,
        }
    }
}

const SH_BAR: Symhash = [0x42u8; 16];

#[test]
fn channel1_in_closure_emits_und_no_anchor() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.overlay_globals.insert("bar".into(), SH_BAR);
    t.closure_symhashes.insert(SH_BAR); // bar is re-emitted by overlay

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver()).expect("prune ok");
    assert_eq!(p.abs_rewrites, 0, "closure target must stay UND, not an anchor");
    assert!(p.assumed_names.is_empty());
}

#[test]
fn channel2_content_match_anchors_without_verify() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.overlay_globals.insert("bar".into(), SH_BAR);
    t.by_symhash.insert(SH_BAR, SymHashEntry { symhash: SH_BAR, address: 0x2000, size: 0 });

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver()).expect("prune ok");
    assert_eq!(p.abs_rewrites, 1, "content-match must anchor to base address");
    assert!(
        p.assumed_names.is_empty(),
        "channel-2 hits are content-keyed and need no post-link verify"
    );
}

#[test]
fn channel3_unseen_name_anchors_with_verify() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    // overlay never saw `bar`; base resolved it (e.g. a ROM/script symbol).
    t.base_symtab.insert("bar".into(), 0x1000);

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver()).expect("prune ok");
    assert_eq!(p.abs_rewrites, 1);
    assert_eq!(
        p.assumed_names,
        vec![("bar".to_string(), 0x1000)],
        "channel-3 must record the assumption for post-link verify"
    );
}

#[test]
fn a1_content_drift_not_in_closure_bails() {
    // Overlay scanned a definition for `bar` whose content differs from
    // base (symhash not in by_symhash) and which the closure walk never
    // included — and `bar` ALSO appears in base.symtab. The old code
    // fell through to channel 3 and silently bound to base's stale
    // address; it must now bail.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.overlay_globals.insert("bar".into(), SH_BAR); // overlay saw it
    // by_symhash does NOT contain SH_BAR → content differs from base.
    // closure_symhashes does NOT contain SH_BAR → not re-emitted.
    t.base_symtab.insert("bar".into(), 0x1000); // tempting stale address

    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver())
        .expect_err("must bail rather than bind to base's stale address");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("differs from base") && msg.contains("not in the closure"),
        "unexpected error: {msg}"
    );
}

#[test]
fn a2_ambiguous_base_name_bails() {
    // overlay never saw `bar`; base defined it at multiple distinct
    // addresses, so channel 3 can't disambiguate without a tu_id.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.base_symtab_ambiguous.insert("bar".into());

    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver())
        .expect_err("must bail on ambiguous base name");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("multiple distinct addresses"),
        "unexpected error: {msg}"
    );
}

/// `.text.foo` (kept) has an STT_SECTION reloc into `.shared` (pruned).
/// `.shared` defines two symbols: `lowsym` at offset 0 (NOT content-
/// matched in base) and `hisym` at offset 8 (content-matched). The
/// section-surrogate path must try *all* symbols and resolve via `hisym`,
/// not bail on the lowest-addressed `lowsym`. (Regression for the
/// esp-hal `__pre_init` surrogate failure.)
fn synth_obj_section_ref() -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    let text_id = obj.add_section(Vec::new(), b".text.foo".to_vec(), SectionKind::Text);
    obj.set_section_data(text_id, vec![0xccu8; 16], 4);
    obj.add_symbol(Symbol {
        name: b"foo".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text_id),
        flags: SymbolFlags::None,
    });

    let shared_id = obj.add_section(Vec::new(), b".shared".to_vec(), SectionKind::Text);
    obj.set_section_data(shared_id, vec![0x90u8; 16], 4);
    // lowsym at offset 0 (lowest), hisym at offset 8.
    obj.add_symbol(Symbol {
        name: b"lowsym".to_vec(),
        value: 0,
        size: 8,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(shared_id),
        flags: SymbolFlags::None,
    });
    obj.add_symbol(Symbol {
        name: b"hisym".to_vec(),
        value: 8,
        size: 8,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(shared_id),
        flags: SymbolFlags::None,
    });

    // STT_SECTION reloc from .text.foo+4 into .shared (+addend 8).
    let shared_section_sym = obj.section_symbol(shared_id);
    obj.add_relocation(
        text_id,
        Relocation {
            offset: 4,
            symbol: shared_section_sym,
            addend: 8,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Absolute,
                encoding: RelocationEncoding::Generic,
                size: 64,
            },
        },
    )
    .expect("add section reloc");

    obj.write().expect("emit ELF")
}

#[test]
fn section_surrogate_tries_all_symbols_not_just_lowest() {
    let bytes = synth_obj_section_ref();
    let keep = keep_text_foo(&bytes); // keep only .text.foo; .shared is pruned
    const SH_HI: Symhash = [0x77u8; 16];
    let mut t = Tables::default();
    // Only `hisym` resolves; `lowsym` (lower address) does not.
    t.overlay_globals.insert("hisym".into(), SH_HI);
    t.by_symhash.insert(SH_HI, SymHashEntry { symhash: SH_HI, address: 0x5000, size: 8 });

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver())
        .expect("must resolve the section via hisym, not bail on lowsym");
    assert_eq!(
        p.abs_rewrites, 1,
        "the STT_SECTION reloc should anchor via the content-matched sibling"
    );
}

#[test]
fn unresolvable_name_bails() {
    // overlay never saw it, base never defined it, not weak → hard error.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let t = Tables::default();
    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver())
        .expect_err("must bail on a fully-unresolvable target");
    assert!(format!("{err:#}").contains("can't resolve"));
}
