//! Channel-resolution coverage for `prune::prune_object` under the
//! positional (section-table) resolution model. See
//! `docs/14-identity-granularity.md`.
//!
//! Builds a minimal relocatable `.o` whose `.text.foo` carries one reloc
//! to an external global `bar`, then drives `prune_object` through each
//! resolution channel by configuring the `BaseResolver` tables directly:
//!
//!   - channel 1 (target's trans_hash in overlay's closure) → UND
//!   - channel 2 (target's trans_hash in base's section table) → anchor
//!     at `by_section[th] + in_section_offset` (positional), no verify
//!   - channel 3 (overlay never saw it; base.symtab has it) → anchor +
//!     verify name
//!   - ambiguous section + named ref → anchor at base.symtab address +
//!     verify (preserves address identity for un-folded identical
//!     sections)
//!   - A1: overlay saw it, content NOT in base, not in closure → BAIL
//!         (must NOT bind to a stale/guessed address)
//!   - ambiguous base name (overlay never saw it) → BAIL
//!   - weak-duplication: the offset map points at one of two recorded
//!     section copies → resolves to a valid copy (the bug that motivated
//!     this design)

use std::collections::{HashMap, HashSet};

use graft::hash::TransHash;
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

/// Builder for a `BaseResolver` whose backing tables we own.
#[derive(Default)]
struct Tables {
    by_section: HashMap<TransHash, u64>,
    ambiguous_sections: HashSet<TransHash>,
    globals: HashMap<String, (TransHash, u64)>,
    locals: HashMap<(String, [u8; 8]), (TransHash, u64)>,
    locals_any_tu: HashMap<String, (TransHash, u64)>,
    wrapped: HashSet<String>,
    base_symtab: HashMap<String, u64>,
    base_symtab_ambiguous: HashSet<String>,
    closure_trans_hashes: HashSet<TransHash>,
    mutable_trans_hashes: HashSet<TransHash>,
}

impl Tables {
    fn resolver(&self) -> BaseResolver<'_> {
        BaseResolver {
            by_section: &self.by_section,
            ambiguous_sections: &self.ambiguous_sections,
            overlay_globals: &self.globals,
            overlay_locals: &self.locals,
            overlay_locals_any_tu: &self.locals_any_tu,
            wrapped: &self.wrapped,
            base_symtab: &self.base_symtab,
            base_symtab_ambiguous: &self.base_symtab_ambiguous,
            closure_trans_hashes: &self.closure_trans_hashes,
            mutable_trans_hashes: &self.mutable_trans_hashes,
        }
    }
}

const TH_BAR: TransHash = [0x42u8; 16];

fn no_sec_ths() -> HashMap<u32, TransHash> {
    HashMap::new()
}

#[test]
fn channel1_in_closure_emits_und_no_anchor() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.globals.insert("bar".into(), (TH_BAR, 0));
    t.closure_trans_hashes.insert(TH_BAR); // bar's section is re-emitted by overlay

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect("prune ok");
    assert_eq!(p.abs_rewrites, 0, "closure target must stay UND, not an anchor");
    assert!(p.assumed_names.is_empty());
}

#[test]
fn channel2_content_match_anchors_positionally_without_verify() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    // `bar` lives at offset 0x10 in a section base placed at 0x2000.
    t.globals.insert("bar".into(), (TH_BAR, 0x10));
    t.by_section.insert(TH_BAR, 0x2000);

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect("prune ok");
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

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect("prune ok");
    assert_eq!(p.abs_rewrites, 1);
    assert_eq!(
        p.assumed_names,
        vec![("bar".to_string(), 0x1000)],
        "channel-3 must record the assumption for post-link verify"
    );
}

#[test]
fn ambiguous_section_unique_name_resolves_via_symtab_with_verify() {
    // overlay saw `bar`; its section content is identical to other base
    // sections at distinct addresses (un-folded), so the trans_hash is
    // ambiguous (it still carries a representative in by_section). Because
    // the *name* `bar` is unique in base.symtab, these are genuinely
    // distinct byte-identical symbols → pin base's exact copy + verify.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.globals.insert("bar".into(), (TH_BAR, 0x8));
    t.by_section.insert(TH_BAR, 0x2000); // representative copy
    t.ambiguous_sections.insert(TH_BAR);
    t.base_symtab.insert("bar".into(), 0x3000); // bar's exact (unique) address

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect("prune ok");
    assert_eq!(p.abs_rewrites, 1);
    assert_eq!(
        p.assumed_names,
        vec![("bar".to_string(), 0x3000)],
        "ambiguous-section unique-name ref pins base's exact copy + verify"
    );
}

#[test]
fn ambiguous_section_same_name_dup_uses_representative() {
    // A local helper duplicated identically across CGUs: ambiguous
    // trans_hash, and the name is NOT uniquely resolvable in base.symtab
    // (it appears at several addresses). The copies are interchangeable,
    // so resolution uses the representative section address + offset, no
    // verify — never a bail.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.globals.insert("bar".into(), (TH_BAR, 0x4));
    t.by_section.insert(TH_BAR, 0x2000); // representative copy
    t.ambiguous_sections.insert(TH_BAR);
    // `bar` is ambiguous in base.symtab too → no unique address to pin.
    t.base_symtab_ambiguous.insert("bar".into());

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect("must resolve to the representative copy, not bail");
    assert_eq!(p.abs_rewrites, 1);
    assert!(
        p.assumed_names.is_empty(),
        "interchangeable same-name copy needs no verify"
    );
}

#[test]
fn ambiguous_mutable_section_unique_name_still_pins_via_symtab() {
    // Mutable (e.g. zero-init .data) content duplicated at several base
    // addresses, but the name uniquely pins one copy → resolve + verify,
    // same as the read-only case. Mutability only forbids the
    // *representative* shortcut, not name-pinning.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.globals.insert("bar".into(), (TH_BAR, 0x0));
    t.by_section.insert(TH_BAR, 0x2000);
    t.ambiguous_sections.insert(TH_BAR);
    t.mutable_trans_hashes.insert(TH_BAR);
    t.base_symtab.insert("bar".into(), 0x3000);

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect("prune ok");
    assert_eq!(p.assumed_names, vec![("bar".to_string(), 0x3000)]);
}

#[test]
fn ambiguous_mutable_section_unpinnable_name_bails() {
    // Mutable content at several base addresses and the name does NOT
    // uniquely resolve in base.symtab: a representative bind would alias
    // distinct variables (the M2 xtensa .bss/.data call-to-0 bug) — bail.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.globals.insert("bar".into(), (TH_BAR, 0x0));
    t.by_section.insert(TH_BAR, 0x2000); // representative exists …
    t.ambiguous_sections.insert(TH_BAR);
    t.mutable_trans_hashes.insert(TH_BAR); // … but the content is mutable
    t.base_symtab_ambiguous.insert("bar".into()); // and the name can't pin

    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect_err("must bail rather than alias distinct mutable variables");
    let msg = format!("{err:#}");
    assert!(msg.contains("alias distinct variables"), "unexpected error: {msg}");
}

#[test]
fn weak_dup_resolves_via_recorded_view() {
    // The motivating case: a weak symbol emitted into two coarse sections
    // has two distinct trans_hashes. The offset map (first-write-wins)
    // points at ONE of them (here `TH_B`); base recorded BOTH section
    // copies, so resolution lands in a valid, byte-identical copy — no
    // consistency rule needed. (The pre-design symhash path recorded only
    // the first-weak view and bailed when the views disagreed.)
    const TH_A: TransHash = [0xA1u8; 16];
    const TH_B: TransHash = [0xB2u8; 16];
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.globals.insert("bar".into(), (TH_B, 0x20)); // offset map picked node B
    t.by_section.insert(TH_A, 0x1000); // base recorded copy A …
    t.by_section.insert(TH_B, 0x2000); // … and copy B

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect("must resolve via the recorded copy B, not bail");
    assert_eq!(p.abs_rewrites, 1);
    assert!(p.assumed_names.is_empty(), "positional content-match needs no verify");
}

#[test]
fn a1_content_drift_not_in_closure_bails() {
    // Overlay scanned a definition for `bar` whose content differs from
    // base (trans_hash not in by_section) and which the closure never
    // re-emitted — and `bar` ALSO appears in base.symtab. Must bail
    // rather than bind to base's stale address.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.globals.insert("bar".into(), (TH_BAR, 0)); // overlay saw it
    // by_section does NOT contain TH_BAR → content differs from base.
    // closure_trans_hashes does NOT contain TH_BAR → not re-emitted.
    t.base_symtab.insert("bar".into(), 0x1000); // tempting stale address

    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect_err("must bail rather than bind to base's stale address");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("differs from base") && msg.contains("not in the closure"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ambiguous_base_name_bails() {
    // overlay never saw `bar`; base defined it at multiple distinct
    // addresses, so channel 3 can't disambiguate without a tu_id.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let mut t = Tables::default();
    t.base_symtab_ambiguous.insert("bar".into());

    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect_err("must bail on ambiguous base name");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("multiple distinct addresses"),
        "unexpected error: {msg}"
    );
}

/// `.text.foo` (kept) has an STT_SECTION reloc into `.shared` (pruned).
/// The section resolves positionally via its node trans_hash, supplied
/// through the per-object `section_trans_hash` map — no surrogate symbol
/// search.
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
fn section_target_resolves_positionally() {
    let bytes = synth_obj_section_ref();
    let keep = keep_text_foo(&bytes); // keep only .text.foo; .shared is pruned
    const TH_SHARED: TransHash = [0x77u8; 16];

    // Map `.shared`'s 0-based index → its node trans_hash.
    let f = object::File::parse(&*bytes).unwrap();
    let shared0 = f
        .sections()
        .find(|s| s.name().unwrap_or("") == ".shared")
        .map(|s| s.index().0 as u32 - 1)
        .expect(".shared present");
    let mut sec_ths: HashMap<u32, TransHash> = HashMap::new();
    sec_ths.insert(shared0, TH_SHARED);

    let mut t = Tables::default();
    t.by_section.insert(TH_SHARED, 0x5000);

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &sec_ths)
        .expect("must resolve the section via its trans_hash");
    assert_eq!(
        p.abs_rewrites, 1,
        "the STT_SECTION reloc should anchor at the section's base address"
    );
}

#[test]
fn section_target_content_absent_bails() {
    // `.shared` is pruned and its trans_hash is NOT in base's table →
    // closure / scan-discovery gap, must bail.
    let bytes = synth_obj_section_ref();
    let keep = keep_text_foo(&bytes);
    const TH_SHARED: TransHash = [0x77u8; 16];
    let f = object::File::parse(&*bytes).unwrap();
    let shared0 = f
        .sections()
        .find(|s| s.name().unwrap_or("") == ".shared")
        .map(|s| s.index().0 as u32 - 1)
        .unwrap();
    let mut sec_ths: HashMap<u32, TransHash> = HashMap::new();
    sec_ths.insert(shared0, TH_SHARED);

    let t = Tables::default(); // by_section empty
    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &sec_ths)
        .expect_err("must bail when the section content isn't in base");
    assert!(format!("{err:#}").contains("not found in base"));
}

#[test]
fn section_target_ambiguous_mutable_bails() {
    // STT_SECTION ref into ambiguous *mutable* content: no name to pin a
    // copy, representative would alias distinct variables → bail.
    let bytes = synth_obj_section_ref();
    let keep = keep_text_foo(&bytes);
    const TH_SHARED: TransHash = [0x77u8; 16];
    let f = object::File::parse(&*bytes).unwrap();
    let shared0 = f
        .sections()
        .find(|s| s.name().unwrap_or("") == ".shared")
        .map(|s| s.index().0 as u32 - 1)
        .unwrap();
    let mut sec_ths: HashMap<u32, TransHash> = HashMap::new();
    sec_ths.insert(shared0, TH_SHARED);

    let mut t = Tables::default();
    t.by_section.insert(TH_SHARED, 0x5000);
    t.ambiguous_sections.insert(TH_SHARED);
    t.mutable_trans_hashes.insert(TH_SHARED);

    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &sec_ths)
        .expect_err("must bail rather than alias distinct mutable variables");
    assert!(format!("{err:#}").contains("alias distinct variables"));
}

#[test]
fn section_target_ambiguous_readonly_uses_representative() {
    // Same shape but read-only content: representative is sound (any
    // byte-identical copy reads the same).
    let bytes = synth_obj_section_ref();
    let keep = keep_text_foo(&bytes);
    const TH_SHARED: TransHash = [0x77u8; 16];
    let f = object::File::parse(&*bytes).unwrap();
    let shared0 = f
        .sections()
        .find(|s| s.name().unwrap_or("") == ".shared")
        .map(|s| s.index().0 as u32 - 1)
        .unwrap();
    let mut sec_ths: HashMap<u32, TransHash> = HashMap::new();
    sec_ths.insert(shared0, TH_SHARED);

    let mut t = Tables::default();
    t.by_section.insert(TH_SHARED, 0x5000);
    t.ambiguous_sections.insert(TH_SHARED);
    // NOT in mutable_trans_hashes.

    let p = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &sec_ths)
        .expect("read-only representative resolution must succeed");
    assert_eq!(p.abs_rewrites, 1);
}

#[test]
fn unresolvable_name_bails() {
    // overlay never saw it, base never defined it, not weak → hard error.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let t = Tables::default();
    let err = prune::prune_object(&bytes, [0; 8], &keep, &t.resolver(), &no_sec_ths())
        .expect_err("must bail on a fully-unresolvable target");
    assert!(format!("{err:#}").contains("can't resolve"));
}
