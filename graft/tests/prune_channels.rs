//! Channel coverage for `resolve::Resolver::dispose` — the single
//! resolution cascade shared by the closure walk and prune — plus
//! emission checks that `prune::prune_object` faithfully renders each
//! `RelocDisposition`. See `docs/14-identity-granularity.md` and
//! `resolve.rs`'s module docs for the cascade.
//!
//!   - channel 1 (target node in the closure) → UND
//!   - channel 2 (target's trans_hash in base's section table) → anchor
//!     at `by_section[th] + value` (positional), no verify
//!   - channel 2a (ambiguous hash, name unique in base.symtab) → anchor
//!     at the pinned address + verify
//!   - ambiguous + mutable + unpinnable → BAIL (aliasing guard)
//!   - ambiguous + read-only same-name dup → representative, no verify
//!   - drift (overlay content not in base, not re-emitted) → BAIL
//!   - channel 4 (External; base.symtab) → anchor + verify
//!   - ambiguous base name → BAIL; weak undef → weak UND; else BAIL

use std::collections::{HashMap, HashSet};

use graft::graph::{NodeId, ResolvedTarget};
use graft::hash::TransHash;
use graft::prune;
use graft::metadata::Placed;
use graft::resolve::{RelocDisposition, RelocQuery, Resolver};
use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    Object as _, ObjectSection, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

const TH_BAR: TransHash = [0x42u8; 16];
const NID_BAR: NodeId = 7;

/// Owned backing tables for a `Resolver` (the resolver borrows
/// everything).
#[derive(Default)]
struct Tables {
    trans_hash: Vec<TransHash>,
    reloc_targets: HashMap<(u32, u32), HashMap<(u64, u32), ResolvedTarget>>,
    closure_nids: HashSet<NodeId>,
    mutable_ths: HashSet<TransHash>,
    wrapped: HashSet<String>,
    by_section: HashMap<TransHash, Placed>,
    ambiguous_sections: HashSet<TransHash>,
    by_name: HashMap<String, u64>,
    by_name_ambiguous: HashSet<String>,
    tls_range: Option<(u64, u64)>,
    tls_nids: HashSet<NodeId>,
}

impl Tables {
    /// Tables with node `NID_BAR` carrying `TH_BAR`, and the reloc at
    /// `(sec 0, offset 4, r_type 1)` of object 0 resolved as `target`.
    fn with_target(target: ResolvedTarget) -> Self {
        let mut t = Tables::default();
        t.trans_hash = vec![[0u8; 16]; (NID_BAR + 1) as usize];
        t.trans_hash[NID_BAR as usize] = TH_BAR;
        t.reloc_targets
            .entry((0, 0))
            .or_default()
            .insert((4, 1), target);
        t
    }

    fn resolver(&self) -> Resolver<'_> {
        Resolver {
            trans_hash: &self.trans_hash,
            reloc_targets: &self.reloc_targets,
            closure_nids: &self.closure_nids,
            mutable_ths: &self.mutable_ths,
            wrapped: &self.wrapped,
            by_section: &self.by_section,
            ambiguous_sections: &self.ambiguous_sections,
            by_name: &self.by_name,
            by_name_ambiguous: &self.by_name_ambiguous,
            tls_range: self.tls_range,
            tls_nids: &self.tls_nids,
        }
    }
}

/// The standard query: a named ref to `bar` from `.text.foo`, at the
/// reloc site `Tables::with_target` populated.
fn query_bar() -> RelocQuery<'static> {
    RelocQuery {
        section0: 0,
        offset: 4,
        r_type: 1,
        target_name: Some("bar"),
        weak_ref: false,
        from_section: ".text.foo",
    }
}

fn section_query() -> RelocQuery<'static> {
    RelocQuery { target_name: None, ..query_bar() }
}

#[test]
fn channel1_closure_node_disposes_und() {
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0 });
    t.closure_nids.insert(NID_BAR);

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Und { name: "bar".into(), weak: false, tls: false });
}

#[test]
fn channel1_is_node_keyed_not_hash_keyed() {
    // A DIFFERENT node with the same trans_hash is in the closure; the
    // target node is not. Channel 1 must NOT fire (a th-keyed check
    // would emit UND for a name the overlay never re-emits → ld binds
    // it to 0). The target's content is in base → positional anchor.
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0x10 });
    t.trans_hash.push(TH_BAR); // content twin at NID_BAR + 1
    t.closure_nids.insert(NID_BAR + 1);
    t.by_section.insert(TH_BAR, Placed { addr: 0x2000, out_size: 0x100 });

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Anchor { tls: false, vaddr: 0x2010, verify_name: None });
}

#[test]
fn channel2_content_match_anchors_positionally_without_verify() {
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0x10 });
    t.by_section.insert(TH_BAR, Placed { addr: 0x2000, out_size: 0x100 });

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Anchor { tls: false, vaddr: 0x2010, verify_name: None });
}

#[test]
fn channel2a_ambiguous_unique_name_pins_via_symtab_with_verify() {
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0x8 });
    t.by_section.insert(TH_BAR, Placed { addr: 0x2000, out_size: 0x100 }); // representative copy
    t.ambiguous_sections.insert(TH_BAR);
    t.by_name.insert("bar".into(), 0x3000); // bar's exact (unique) address

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(
        d,
        RelocDisposition::Anchor { tls: false, vaddr: 0x3000, verify_name: Some("bar".into()) },
    );
}

#[test]
fn ambiguous_mutable_unpinnable_bails() {
    // Mutable content at several base addresses and the name does NOT
    // uniquely resolve in base.symtab: a representative bind would alias
    // distinct variables (the M2 xtensa .bss/.data call-to-0 bug).
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0 });
    t.by_section.insert(TH_BAR, Placed { addr: 0x2000, out_size: 0x100 });
    t.ambiguous_sections.insert(TH_BAR);
    t.mutable_ths.insert(TH_BAR);
    t.by_name_ambiguous.insert("bar".into());

    let err = t.resolver().dispose(0, &query_bar()).expect_err("must bail");
    assert!(format!("{err:#}").contains("alias distinct variables"));
}

#[test]
fn ambiguous_readonly_same_name_dup_uses_representative() {
    // Byte-identical read-only copies, name not uniquely pinnable →
    // interchangeable; representative + offset, no verify.
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0x4 });
    t.by_section.insert(TH_BAR, Placed { addr: 0x2000, out_size: 0x100 });
    t.ambiguous_sections.insert(TH_BAR);
    t.by_name_ambiguous.insert("bar".into());

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Anchor { tls: false, vaddr: 0x2004, verify_name: None });
}

#[test]
fn content_drift_not_in_closure_bails() {
    // Overlay scanned a definition whose content differs from base
    // (th not in by_section) and the closure never re-emitted it — and
    // `bar` ALSO appears in base.symtab. Must bail rather than bind to
    // base's stale address.
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0 });
    t.by_name.insert("bar".into(), 0x1000); // tempting stale address

    let err = t.resolver().dispose(0, &query_bar()).expect_err("must bail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("differs from base") && msg.contains("not in the closure"),
        "unexpected error: {msg}"
    );
}

#[test]
fn channel4_external_name_anchors_with_verify() {
    let mut t = Tables::with_target(ResolvedTarget::External);
    t.by_name.insert("bar".into(), 0x1000);

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(
        d,
        RelocDisposition::Anchor { tls: false, vaddr: 0x1000, verify_name: Some("bar".into()) },
    );
}

#[test]
fn external_unrecorded_reloc_site_defaults_to_external() {
    // No recorded resolution for the site at all — treated as External,
    // resolved through base.symtab.
    let mut t = Tables::default();
    t.by_name.insert("bar".into(), 0x1000);

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(
        d,
        RelocDisposition::Anchor { tls: false, vaddr: 0x1000, verify_name: Some("bar".into()) },
    );
}

#[test]
fn ambiguous_base_name_bails() {
    let mut t = Tables::with_target(ResolvedTarget::External);
    t.by_name_ambiguous.insert("bar".into());

    let err = t.resolver().dispose(0, &query_bar()).expect_err("must bail");
    assert!(format!("{err:#}").contains("multiple distinct addresses"));
}

#[test]
fn weak_undef_mirrors_as_weak_und() {
    let t = Tables::with_target(ResolvedTarget::External);
    let q = RelocQuery { weak_ref: true, ..query_bar() };

    let d = t.resolver().dispose(0, &q).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Und { name: "bar".into(), weak: true, tls: false });
}

#[test]
fn unresolvable_name_bails() {
    let t = Tables::with_target(ResolvedTarget::External);
    let err = t.resolver().dispose(0, &query_bar()).expect_err("must bail");
    assert!(format!("{err:#}").contains("can't resolve"));
}

#[test]
fn wrapped_name_resolves_and_emits_as_wrapper() {
    // ld's --wrap redirects the reference; the emitted/verified name
    // must be the wrapper's.
    let mut t = Tables::with_target(ResolvedTarget::External);
    t.wrapped.insert("bar".into());
    t.by_name.insert("__wrap_bar".into(), 0x4000);

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(
        d,
        RelocDisposition::Anchor { tls: false, vaddr: 0x4000, verify_name: Some("__wrap_bar".into()) },
    );
}

#[test]
fn section_target_resolves_positionally() {
    let mut t = Tables::with_target(ResolvedTarget::Section { nid: NID_BAR });
    t.by_section.insert(TH_BAR, Placed { addr: 0x5000, out_size: 0x100 });

    let d = t.resolver().dispose(0, &section_query()).expect("dispose ok");
    // The reloc's own addend rides along separately; the anchor is the
    // section's base.
    assert_eq!(d, RelocDisposition::Anchor { tls: false, vaddr: 0x5000, verify_name: None });
}

#[test]
fn section_target_ambiguous_mutable_bails() {
    // STT_SECTION ref into ambiguous *mutable* content: no name to pin
    // a copy, representative would alias distinct variables.
    let mut t = Tables::with_target(ResolvedTarget::Section { nid: NID_BAR });
    t.by_section.insert(TH_BAR, Placed { addr: 0x5000, out_size: 0x100 });
    t.ambiguous_sections.insert(TH_BAR);
    t.mutable_ths.insert(TH_BAR);

    let err = t.resolver().dispose(0, &section_query()).expect_err("must bail");
    assert!(format!("{err:#}").contains("alias distinct variables"));
}

#[test]
fn section_target_ambiguous_readonly_uses_representative() {
    let mut t = Tables::with_target(ResolvedTarget::Section { nid: NID_BAR });
    t.by_section.insert(TH_BAR, Placed { addr: 0x5000, out_size: 0x100 });
    t.ambiguous_sections.insert(TH_BAR);

    let d = t.resolver().dispose(0, &section_query()).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Anchor { tls: false, vaddr: 0x5000, verify_name: None });
}

#[test]
fn section_target_content_absent_bails() {
    let t = Tables::with_target(ResolvedTarget::Section { nid: NID_BAR });
    // by_section empty → closure / scan-discovery gap.
    let err = t.resolver().dispose(0, &section_query()).expect_err("must bail");
    assert!(format!("{err:#}").contains("not in the closure"));
}

#[test]
fn section_target_without_scan_node_bails() {
    let t = Tables::with_target(ResolvedTarget::External);
    let err = t.resolver().dispose(0, &section_query()).expect_err("must bail");
    assert!(format!("{err:#}").contains("no scan node"));
}

#[test]
fn channel1_tls_node_disposes_stt_tls_und() {
    // A re-emitted thread-local referenced cross-object: the UND must
    // carry STT_TLS or ld rejects the bind ("TLS definition ...
    // mismatches non-TLS reference" — caught live by e2e scenario I).
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0 });
    t.closure_nids.insert(NID_BAR);
    t.tls_nids.insert(NID_BAR);

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Und { name: "bar".into(), weak: false, tls: true });
}

#[test]
fn channel2_anchor_inside_tls_range_is_classified_tls() {
    // The trans_hash table holds TLS sections at template vaddrs; an
    // anchor landing inside base's PT_TLS span must carry tls=true so
    // prune emits an STT_TLS reference and the base map defines it in
    // an SHF_TLS map section.
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0x10 });
    t.by_section.insert(TH_BAR, Placed { addr: 0x7000, out_size: 0x100 });
    t.tls_range = Some((0x7000, 0x7100));

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Anchor { tls: true, vaddr: 0x7010, verify_name: None });
}

#[test]
fn channel4_name_inside_tls_range_is_classified_tls() {
    // by_name TLS entries are template vaddrs too (load_base_metadata
    // translates st_value via PT_TLS.p_vaddr).
    let mut t = Tables::with_target(ResolvedTarget::External);
    t.by_name.insert("bar".into(), 0x7020);
    t.tls_range = Some((0x7000, 0x7100));

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(
        d,
        RelocDisposition::Anchor { tls: true, vaddr: 0x7020, verify_name: Some("bar".into()) },
    );
}

#[test]
fn anchor_outside_tls_range_is_not_tls() {
    let mut t = Tables::with_target(ResolvedTarget::Symbol { nid: NID_BAR, value: 0 });
    t.by_section.insert(TH_BAR, Placed { addr: 0x2000, out_size: 0x100 });
    t.tls_range = Some((0x7000, 0x7100));

    let d = t.resolver().dispose(0, &query_bar()).expect("dispose ok");
    assert_eq!(d, RelocDisposition::Anchor { tls: false, vaddr: 0x2000, verify_name: None });
}

// ---------------------------------------------------------------------
// Emission: prune_object renders dispositions faithfully.
// ---------------------------------------------------------------------

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

#[test]
fn prune_emits_anchor_and_records_verify_name() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let dispose = |q: &RelocQuery<'_>| {
        assert_eq!(q.target_name, Some("bar"));
        Ok(RelocDisposition::Anchor { tls: false, vaddr: 0x3000, verify_name: Some("bar".into()) })
    };
    let p = prune::prune_object(&bytes, &keep, &dispose).expect("prune ok");
    assert_eq!(p.anchor_rewrites, 1);
    assert_eq!(p.assumed_names, vec![("bar".to_string(), 0x3000)]);
    assert_eq!(p.anchors, vec![(0x3000, false)]);

    // The anchor is an UND *reference* — the overlay run's base-map
    // object defines it (section symbol or ABS per classification).
    use object::ObjectSymbol;
    let out = object::File::parse(&*p.bytes).unwrap();
    let anchor = out
        .symbols()
        .find(|s| s.name().unwrap_or("") == "__graft_assumed_0000000000003000")
        .expect("anchor symbol present");
    assert!(anchor.is_undefined(), "anchors are UND refs into the base map");
    assert!(!matches!(anchor.kind(), object::SymbolKind::Tls));
}

#[test]
fn prune_emits_tls_und_as_stt_tls() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let dispose =
        |_q: &RelocQuery<'_>| Ok(RelocDisposition::Und { name: "bar".into(), weak: false, tls: true });
    let p = prune::prune_object(&bytes, &keep, &dispose).expect("prune ok");

    use object::ObjectSymbol;
    let out = object::File::parse(&*p.bytes).unwrap();
    let und = out
        .symbols()
        .find(|s| s.name().unwrap_or("") == "bar")
        .expect("UND bar present");
    assert!(und.is_undefined());
    assert!(matches!(und.kind(), object::SymbolKind::Tls));
}

#[test]
fn prune_emits_tls_anchor_as_und_stt_tls() {
    // TLS-flavored relocs require an STT_TLS symbol; the TLS flag on
    // the disposition must surface as the UND reference's type.
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let dispose = |_q: &RelocQuery<'_>| {
        Ok(RelocDisposition::Anchor { tls: true, vaddr: 0x7010, verify_name: None })
    };
    let p = prune::prune_object(&bytes, &keep, &dispose).expect("prune ok");
    assert_eq!(p.anchors, vec![(0x7010, true)]);

    use object::ObjectSymbol;
    let out = object::File::parse(&*p.bytes).unwrap();
    let anchor = out
        .symbols()
        .find(|s| s.name().unwrap_or("") == "__graft_assumed_0000000000007010")
        .expect("anchor symbol present");
    assert!(anchor.is_undefined());
    assert!(
        matches!(anchor.kind(), object::SymbolKind::Tls),
        "TLS anchor reference must be STT_TLS, got {:?}",
        anchor.kind()
    );
}

#[test]
fn prune_emits_und_for_closure_target() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let dispose =
        |_q: &RelocQuery<'_>| Ok(RelocDisposition::Und { name: "bar".into(), weak: false, tls: false });
    let p = prune::prune_object(&bytes, &keep, &dispose).expect("prune ok");
    assert_eq!(p.anchor_rewrites, 0, "UND disposition must not create an anchor");
    assert!(p.assumed_names.is_empty());

    use object::ObjectSymbol;
    let out = object::File::parse(&*p.bytes).unwrap();
    let und = out
        .symbols()
        .find(|s| s.name().unwrap_or("") == "bar")
        .expect("UND bar present");
    assert!(und.is_undefined());
    assert!(!und.is_weak());
}

#[test]
fn prune_emits_weak_und() {
    let bytes = synth_obj_ref_bar();
    let keep = keep_text_foo(&bytes);
    let dispose =
        |_q: &RelocQuery<'_>| Ok(RelocDisposition::Und { name: "bar".into(), weak: true, tls: false });
    let p = prune::prune_object(&bytes, &keep, &dispose).expect("prune ok");

    use object::ObjectSymbol;
    let out = object::File::parse(&*p.bytes).unwrap();
    let und = out
        .symbols()
        .find(|s| s.name().unwrap_or("") == "bar")
        .expect("UND bar present");
    assert!(und.is_undefined());
    assert!(und.is_weak());
}

#[test]
fn prune_wires_internal_section_target_without_dispose() {
    // `.text.foo` (kept) has an STT_SECTION reloc into `.shared` (also
    // kept) — fully internal; dispose must never be consulted.
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text_id = obj.add_section(Vec::new(), b".text.foo".to_vec(), SectionKind::Text);
    obj.set_section_data(text_id, vec![0xccu8; 16], 4);
    let shared_id = obj.add_section(Vec::new(), b".shared".to_vec(), SectionKind::Text);
    obj.set_section_data(shared_id, vec![0x90u8; 16], 4);
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
    let bytes = obj.write().expect("emit ELF");

    let f = object::File::parse(&*bytes).unwrap();
    let keep: HashSet<u32> = f.sections().map(|s| s.index().0 as u32 - 1).collect();

    let dispose = |q: &RelocQuery<'_>| -> anyhow::Result<RelocDisposition> {
        panic!("internal reloc must not reach dispose: {:?}", q.from_section)
    };
    let p = prune::prune_object(&bytes, &keep, &dispose).expect("prune ok");
    assert_eq!(p.anchor_rewrites, 0);
}
