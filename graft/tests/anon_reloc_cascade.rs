//! Regression test for the anon-section reloc-target cascade.
//!
//! Synthesizes two relocatable ELFs — "base" and "overlay" — that
//! differ ONLY in the *names* of an anonymous rodata section that
//! a `.text.foo` reloc points at. The bytes of `.text.foo` are
//! identical in both. The bytes of the anon section are also
//! identical. Every other input is identical.
//!
//! The trans_hash for `foo` should be identical in both — its bytes
//! are the same and its semantic dependency is the same content. If
//! `encode_relocs` includes the (unstable, build-noise) anon section
//! name verbatim, the hashes will differ instead, which is the
//! cascade we observed in the roborack3 mutation experiments.
//!
//! Background: rustc emits compiler-generated rodata constants under
//! names like `.rodata..Lanon.<cgu-fingerprint>.<n>`. Both the
//! `<cgu-fingerprint>` (when CGUs re-partition) and `<n>` (when new
//! anons are inserted earlier in the same CGU) shift between builds
//! that share most of their source. Sections that reference an anon
//! by `<section:.rodata..Lanon.<old>.<m>>` in base and
//! `<section:.rodata..Lanon.<new>.<n>>` in overlay would otherwise
//! flip their per-section hash, which propagates upstream through
//! SCC successors and explodes the closure.
//!
//! Same applies to `anon.<cgu>.<n>.llvm.<id>` (global-symbol form
//! for hidden-linkage anon objects) and to the `.llvm.<id>` suffix
//! that rustc appends to internal-linkage symbols.

use std::path::PathBuf;

use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

/// Build a relocatable ELF with one `.text.foo` containing a single
/// reloc to an anonymous rodata section. The anon section's *name* is
/// caller-supplied (so two builds can use different names) but its
/// *content* is fixed across both.
fn synth_obj(anon_section_name: &[u8]) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    // .text.foo — 16 bytes of arbitrary code with one reloc at offset 4.
    let text_id = obj.add_section(Vec::new(), b".text.foo".to_vec(), SectionKind::Text);
    obj.set_section_data(text_id, vec![0xccu8; 16], 4);
    let foo_sym = obj.add_symbol(Symbol {
        name: b"foo".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text_id),
        flags: SymbolFlags::None,
    });
    let _ = foo_sym;

    // Anon rodata — 12 bytes of arbitrary content. *Name* varies
    // between calls; bytes do not.
    let anon_id = obj.add_section(Vec::new(), anon_section_name.to_vec(), SectionKind::ReadOnlyData);
    obj.set_section_data(anon_id, b"hello world\0".to_vec(), 4);
    let anon_section_sym = obj.section_symbol(anon_id);

    // Reloc at .text.foo+4 → anon section + 0. Section-targeted
    // (STT_SECTION); graft's `parse` records the target as
    // `<section:<anon_section_name>>`.
    obj.add_relocation(
        text_id,
        Relocation {
            offset: 4,
            symbol: anon_section_sym,
            addend: 0,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Absolute,
                encoding: RelocationEncoding::Generic,
                size: 64,
            },
        },
    )
    .expect("add reloc");

    obj.write().expect("emit ELF")
}

/// Run scan, find `foo`'s trans_hash.
fn foo_trans_hash(obj_bytes: &[u8]) -> [u8; 16] {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("synth.o");
    std::fs::write(&path, obj_bytes).expect("write");

    let r = graft::scan::run::<PathBuf>(&[path]).expect("scan");
    // `foo`'s defining section is `.text.foo`. Find the NodeId for it
    // and look up its trans_hash.
    let (obj_idx, sec_idx) = r
        .objects
        .iter()
        .enumerate()
        .find_map(|(oi, o)| {
            o.sections
                .iter()
                .position(|s| s.name == ".text.foo")
                .map(|si| (oi, si))
        })
        .expect("find .text.foo");
    let nid = r
        .graph
        .nodes
        .iter()
        .position(|nm| nm.object as usize == obj_idx && nm.section as usize == sec_idx)
        .expect("nodeid for .text.foo");
    r.trans_hash[nid]
}

#[test]
fn foo_hash_stable_under_anon_section_rename() {
    // Two anon section names that an unfixed rustc emission would use:
    //   base    : .rodata..Lanon.<cgu-AA>.<5>
    //   overlay : .rodata..Lanon.<cgu-BB>.<7>
    // Both wrap identical bytes. graft must hash `foo` the same.
    let base = synth_obj(b".rodata..Lanon.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.5");
    let overlay = synth_obj(b".rodata..Lanon.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.7");

    let h_base = foo_trans_hash(&base);
    let h_overlay = foo_trans_hash(&overlay);

    assert_eq!(
        h_base, h_overlay,
        "foo's trans_hash should be stable when the only difference between two builds is \
         compiler-internal anon-section naming (CGU fingerprint + sequence index). \
         Differing here means encode_relocs serializes the unstable target name verbatim, \
         which is the cascade observed in the roborack3 fallback-string experiment."
    );
}

#[test]
fn foo_hash_stable_under_section_to_symbol_reloc_form_shift() {
    // Same content for foo and bar, but in one build foo references
    // bar via the section symbol (STT_SECTION reloc, encoded as
    // `<section:.text.bar>`) and in the other via bar's global
    // symbol (encoded as `bar`). This shows up in real builds when
    // cargo's incremental re-partitioning moves bar to a different
    // CGU: an intra-CGU reloc that used STT_SECTION becomes a
    // cross-CGU symbol reloc. Without resolving by content, the
    // encoded reloc lists differ even though the semantic dependency
    // is identical.
    let base = synth_two_funcs(/*by_section=*/ true);
    let overlay = synth_two_funcs(/*by_section=*/ false);
    assert_eq!(
        foo_trans_hash(&base),
        foo_trans_hash(&overlay),
        "foo's trans_hash should be stable when a reloc to bar shifts \
         between STT_SECTION form (`<section:...>`) and global-symbol \
         form across builds. Differing means encode_relocs distinguishes \
         the two reloc forms despite both pointing at the same bar bytes."
    );
}

/// Build an .o with `.text.foo` (16 bytes) calling into `.text.bar`
/// (8 bytes). When `by_section` is true, the reloc targets bar via
/// the section symbol (STT_SECTION). When false, the reloc targets
/// bar via its global symbol.
fn synth_two_funcs(by_section: bool) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    let foo_id = obj.add_section(Vec::new(), b".text.foo".to_vec(), SectionKind::Text);
    obj.set_section_data(foo_id, vec![0xccu8; 16], 4);
    let _foo_sym = obj.add_symbol(Symbol {
        name: b"foo".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(foo_id),
        flags: SymbolFlags::None,
    });

    let bar_id = obj.add_section(Vec::new(), b".text.bar".to_vec(), SectionKind::Text);
    obj.set_section_data(bar_id, vec![0x90u8; 8], 4);
    let bar_sym = obj.add_symbol(Symbol {
        name: b"bar".to_vec(),
        value: 0,
        size: 8,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(bar_id),
        flags: SymbolFlags::None,
    });

    let target_sym = if by_section {
        obj.section_symbol(bar_id)
    } else {
        bar_sym
    };
    obj.add_relocation(
        foo_id,
        Relocation {
            offset: 4,
            symbol: target_sym,
            addend: 0,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Absolute,
                encoding: RelocationEncoding::Generic,
                size: 64,
            },
        },
    )
    .expect("add reloc");

    obj.write().expect("emit ELF")
}

#[test]
fn foo_hash_differs_when_target_content_changes() {
    // Sanity: actually changing bar's content must change foo's
    // trans_hash. This is the contrapositive — without it, the
    // canonicalizer might be over-collapsing.
    let a = synth_obj(b".rodata..Lanon.aa.1");
    let b = synth_obj_with_anon_bytes(b".rodata..Lanon.aa.1", b"different??\0");
    assert_ne!(
        foo_trans_hash(&a),
        foo_trans_hash(&b),
        "foo's trans_hash must change when its (anon) target's bytes \
         change — otherwise the canonicalizer is collapsing genuinely \
         distinct content."
    );
}

/// Like synth_obj but with caller-supplied anon bytes (12 bytes).
fn synth_obj_with_anon_bytes(anon_section_name: &[u8], anon_bytes: &[u8]) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text_id = obj.add_section(Vec::new(), b".text.foo".to_vec(), SectionKind::Text);
    obj.set_section_data(text_id, vec![0xccu8; 16], 4);
    let _ = obj.add_symbol(Symbol {
        name: b"foo".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text_id),
        flags: SymbolFlags::None,
    });
    let anon_id =
        obj.add_section(Vec::new(), anon_section_name.to_vec(), SectionKind::ReadOnlyData);
    let mut bytes = anon_bytes.to_vec();
    bytes.resize(12, 0);
    obj.set_section_data(anon_id, bytes, 4);
    let anon_sym = obj.section_symbol(anon_id);
    obj.add_relocation(
        text_id,
        Relocation {
            offset: 4,
            symbol: anon_sym,
            addend: 0,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Absolute,
                encoding: RelocationEncoding::Generic,
                size: 64,
            },
        },
    )
    .expect("add reloc");
    obj.write().expect("emit ELF")
}

#[test]
fn foo_hash_stable_under_llvm_id_suffix_drift() {
    // .llvm.<digits> internal-linkage suffix is rustc per-build noise.
    // A reloc to `<section:.text.bar.llvm.123>` in one build and
    // `<section:.text.bar.llvm.456>` in another should hash the same
    // when bar's content matches.
    let a = synth_obj_with_named_target(b".text.bar.llvm.123");
    let b = synth_obj_with_named_target(b".text.bar.llvm.456");
    assert_eq!(
        foo_trans_hash(&a),
        foo_trans_hash(&b),
        ".llvm.<id> suffix drift on the target section name must not \
         change foo's trans_hash."
    );
}

fn synth_obj_with_named_target(target_section_name: &[u8]) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let foo_id = obj.add_section(Vec::new(), b".text.foo".to_vec(), SectionKind::Text);
    obj.set_section_data(foo_id, vec![0xccu8; 16], 4);
    let _ = obj.add_symbol(Symbol {
        name: b"foo".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(foo_id),
        flags: SymbolFlags::None,
    });
    let bar_id =
        obj.add_section(Vec::new(), target_section_name.to_vec(), SectionKind::Text);
    obj.set_section_data(bar_id, vec![0x90u8; 8], 4);
    let _ = obj.add_symbol(Symbol {
        name: b"bar".to_vec(),
        value: 0,
        size: 8,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(bar_id),
        flags: SymbolFlags::None,
    });
    let target_sym = obj.section_symbol(bar_id);
    obj.add_relocation(
        foo_id,
        Relocation {
            offset: 4,
            symbol: target_sym,
            addend: 0,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Absolute,
                encoding: RelocationEncoding::Generic,
                size: 64,
            },
        },
    )
    .expect("add reloc");
    obj.write().expect("emit ELF")
}
