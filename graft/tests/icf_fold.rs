//! End-to-end test of the GRAFT_ICF fold pass (`icf.rs`).
//!
//! Builds two synthetic "rcgu" objects that each carry an identical
//! LOCAL function in `.text.dupfn` plus a GLOBAL caller, archives them
//! into an rlib, runs the fold, and verifies:
//!   - group formation folds exactly the LOCAL duplicate (the byte-
//!     identical GLOBAL callers are skipped: distinct section names);
//!   - the rewritten dropper carries a UND `__graft_icf_*` and the
//!     keeper defines it;
//!   - a real `cc -Wl,--gc-sections` link of the rewritten inputs
//!     produces ONE copy of the duplicate's bytes (two without ICF)
//!     and the program still computes the right answer through both
//!     callers.
//!
//! Requires `cc` and x86-64 Linux; skips silently otherwise (the same
//! policy as the other link-driving tests).

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolKind,
    write::{Object as WObject, Relocation as WRelocation, Symbol as WSymbol, SymbolSection},
};

/// mov eax, 42 ; ret
const DUPFN: &[u8] = &[0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3];

/// call rel32 <dupfn> ; ret   (reloc at +1)
const CALLER: &[u8] = &[0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3];

fn build_rcgu(caller_name: &str) -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

    let dup_sec = obj.add_section(Vec::new(), b".text.dupfn".to_vec(), SectionKind::Text);
    obj.section_mut(dup_sec).set_data(DUPFN.to_vec(), 16);
    let dup_sym = obj.add_symbol(WSymbol {
        name: b"dupfn".to_vec(),
        value: 0,
        size: DUPFN.len() as u64,
        kind: SymbolKind::Text,
        scope: object::write::SymbolScope::Compilation, // LOCAL
        weak: false,
        section: SymbolSection::Section(dup_sec),
        flags: object::write::SymbolFlags::None,
    });

    let caller_sec = obj.add_section(
        Vec::new(),
        format!(".text.{caller_name}").into_bytes(),
        SectionKind::Text,
    );
    obj.section_mut(caller_sec).set_data(CALLER.to_vec(), 16);
    obj.add_symbol(WSymbol {
        name: caller_name.as_bytes().to_vec(),
        value: 0,
        size: CALLER.len() as u64,
        kind: SymbolKind::Text,
        scope: object::write::SymbolScope::Linkage, // GLOBAL
        weak: false,
        section: SymbolSection::Section(caller_sec),
        flags: object::write::SymbolFlags::None,
    });
    obj.add_relocation(
        caller_sec,
        WRelocation {
            offset: 1,
            symbol: dup_sym,
            addend: -4,
            flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
        },
    )
    .unwrap();

    obj.write().unwrap()
}

/// int main(void) { return use_a() + use_b(); }
fn build_main() -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    // push rbx; call use_a; mov ebx,eax; call use_b; add eax,ebx; pop rbx; ret
    let code: Vec<u8> = vec![
        0x53, // push rbx
        0xe8, 0, 0, 0, 0, // call use_a (reloc at 2)
        0x89, 0xc3, // mov ebx, eax
        0xe8, 0, 0, 0, 0, // call use_b (reloc at 9)
        0x01, 0xd8, // add eax, ebx
        0x5b, // pop rbx
        0xc3, // ret
    ];
    let sec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
    obj.section_mut(sec).set_data(code, 16);
    obj.add_symbol(WSymbol {
        name: b"main".to_vec(),
        value: 0,
        size: 17,
        kind: SymbolKind::Text,
        scope: object::write::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(sec),
        flags: object::write::SymbolFlags::None,
    });
    for (off, name) in [(2u64, "use_a"), (9u64, "use_b")] {
        let sym = obj.add_symbol(WSymbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            scope: object::write::SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::write::SymbolFlags::None,
        });
        obj.add_relocation(
            sec,
            WRelocation {
                offset: off,
                symbol: sym,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }
    obj.write().unwrap()
}

/// int main(void) { return use_0() + use_1() + ...; }  (sum in ebx)
fn build_main_many(callers: &[String]) -> Vec<u8> {
    let mut obj = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let mut code: Vec<u8> = vec![
        0x53, // push rbx
        0x31, 0xdb, // xor ebx, ebx
    ];
    let mut reloc_offsets = Vec::new();
    for _ in callers {
        reloc_offsets.push(code.len() as u64 + 1);
        code.extend_from_slice(&[0xe8, 0, 0, 0, 0]); // call rel32
        code.extend_from_slice(&[0x01, 0xc3]); // add ebx, eax
    }
    code.extend_from_slice(&[0x89, 0xd8, 0x5b, 0xc3]); // mov eax,ebx; pop rbx; ret
    let size = code.len() as u64;
    let sec = obj.add_section(Vec::new(), b".text.main".to_vec(), SectionKind::Text);
    obj.section_mut(sec).set_data(code, 16);
    obj.add_symbol(WSymbol {
        name: b"main".to_vec(),
        value: 0,
        size,
        kind: SymbolKind::Text,
        scope: object::write::SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(sec),
        flags: object::write::SymbolFlags::None,
    });
    for (off, name) in reloc_offsets.iter().zip(callers) {
        let sym = obj.add_symbol(WSymbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            scope: object::write::SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::write::SymbolFlags::None,
        });
        obj.add_relocation(
            sec,
            WRelocation {
                offset: *off,
                symbol: sym,
                addend: -4,
                flags: RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            },
        )
        .unwrap();
    }
    obj.write().unwrap()
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn link(cc: &str, out: &Path, inputs: &[&Path]) -> bool {
    let mut c = Command::new(cc);
    c.arg("-o").arg(out);
    for i in inputs {
        c.arg(i);
    }
    c.arg("-Wl,--gc-sections");
    let st = c.status().expect("spawn cc");
    st.success()
}

fn count_pattern(elf_bytes: &[u8], pat: &[u8]) -> usize {
    use object::{Object, ObjectSection};
    let elf = object::File::parse(elf_bytes).unwrap();
    let mut count = 0;
    for sec in elf.sections() {
        if sec.kind() != object::SectionKind::Text {
            continue;
        }
        let data = sec.data().unwrap_or(&[]);
        count += data.windows(pat.len()).filter(|w| *w == pat).count();
    }
    count
}

fn run_exit_code(prog: &Path) -> i32 {
    Command::new(prog)
        .status()
        .expect("run linked program")
        .code()
        .expect("program terminated by signal")
}

#[test]
fn fold_local_duplicate_across_rlib_members() {
    if !have("cc") || !have("ar") {
        eprintln!("skipping: cc/ar not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    // Long member names force the `//` extended-name table — the shape
    // real rlibs have.
    let a_name = "dup_alpha-0123456789abcdef.rcgu.o";
    let b_name = "dup_beta-fedcba9876543210.rcgu.o";
    std::fs::write(d.join(a_name), build_rcgu("use_a")).unwrap();
    std::fs::write(d.join(b_name), build_rcgu("use_b")).unwrap();
    std::fs::write(d.join("main.o"), build_main()).unwrap();

    let rlib = d.join("libdup.rlib");
    let st = Command::new("ar")
        .current_dir(d)
        .args(["crs", "libdup.rlib", a_name, b_name])
        .status()
        .unwrap();
    assert!(st.success(), "ar failed");

    // Control link: two copies of the duplicate bytes, exit code 84.
    let control = d.join("control");
    assert!(link("cc", &control, &[&d.join("main.o"), &rlib]));
    let control_bytes = std::fs::read(&control).unwrap();
    assert_eq!(count_pattern(&control_bytes, DUPFN), 2, "control should keep both copies");
    assert_eq!(run_exit_code(&control), 84);

    // Scan + fold.
    let scan = graft::scan::run(
        &[d.join("main.o"), rlib.clone()],
        &[] as &[PathBuf],
        &[],
        &[],
        Some("main"),
    )
    .unwrap();
    let fake_output = d.join("out.elf");
    let outcome = graft::icf::run(&scan, &fake_output)
        .unwrap()
        .expect("fold should find the duplicates");
    // Two groups fold: the LOCAL dupfn twins AND the byte-identical
    // GLOBAL use_a/use_b callers (demote-to-weak + cross-alias path;
    // same name class `.text`, trans_hash equal because their dupfn
    // callees hash equal).
    assert_eq!(outcome.stats.groups_folded, 2);
    assert_eq!(outcome.stats.copies_dropped, 2);
    assert_eq!(
        outcome.stats.bytes_dropped,
        (DUPFN.len() + CALLER.len()) as u64
    );

    let new_rlib = outcome
        .replacements
        .get(&std::fs::canonicalize(&rlib).unwrap())
        .expect("rlib rewritten");

    // Symmetric weak aliasing: BOTH members define __graft_icf_* (one
    // per folded group) as weak symbols at their own copies; neither
    // imports anything (no cross-object UND may exist — archive member
    // selection must stay bit-identical to the unfolded link). The
    // GLOBAL callers are demoted to weak in their own members and
    // cross-aliased weak in the other.
    {
        use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
        let bytes = std::fs::read(new_rlib).unwrap();
        let ar = ArchiveFile::parse(&*bytes).unwrap();
        let mut icf_weak_defs = 0;
        let mut unds = 0;
        let mut use_defs = 0; // use_a/use_b definitions across members
        for m in ar.members() {
            let m = m.unwrap();
            let data = m.data(&*bytes).unwrap();
            let obj = object::File::parse(data).unwrap();
            for sym in obj.symbols() {
                let name = sym.name().unwrap_or("");
                if sym.is_undefined() {
                    if name.starts_with("__graft_icf_") {
                        unds += 1;
                    }
                    continue;
                }
                if name.starts_with("__graft_icf_") {
                    assert!(sym.is_weak(), "fold definitions must be weak");
                    icf_weak_defs += 1;
                }
                if name == "use_a" || name == "use_b" {
                    assert!(
                        sym.is_weak(),
                        "{name} must be weak (demoted or cross-aliased)"
                    );
                    use_defs += 1;
                }
            }
        }
        // 2 groups × 2 members = 4 weak group names; each member holds
        // its own demoted caller + the other's alias = 4 defs total.
        assert_eq!((icf_weak_defs, unds), (4, 0));
        assert_eq!(use_defs, 4);
    }

    // Folded link: one copy, same behavior.
    let folded = d.join("folded");
    assert!(
        link("cc", &folded, &[&d.join("main.o"), new_rlib]),
        "link with rewritten rlib failed"
    );
    let folded_bytes = std::fs::read(&folded).unwrap();
    assert_eq!(count_pattern(&folded_bytes, DUPFN), 1, "fold left exactly one dupfn copy");
    assert_eq!(run_exit_code(&folded), 84, "folded program still computes 42+42");
    // The GLOBAL caller twins folded too: one body, and both names
    // resolve to the same address.
    {
        use object::{Object, ObjectSymbol};
        let elf = object::File::parse(&*folded_bytes).unwrap();
        let addr = |n: &str| {
            elf.symbols()
                .find(|s| s.name() == Ok(n))
                .unwrap_or_else(|| panic!("{n} missing"))
                .address()
        };
        assert_eq!(addr("use_a"), addr("use_b"), "caller twins share one body");
    }
}

/// Groups larger than MAX_PARTICIPANTS split into independent chunks,
/// each folding under its own weak name: 18 copies → a 16-chunk and a
/// 2-chunk → exactly TWO survivors, and the program still runs right.
#[test]
fn oversized_group_folds_as_chunks() {
    if !have("cc") || !have("ar") {
        eprintln!("skipping: cc/ar not available");
        return;
    }
    let n = graft::icf::MAX_PARTICIPANTS + 2; // 18: chunks of 16 + 2
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    let callers: Vec<String> = (0..n).map(|i| format!("use_{i:02}")).collect();
    let members: Vec<String> = (0..n)
        .map(|i| format!("dup_{i:02}-0123456789abcdef.rcgu.o"))
        .collect();
    for (m, c) in members.iter().zip(&callers) {
        std::fs::write(d.join(m), build_rcgu(c)).unwrap();
    }
    std::fs::write(d.join("main.o"), build_main_many(&callers)).unwrap();

    let rlib = d.join("libdup.rlib");
    let st = Command::new("ar")
        .current_dir(d)
        .args(["crs", "libdup.rlib"])
        .args(&members)
        .status()
        .unwrap();
    assert!(st.success(), "ar failed");

    // main's exit code is (n * 42) & 0xff.
    let expected_exit = ((n as i32) * 42) & 0xff;

    // Control link: every copy survives.
    let control = d.join("control");
    assert!(link("cc", &control, &[&d.join("main.o"), &rlib]));
    let control_bytes = std::fs::read(&control).unwrap();
    assert_eq!(count_pattern(&control_bytes, DUPFN), n, "control keeps all copies");
    assert_eq!(run_exit_code(&control), expected_exit);

    // Scan + fold. Two groups of 18 (dupfn twins, caller twins); each
    // splits 16+2, dropping (16-1)+(2-1) = 16 copies per group.
    let scan = graft::scan::run(
        &[d.join("main.o"), rlib.clone()],
        &[] as &[PathBuf],
        &[],
        &[],
        Some("main"),
    )
    .unwrap();
    let outcome = graft::icf::run(&scan, &d.join("out.elf"))
        .unwrap()
        .expect("fold should find the duplicates");
    assert_eq!(outcome.stats.groups_folded, 2);
    assert_eq!(outcome.stats.groups_chunked, 2);
    assert_eq!(outcome.stats.copies_dropped, 2 * (n - 2));
    assert_eq!(
        outcome.stats.bytes_dropped,
        ((n - 2) * (DUPFN.len() + CALLER.len())) as u64
    );

    let new_rlib = outcome
        .replacements
        .get(&std::fs::canonicalize(&rlib).unwrap())
        .expect("rlib rewritten");

    // Per group: one unsuffixed chunk-0 name + one `_c1` name. No UNDs
    // ever (weak defs self-resolve within each member).
    {
        use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
        let bytes = std::fs::read(new_rlib).unwrap();
        let ar = ArchiveFile::parse(&*bytes).unwrap();
        let mut icf_names: std::collections::HashSet<String> = Default::default();
        for m in ar.members() {
            let m = m.unwrap();
            let data = m.data(&*bytes).unwrap();
            let obj = object::File::parse(data).unwrap();
            for sym in obj.symbols() {
                let name = sym.name().unwrap_or("");
                if !name.starts_with("__graft_icf_") {
                    continue;
                }
                assert!(!sym.is_undefined(), "no cross-object UND allowed: {name}");
                assert!(sym.is_weak(), "fold definitions must be weak: {name}");
                icf_names.insert(name.to_string());
            }
        }
        assert_eq!(icf_names.len(), 4, "2 groups × 2 chunks: {icf_names:?}");
        assert_eq!(
            icf_names.iter().filter(|n| n.ends_with("_c1")).count(),
            2,
            "one _c1 name per group: {icf_names:?}"
        );
    }

    // Folded link: one dupfn survivor per chunk (2 total), callers
    // collapse to 2 distinct addresses with multiplicity {16, 2}.
    let folded = d.join("folded");
    assert!(
        link("cc", &folded, &[&d.join("main.o"), new_rlib]),
        "link with rewritten rlib failed"
    );
    let folded_bytes = std::fs::read(&folded).unwrap();
    assert_eq!(count_pattern(&folded_bytes, DUPFN), 2, "one dupfn survivor per chunk");
    assert_eq!(run_exit_code(&folded), expected_exit);
    {
        use object::{Object, ObjectSymbol};
        let elf = object::File::parse(&*folded_bytes).unwrap();
        let mut by_addr: std::collections::HashMap<u64, usize> = Default::default();
        for c in &callers {
            let addr = elf
                .symbols()
                .find(|s| s.name() == Ok(c.as_str()))
                .unwrap_or_else(|| panic!("{c} missing"))
                .address();
            *by_addr.entry(addr).or_default() += 1;
        }
        let mut mult: Vec<usize> = by_addr.values().copied().collect();
        mult.sort();
        assert_eq!(mult, vec![2, n - 2], "callers fold per chunk");
    }
}

#[test]
fn archive_rebuild_is_parse_equivalent_without_edits() {
    if !have("ar") {
        eprintln!("skipping: ar not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let a_name = "member_one-0123456789abcdef.rcgu.o";
    let b_name = "m2.o";
    std::fs::write(d.join(a_name), build_rcgu("use_a")).unwrap();
    std::fs::write(d.join(b_name), build_rcgu("use_b")).unwrap();
    let st = Command::new("ar")
        .current_dir(d)
        .args(["crs", "lib.rlib", a_name, b_name])
        .status()
        .unwrap();
    assert!(st.success());
    let orig = std::fs::read(d.join("lib.rlib")).unwrap();

    // No replacements, no index additions: the rebuild must preserve
    // members, names, data, and the symbol index verbatim-equivalent.
    let rebuilt =
        graft::icf::rebuild_archive_for_tests(&orig, &Default::default(), &[]).unwrap();

    use object::read::archive::ArchiveFile;
    let ar_a = ArchiveFile::parse(&*orig).unwrap();
    let ar_b = ArchiveFile::parse(&*rebuilt).unwrap();
    let mems_a: Vec<(Vec<u8>, Vec<u8>)> = ar_a
        .members()
        .map(|m| {
            let m = m.unwrap();
            (m.name().to_vec(), m.data(&*orig).unwrap().to_vec())
        })
        .collect();
    let mems_b: Vec<(Vec<u8>, Vec<u8>)> = ar_b
        .members()
        .map(|m| {
            let m = m.unwrap();
            (m.name().to_vec(), m.data(&*rebuilt).unwrap().to_vec())
        })
        .collect();
    assert_eq!(mems_a, mems_b);

    let syms = |ar: &ArchiveFile, bytes: &[u8]| -> Vec<(String, Vec<u8>)> {
        let _ = bytes;
        ar.symbols()
            .unwrap()
            .unwrap()
            .map(|s| {
                let s = s.unwrap();
                (String::from_utf8_lossy(s.name()).into_owned(), Vec::new())
            })
            .collect()
    };
    assert_eq!(syms(&ar_a, &orig), syms(&ar_b, &rebuilt));
}
