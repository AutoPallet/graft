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
        .expect("fold should find the duplicate");
    assert_eq!(outcome.stats.groups_folded, 1, "exactly the dupfn group folds");
    assert_eq!(outcome.stats.copies_dropped, 1);
    assert_eq!(outcome.stats.bytes_dropped, DUPFN.len() as u64);
    // The byte-identical GLOBAL callers must NOT fold (name mismatch /
    // non-local — either skip is acceptable, folding them is not).
    assert_eq!(
        outcome.stats.skipped_name_mismatch + outcome.stats.skipped_nonlocal,
        1,
        "the use_a/use_b 'twin' group is skipped, not folded"
    );

    let new_rlib = outcome
        .replacements
        .get(&std::fs::canonicalize(&rlib).unwrap())
        .expect("rlib rewritten");

    // Symmetric weak aliasing: BOTH members define __graft_icf_* as a
    // weak symbol at their own copy; neither imports anything (no
    // cross-object UND may exist — archive member selection must stay
    // bit-identical to the unfolded link).
    {
        use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
        let bytes = std::fs::read(new_rlib).unwrap();
        let ar = ArchiveFile::parse(&*bytes).unwrap();
        let mut weak_defs = 0;
        let mut unds = 0;
        for m in ar.members() {
            let m = m.unwrap();
            let data = m.data(&*bytes).unwrap();
            let obj = object::File::parse(data).unwrap();
            for sym in obj.symbols() {
                let name = sym.name().unwrap_or("");
                if !name.starts_with("__graft_icf_") {
                    continue;
                }
                if sym.is_undefined() {
                    unds += 1;
                } else {
                    assert!(sym.is_weak(), "fold definitions must be weak");
                    weak_defs += 1;
                }
            }
        }
        assert_eq!((weak_defs, unds), (2, 0), "every copy defines weak, none imports");
    }

    // Folded link: one copy, same behavior.
    let folded = d.join("folded");
    assert!(
        link("cc", &folded, &[&d.join("main.o"), new_rlib]),
        "link with rewritten rlib failed"
    );
    let folded_bytes = std::fs::read(&folded).unwrap();
    assert_eq!(count_pattern(&folded_bytes, DUPFN), 1, "fold left exactly one copy");
    assert_eq!(run_exit_code(&folded), 84, "folded program still computes 42+42");
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
