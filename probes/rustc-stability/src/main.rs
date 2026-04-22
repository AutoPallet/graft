//! M0.25 — rustc stability probe.
//!
//! Builds a small fixture workspace under several scenarios and compares
//! the resulting `.rcgu.o` files. Answers three questions:
//!
//! 1. **Determinism.** Back-to-back identical builds produce byte-identical
//!    `.o` files for matched TUs?
//! 2. **Unrelated-edit isolation.** Adding an unrelated function to one
//!    crate shifts `.o`s in other crates?
//! 3. **tu_id candidate stability.** Which of three candidates for a
//!    structural translation-unit identifier is actually stable:
//!
//!    1. `.o` member filename with drifting hash-like segments stripped.
//!    2. First `STT_FILE` entry in the `.o`'s `.symtab`.
//!    3. blake3 of sorted `STB_GLOBAL` symbol names defined in the `.o`.
//!
//! TUs are matched across scenarios by `(crate_name, STT_FILE)` — the
//! working hypothesis being that STT_FILE is the reliable anchor — then
//! the other candidates are checked for agreement on the same matches.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use object::read::archive::ArchiveFile;
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

const PROBE_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[derive(Clone, Debug)]
enum Edit {
    None,
    /// Append `pub fn noop_<tag>() {}` to `<crate>/src/lib.rs`.
    AppendNoop { krate: &'static str, tag: &'static str },
    /// Change `a_one` body in `crate_a`: `*3 + 7` → `*5 + 7`.
    TweakABody,
}

#[derive(Clone, Debug)]
struct Scenario {
    name: &'static str,
    edit: Edit,
    rustflags: &'static [&'static str],
}

const SCENARIOS: &[Scenario] = &[
    Scenario { name: "baseline_1",    edit: Edit::None,                                         rustflags: &[] },
    Scenario { name: "baseline_2",    edit: Edit::None,                                         rustflags: &[] },
    Scenario { name: "noop_b",        edit: Edit::AppendNoop { krate: "crate_b", tag: "nb" },   rustflags: &[] },
    Scenario { name: "noop_a",        edit: Edit::AppendNoop { krate: "crate_a", tag: "na" },   rustflags: &[] },
    Scenario { name: "tweak_a_body",  edit: Edit::TweakABody,                                   rustflags: &[] },
    Scenario { name: "cgu1_baseline", edit: Edit::None,                                         rustflags: &["-Ccodegen-units=1"] },
    Scenario { name: "cgu1_noop_b",   edit: Edit::AppendNoop { krate: "crate_b", tag: "nb" },   rustflags: &["-Ccodegen-units=1"] },
];

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ObjectInfo {
    krate: String,
    rlib: String,
    member: String,
    /// Member name with work-product-hash-like segments collapsed to `#`. Candidate 1.
    stripped_member: String,
    bytes_hash: String,
    /// First STT_FILE symbol in the `.o`'s symtab (rustc conventionally emits one). Candidate 2.
    stt_file: Option<String>,
    /// Sorted STB_GLOBAL symbol names defined in the object.
    globals: Vec<String>,
    /// blake3 of `globals`, as hex. Candidate 3.
    globals_hash: String,
    sections: BTreeMap<String, SectionInfo>,
    llvm_hash_suffixes: Vec<String>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct SectionInfo {
    size: u64,
    bytes_hash: Option<String>,
}

fn main() -> Result<()> {
    let fixture_src = PathBuf::from(PROBE_DIR).join("fixture");
    if !fixture_src.join("Cargo.toml").is_file() {
        bail!("fixture not found at {}", fixture_src.display());
    }

    let root = std::env::temp_dir().join(format!("graft-probe-{}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root).ok();
    }
    fs::create_dir_all(&root)?;
    eprintln!("probe work root: {}", root.display());

    let mut snapshots: BTreeMap<String, Snapshot> = BTreeMap::new();
    for s in SCENARIOS {
        eprintln!("--- scenario: {}", s.name);
        let workdir = root.join(s.name);
        copy_tree(&fixture_src, &workdir).with_context(|| format!("copy fixture to {}", workdir.display()))?;
        apply_edit(&workdir, &s.edit)?;
        run_cargo_build(&workdir, s.rustflags)?;
        let snap = snapshot(&workdir).with_context(|| format!("snapshot {}", workdir.display()))?;
        eprintln!("  {} object files", snap.objects.len());
        snapshots.insert(s.name.to_string(), snap);
    }

    eprintln!();
    report(&snapshots);
    Ok(())
}

#[derive(Debug)]
struct Snapshot {
    objects: Vec<ObjectInfo>,
}

impl Snapshot {
    /// Match-index TUs by `(crate_name, stt_file)`. Duplicates within a
    /// scenario fold into a `Vec` so we can see them.
    fn by_tu_anchor(&self) -> BTreeMap<(String, String), Vec<&ObjectInfo>> {
        let mut out: BTreeMap<(String, String), Vec<&ObjectInfo>> = BTreeMap::new();
        for o in &self.objects {
            let key = (o.krate.clone(), o.stt_file.clone().unwrap_or_else(|| "-no-stt-file-".into()));
            out.entry(key).or_default().push(o);
        }
        out
    }
}

// ---------------- fixture handling ----------------

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_tree(&from, &to)?;
        } else if ft.is_file() {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn apply_edit(workdir: &Path, edit: &Edit) -> Result<()> {
    match edit {
        Edit::None => Ok(()),
        Edit::AppendNoop { krate, tag } => {
            let path = workdir.join(krate).join("src/lib.rs");
            let mut text = fs::read_to_string(&path)?;
            text.push_str(&format!("\npub fn noop_{tag}() {{}}\n"));
            fs::write(&path, text)?;
            Ok(())
        }
        Edit::TweakABody => {
            let path = workdir.join("crate_a/src/lib.rs");
            let text = fs::read_to_string(&path)?;
            let tweaked = text.replace("wrapping_mul(3)", "wrapping_mul(5)");
            if tweaked == text {
                bail!("TweakABody: expected `wrapping_mul(3)` in crate_a/src/lib.rs");
            }
            fs::write(&path, tweaked)?;
            Ok(())
        }
    }
}

fn run_cargo_build(workdir: &Path, rustflags: &[&str]) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--quiet").current_dir(workdir);
    if !rustflags.is_empty() {
        cmd.env("RUSTFLAGS", rustflags.join(" "));
    }
    cmd.env("CARGO_TARGET_DIR", workdir.join("target"));
    let status = cmd.status().context("run `cargo build`")?;
    if !status.success() {
        bail!("cargo build failed in {} (status {})", workdir.display(), status);
    }
    Ok(())
}

// ---------------- snapshot ----------------

fn snapshot(workdir: &Path) -> Result<Snapshot> {
    let deps = workdir.join("target/debug/deps");
    let mut objects = Vec::new();
    for entry in fs::read_dir(&deps).with_context(|| format!("read deps dir {}", deps.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("rlib") {
            scan_rlib(&path, &mut objects)?;
        }
    }
    Ok(Snapshot { objects })
}

fn scan_rlib(path: &Path, out: &mut Vec<ObjectInfo>) -> Result<()> {
    let bytes = fs::read(path)?;
    let archive = ArchiveFile::parse(&*bytes).with_context(|| format!("parse archive {}", path.display()))?;
    let rlib_name = path.file_name().unwrap().to_string_lossy().into_owned();
    let krate = rlib_crate_name(&rlib_name);
    // Our fixture workspace crates only; ignore rustc sysroot deps.
    if !["crate_a", "crate_b", "app"].contains(&krate.as_str()) {
        return Ok(());
    }
    for member in archive.members() {
        let member = member.map_err(|e| anyhow::anyhow!("archive member: {e}"))?;
        let name = String::from_utf8_lossy(member.name()).into_owned();
        if !name.ends_with(".o") && !name.ends_with(".rcgu.o") {
            continue;
        }
        let data = member.data(&*bytes).map_err(|e| anyhow::anyhow!("member data: {e}"))?;
        let info = describe_object(&krate, &rlib_name, &name, data)?;
        out.push(info);
    }
    Ok(())
}

/// `libcrate_a-321d08363f02f540.rlib` → `crate_a`.
fn rlib_crate_name(rlib: &str) -> String {
    let stem = rlib.strip_suffix(".rlib").unwrap_or(rlib);
    let stem = stem.strip_prefix("lib").unwrap_or(stem);
    match stem.rfind('-') {
        Some(i) => stem[..i].to_string(),
        None => stem.to_string(),
    }
}

fn describe_object(krate: &str, rlib: &str, member: &str, data: &[u8]) -> Result<ObjectInfo> {
    let bytes_hash = hex_hash(data);
    let obj = object::File::parse(data).with_context(|| format!("parse ELF {rlib}::{member}"))?;

    let mut stt_file = None;
    let mut globals = Vec::new();
    let mut llvm_hash_suffixes = BTreeSet::new();
    for sym in obj.symbols() {
        let name = sym.name().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        if matches!(sym.kind(), SymbolKind::File) && stt_file.is_none() {
            stt_file = Some(name.clone());
            continue;
        }
        if sym.is_global() && sym.is_definition() {
            globals.push(name.clone());
        }
        if let Some(idx) = name.find(".llvm.") {
            llvm_hash_suffixes.insert(name[idx..].to_string());
        }
    }
    globals.sort();
    globals.dedup();
    let globals_hash = hash_strs(&globals);

    let mut sections = BTreeMap::new();
    for sec in obj.sections() {
        let sname = sec.name().unwrap_or("?").to_string();
        let size = sec.size();
        let bytes_hash = sec.data().ok().filter(|d| !d.is_empty()).map(hex_hash);
        sections.insert(sname, SectionInfo { size, bytes_hash });
    }

    Ok(ObjectInfo {
        krate: krate.to_string(),
        rlib: rlib.to_string(),
        member: member.to_string(),
        stripped_member: strip_member_hashes(member),
        bytes_hash,
        stt_file,
        globals,
        globals_hash,
        sections,
        llvm_hash_suffixes: llvm_hash_suffixes.into_iter().collect(),
    })
}

/// Collapse dot-separated segments that look like drifting hashes.
/// A segment "looks drifting" if it's made entirely of `[0-9a-z]` and either:
///   - ≥16 chars and has a letter (crate hash / work-product hash), OR
///   - 5–14 chars and has a letter (work-product suffix),
///
/// *But* we preserve segments of length ≥20 containing letters — those are the
/// stable CGU-name hashes (24 chars of base36 in rustc 1.94).
///
/// Used as candidate 1. This is necessarily heuristic; the probe checks
/// whether it agrees with candidate 2 on matched TUs.
fn strip_member_hashes(name: &str) -> String {
    name.split('.')
        .map(|seg| {
            let len = seg.len();
            let is_b36 = !seg.is_empty()
                && seg.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'z').contains(&b));
            let has_letter = seg.bytes().any(|b| b.is_ascii_alphabetic());
            let looks_drifting = is_b36 && has_letter && (
                (len >= 16 && len < 20) || (len >= 5 && len <= 14 && len < 16)
            );
            // Also treat 16-char hex (crate hash) as drifting even though it'd otherwise be "stable":
            let is_crate_hash = len == 16 && seg.bytes().all(|b| b.is_ascii_hexdigit());
            if looks_drifting || is_crate_hash {
                "#".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn hex_hash(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    encode_hex16(h.as_bytes())
}

fn hash_strs(strs: &[String]) -> String {
    let mut h = blake3::Hasher::new();
    for s in strs {
        h.update(s.as_bytes());
        h.update(b"\0");
    }
    encode_hex16(h.finalize().as_bytes())
}

fn encode_hex16(bytes: &[u8]) -> String {
    let n = bytes.len().min(16);
    let mut s = String::with_capacity(n * 2);
    for b in &bytes[..n] {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0xF));
    }
    s
}

fn nibble(n: u8) -> char {
    if n < 10 { (b'0' + n) as char } else { (b'a' + n - 10) as char }
}

// ---------------- report ----------------

fn report(snapshots: &BTreeMap<String, Snapshot>) {
    println!("===== M0.25 PROBE REPORT =====\n");
    q1_determinism(snapshots);
    q2_isolation(snapshots);
    q3_tu_candidates(snapshots);
    supplementary(snapshots);
}

fn q1_determinism(snaps: &BTreeMap<String, Snapshot>) {
    println!("### Q1: Determinism (baseline_1 vs baseline_2)");
    println!("  a) whole-file byte identity (ELF headers + symtab + section bytes):");
    compare_byte_identity(snaps, "baseline_1", "baseline_2", None);
    println!("  b) per-section byte identity on matched TUs (is codegen itself stable?):");
    compare_section_identity(snaps, "baseline_1", "baseline_2", None);
    println!();
}

fn q2_isolation(snaps: &BTreeMap<String, Snapshot>) {
    println!("### Q2: Unrelated-edit isolation (per-section check)");
    println!("  Whole-file bytes can drift on metadata alone. The real test is whether");
    println!("  section content of TUs outside the edit stays identical.\n");
    let cases: &[(&str, &str, &str)] = &[
        ("baseline_1", "noop_b", "crate_a"),
        ("baseline_1", "noop_a", "crate_b"),
        ("baseline_1", "tweak_a_body", "crate_b"),
        ("baseline_1", "noop_a", "crate_a"),       // same-crate baseline — expect diff
        ("baseline_1", "tweak_a_body", "crate_a"), // same-crate baseline — expect diff
    ];
    for (a, b, krate) in cases {
        compare_section_identity(snaps, a, b, Some(krate));
    }
    println!();
}

/// Compare section content on matched TUs. We focus on `SHF_ALLOC` sections
/// (`.text*`, `.rodata*`, `.data*`, `.bss*`) because those are what ends up
/// in the final binary and what graft's `trans_hash` covers; ELF headers,
/// `.symtab`/`.strtab`, debug sections, and relocation sections can drift
/// without affecting actual program behavior. Per-section diff report
/// shows which sections differ.
fn compare_section_identity(
    snaps: &BTreeMap<String, Snapshot>,
    a_name: &str,
    b_name: &str,
    only_crate: Option<&str>,
) {
    let (Some(a), Some(b)) = (snaps.get(a_name), snaps.get(b_name)) else {
        println!("  (missing {a_name} or {b_name})");
        return;
    };
    let a_tus = a.by_tu_anchor();
    let b_tus = b.by_tu_anchor();
    let mut keys: BTreeSet<_> = a_tus.keys().chain(b_tus.keys()).collect();
    if let Some(k) = only_crate { keys.retain(|(kr, _)| kr == k); }

    let mut matched = 0;
    let mut alloc_identical = 0;
    let mut details: Vec<String> = Vec::new();

    for key @ (krate, stt) in &keys {
        let (Some(av), Some(bv)) = (a_tus.get(*key), b_tus.get(*key)) else { continue };
        matched += 1;
        let ao = av[0];
        let bo = bv[0];
        let alloc_sections: BTreeSet<&str> = ao.sections.keys()
            .chain(bo.sections.keys())
            .map(String::as_str)
            .filter(|n| is_alloc_section(n))
            .collect();
        let mut section_diffs: Vec<String> = Vec::new();
        for sec in &alloc_sections {
            let ah = ao.sections.get(*sec).and_then(|s| s.bytes_hash.clone());
            let bh = bo.sections.get(*sec).and_then(|s| s.bytes_hash.clone());
            if ah != bh {
                section_diffs.push(format!(
                    "{sec}:{}≠{}",
                    ah.as_deref().map(short).unwrap_or("-"),
                    bh.as_deref().map(short).unwrap_or("-"),
                ));
            }
        }
        if section_diffs.is_empty() {
            alloc_identical += 1;
        } else {
            details.push(format!("    {krate} stt={stt}  diffs: {}", section_diffs.join(", ")));
        }
    }

    let scope = only_crate.map(|k| format!(" [{k} only]")).unwrap_or_default();
    let ok = matched > 0 && alloc_identical == matched;
    let sym = if ok { "✓" } else { "·" };
    println!(
        "  {sym} {a_name} ↔ {b_name}{scope}: matched={matched} all-alloc-sections-match={alloc_identical}"
    );
    for line in details.iter().take(10) { println!("{line}"); }
    if details.len() > 10 { println!("    ... ({} more)", details.len() - 10); }
}

fn is_alloc_section(name: &str) -> bool {
    // SHF_ALLOC sections from rustc-emitted `.o`s — what we care about for graft's
    // trans_hash. This is a name-based heuristic; the flag would be more precise but
    // the name convention is stable.
    name.starts_with(".text")
        || name.starts_with(".rodata")
        || name.starts_with(".data")
        || name.starts_with(".bss")
        || name.starts_with(".tdata")
        || name.starts_with(".tbss")
}

fn compare_byte_identity(
    snaps: &BTreeMap<String, Snapshot>,
    a_name: &str,
    b_name: &str,
    only_crate: Option<&str>,
) {
    let (Some(a), Some(b)) = (snaps.get(a_name), snaps.get(b_name)) else {
        println!("  (missing {a_name} or {b_name})");
        return;
    };
    let a_tus = a.by_tu_anchor();
    let b_tus = b.by_tu_anchor();

    let mut keys: BTreeSet<_> = a_tus.keys().chain(b_tus.keys()).collect();
    if let Some(k) = only_crate {
        keys.retain(|(kr, _)| kr == k);
    }

    let mut matched = 0;
    let mut byte_identical = 0;
    let mut a_only = 0;
    let mut b_only = 0;
    let mut diffs: Vec<String> = Vec::new();

    for key @ (krate, stt) in &keys {
        let av = a_tus.get(*key);
        let bv = b_tus.get(*key);
        match (av, bv) {
            (Some(av), Some(bv)) => {
                matched += 1;
                let ah = &av[0].bytes_hash;
                let bh = &bv[0].bytes_hash;
                if ah == bh {
                    byte_identical += 1;
                } else {
                    diffs.push(format!("    {krate}  stt={stt}  {} ≠ {}", short(ah), short(bh)));
                }
            }
            (Some(_), None) => {
                a_only += 1;
                diffs.push(format!("    {krate}  stt={stt}  (A only)"));
            }
            (None, Some(_)) => {
                b_only += 1;
                diffs.push(format!("    {krate}  stt={stt}  (B only)"));
            }
            (None, None) => {}
        }
    }

    let scope = only_crate.map(|k| format!(" [{k} only]")).unwrap_or_default();
    let ok = matched > 0 && byte_identical == matched && a_only == 0 && b_only == 0;
    let sym = if ok { "✓" } else { "·" };
    println!(
        "  {sym} {a_name} ↔ {b_name}{scope}: matched={matched} byte-identical={byte_identical} A-only={a_only} B-only={b_only}"
    );
    for line in diffs.iter().take(10) {
        println!("{line}");
    }
    if diffs.len() > 10 {
        println!("    ... ({} more)", diffs.len() - 10);
    }
}

fn q3_tu_candidates(snaps: &BTreeMap<String, Snapshot>) {
    println!("### Q3: tu_id candidate stability");
    println!("  TUs are matched across scenarios by (crate_name, STT_FILE). For each");
    println!("  matched TU, we check whether candidates 1 (stripped filename) and 3");
    println!("  (globals-hash) agree on both sides.\n");

    let pairs: &[(&str, &str, &str)] = &[
        ("baseline_1", "baseline_2", "pristine re-run"),
        ("baseline_1", "noop_b", "unrelated-crate noop"),
        ("baseline_1", "noop_a", "same-crate noop (adds a global)"),
        ("baseline_1", "tweak_a_body", "in-TU body edit"),
        ("baseline_1", "cgu1_baseline", "cgu count change"),
        ("cgu1_baseline", "cgu1_noop_b", "cgu=1, unrelated-crate noop"),
    ];
    for (a_name, b_name, label) in pairs {
        let (Some(a), Some(b)) = (snaps.get(*a_name), snaps.get(*b_name)) else { continue };
        let a_tus = a.by_tu_anchor();
        let b_tus = b.by_tu_anchor();
        let mut matched = 0;
        let mut cand1_agree = 0;
        let mut cand3_agree = 0;
        let mut a_only_tus = 0;
        let mut b_only_tus = 0;
        let keys: BTreeSet<_> = a_tus.keys().chain(b_tus.keys()).collect();
        for key in &keys {
            match (a_tus.get(*key), b_tus.get(*key)) {
                (Some(av), Some(bv)) => {
                    matched += 1;
                    if av[0].stripped_member == bv[0].stripped_member { cand1_agree += 1; }
                    if av[0].globals_hash == bv[0].globals_hash { cand3_agree += 1; }
                }
                (Some(_), None) => { a_only_tus += 1; }
                (None, Some(_)) => { b_only_tus += 1; }
                (None, None) => {}
            }
        }
        println!("  {a_name} ↔ {b_name}  ({label})");
        println!("    matched={matched}  A-only={a_only_tus}  B-only={b_only_tus}  (candidate 2 matches by construction)");
        println!("    of matched: candidate 1 (stripped filename) agrees {}×", cand1_agree);
        println!("    of matched: candidate 3 (globals-hash)      agrees {}×", cand3_agree);
    }
    println!();
}

fn supplementary(snaps: &BTreeMap<String, Snapshot>) {
    println!("### Supplementary: .llvm.<hash> suffixes");
    let mut any = BTreeSet::new();
    for snap in snaps.values() {
        for o in &snap.objects {
            for s in &o.llvm_hash_suffixes { any.insert(s.clone()); }
        }
    }
    println!("  {} distinct suffix values across all scenarios", any.len());
    for s in any.iter().take(10) { println!("    {s}"); }
    println!();

    println!("### Supplementary: baseline_1 object inventory");
    if let Some(s) = snaps.get("baseline_1") {
        let mut rows: Vec<_> = s.objects.iter().collect();
        rows.sort_by_key(|o| (&o.krate, &o.member));
        for o in rows {
            println!("  [{}] {}", o.krate, o.member);
            println!("      stripped: {}", o.stripped_member);
            println!("      stt_file: {:?}", o.stt_file);
            println!(
                "      bytes={}  globals={}  globals_hash={}  sections={}",
                short(&o.bytes_hash), o.globals.len(), short(&o.globals_hash), o.sections.len()
            );
        }
    }
    println!();

    println!("### Supplementary: CGU filename format across scenarios");
    println!("  (Stable segments shared across baseline_1 / baseline_2 indicate candidate 1 viability.)");
    let cols = ["baseline_1", "baseline_2", "noop_b", "tweak_a_body", "cgu1_baseline"];
    for name in cols {
        if let Some(s) = snaps.get(name) {
            println!("  --- {name} ---");
            for o in s.objects.iter().take(8) {
                println!("    [{}] {}", o.krate, o.member);
            }
        }
    }
}

fn short(h: &str) -> &str { &h[..h.len().min(12)] }
