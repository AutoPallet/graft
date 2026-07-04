//! Identical-code folding for the base link (`GRAFT_ICF=1`, default off).
//!
//! GNU ld has no ICF, and on xtensa-espidf rustc emits cross-crate
//! monomorphization copies as internalized LOCAL symbols with no COMDAT
//! groups and no weak symbols — so nothing in the toolchain ever folds
//! them (measured on roborack: 1.23 MB of exec bytes = 22.5% of the
//! image; see `graft dup-stats`). graft's `trans_hash` is a sound fold
//! criterion: equality means the sections' bytes, canonicalized relocs,
//! and entire successor subgraphs are identical — strictly stronger
//! than gold/lld's iterative equivalence refinement.
//!
//! Mechanism — vague linkage by *symmetric weak aliasing*, the classic
//! pre-COMDAT trick. In EVERY copy's object:
//!   1. define `__graft_icf_<trans_hash>` as a WEAK+HIDDEN symbol at
//!      offset 0 of that object's own copy of the section;
//!   2. retarget all relocations (in SHF_ALLOC sections) that point
//!      into the copy to that name (addend += old target's st_value).
//! At link time ld resolves the weak name to the first loaded
//! definition; every other copy loses its last reference and
//! `--gc-sections` collects it — which also makes ld itself prune the
//! matching `.eh_frame` FDEs and xtensa `.xt.prop`/`.xt.lit` entries,
//! exactly as it does for any dead section. That is why relocs *from*
//! `.eh_frame` / `.xt.*` / debug sections are deliberately NOT
//! retargeted: they must keep pointing at their own (possibly dying)
//! copy so ld's own gc bookkeeping fires. ICF refuses to run without
//! `--gc-sections` in the link argv.
//!
//! Why symmetric-weak instead of one keeper + UND references: GNU ld
//! scans each archive ONCE, at its argv position. A keeper scheme
//! makes a member in an earlier archive satisfy a reference that only
//! materializes when a later archive's member loads — ld never
//! revisits, and the link dies with "hidden symbol isn't defined"
//! (observed on roborack). With a weak definition in the same object
//! as every reference, no cross-object undef ever exists: archive
//! member selection is bit-identical to the unfolded link, any loaded
//! subset of copies self-resolves, and the winner is simply the first
//! in link order (all copies are byte-identical, so any winner is
//! correct).
//!
//! Safety criteria (v1 — deliberately at least as conservative as
//! gold's `--icf=safe` for the cases we fold):
//! - **Rust rcgu objects only.** Rust explicitly permits merging
//!   identical functions (fn addresses are not guaranteed unique), so
//!   gold's address-taken analysis is not required for soundness. C
//!   objects are never touched: C callers may compare function
//!   pointers (ESP-IDF's event-handler unregistration does), and a
//!   fold there could alias semantically distinct callbacks.
//! - **Executable, non-writable sections only.** No rodata folding
//!   (`ptr::eq` on distinct statics could observe it), no `.rwtext`
//!   (RAM-resident code has region semantics), no TLS/MERGE/GROUP.
//! Sections defining GLOBAL symbols fold too (most duplicated
//! monomorphs are GLOBAL+HIDDEN under distinct crate-suffixed v0
//! names): every participating copy DEMOTES its own global defs to
//! WEAK in place and gains WEAK aliases for every other participant's
//! names at the matching offsets (sections are byte-identical, so
//! offsets transfer). All names then bind to the first-loaded
//! participant and the rest gc away. External strong refs stay
//! correct in every load order because BFD ld extracts an archive
//! member to satisfy a strong undef against a *weak* definition
//! (verified empirically on x86 and xtensa esp-12.2 binutils), and an
//! already-loaded weak def short-circuits the search. Alias count is
//! quadratic in group size, so groups larger than
//! [`MAX_PARTICIPANTS`] are split into independent chunks of at most
//! that many copies. Each chunk folds under its own weak name
//! (`__graft_icf_<th>` for the first, `__graft_icf_<th>_c<n>` after)
//! so weak resolution never crosses chunks — one survivor per chunk,
//! full alias coverage within it. A trailing single-copy chunk is
//! left untouched (correct, just unfolded).
//! - **Identical section-name *class* across the group** — the name
//!   prefix before the per-function mangled tail (`.llvm.<id>`
//!   internalization suffixes stripped). Linker scripts scoop input
//!   sections by wildcard over exactly this prefix, so equal class ⇒
//!   same output-section rule ⇒ same memory region. `.text.X` never
//!   folds with `.text.unlikely.Y` (hot/cold split preserved), and
//!   `.iram1.*` / `.rtc.text.*` placement-attributed code never
//!   enters a group at all (the `.text.` filter above).
//! - Mutable/NOBITS content can never enter a group: the nominal salt
//!   in `hash::compute` keeps distinct mutable variables' hashes
//!   distinct (see CLAUDE.md, M2).
//!
//! Most groups are *distinct* instantiations (different generic args,
//! or the same generic instantiated by different crates — the v0
//! mangled names embed the instantiating crate) whose machine code
//! compiled identically. Folding those is sound for Rust: fn addresses
//! are documented as non-unique (rustc/LLVM already merge identical
//! functions via mergefunc and MSVC `/OPT:ICF` folds Rust routinely),
//! and state aliasing is impossible because trans_hash equality forces
//! the entire reachable subgraph — including every referenced static's
//! *salted, name-keyed* identity — to be identical: two functions
//! touching distinguishable mutable state can never share a hash.
//!
//! Overlay interaction: overlays scan the ORIGINAL inputs and resolve
//! positionally by trans_hash, so a reference to any copy anchors at
//! the keeper's address (all copies share the hash). The base table's
//! `ambiguous` set shrinks accordingly — folding *strengthens* overlay
//! resolution.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::scan::ScanResult;

pub const ENV: &str = "GRAFT_ICF";

/// Parse `GRAFT_ICF`. Unset/empty → off. `1`/`on`/`rust` → on. Anything
/// else is a hard error — never a silent fallthrough (same policy as
/// the `GRAFT` mode variable).
pub fn enabled() -> Result<bool> {
    match std::env::var(ENV) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(e) => Err(anyhow!("{ENV}: {e}")),
        Ok(v) => match v.as_str() {
            "" => Ok(false),
            "1" | "on" | "rust" => Ok(true),
            other => bail!(
                "{ENV}={other:?} is not a recognized mode (expected `1`, `on`, or \
                 `rust`). Refusing to guess."
            ),
        },
    }
}

#[derive(Debug, Default)]
pub struct IcfStats {
    pub groups_folded: usize,
    pub copies_dropped: usize,
    /// Input bytes of the dropped copies — the upper bound on image
    /// shrink (actual shrink is post-relaxation).
    pub bytes_dropped: u64,
    pub rewritten_objects: usize,
    pub rewritten_archives: usize,
    /// Groups skipped because a copy's section defines a WEAK symbol
    /// (already vague linkage — refuse to stack schemes on it).
    pub skipped_weak_def: usize,
    /// Groups skipped because copies' section-name classes differ
    /// (would cross linker-script scooping rules).
    pub skipped_name_mismatch: usize,
    /// Groups skipped for mechanical reasons (section index beyond
    /// SHN_LORESERVE, REL-format relocs, unsupported ELF shape).
    pub skipped_mechanical: usize,
    /// Groups larger than MAX_PARTICIPANTS, folded as multiple
    /// independent chunks (one survivor per chunk instead of one
    /// per group).
    pub groups_chunked: usize,
}

/// Cross-alias count is quadratic in participants; larger groups are
/// split into chunks of this size. 16 keeps the worst symtab/strtab
/// growth per chunk in the tens of KB while covering the bulk of the
/// waste (group-size distribution is heavily skewed toward small
/// groups).
pub const MAX_PARTICIPANTS: usize = 16;

pub struct IcfOutcome {
    pub stats: IcfStats,
    /// original canonical input path → rewritten replacement path.
    /// base mode substitutes matching argv tokens before running ld.
    pub replacements: HashMap<PathBuf, PathBuf>,
    /// `<output>.graft-icf/` — the rewritten-input scratch dir. base
    /// mode deletes it after a successful link (kept on failure, or
    /// when `GRAFT_ICF_KEEP=1`).
    pub work_dir: PathBuf,
}

/// One planned edit to one on-disk input file (loose `.o` or archive
/// member).
#[derive(Debug, Default, Clone)]
struct ObjectPlan {
    /// 0-based section index → weak name replacing refs into it.
    redirects: HashMap<u32, String>,
    /// New WEAK+HIDDEN definitions: (name, 0-based section index,
    /// st_value, st_size).
    adds: Vec<(String, u32, u64, u64)>,
    /// Existing GLOBAL definitions to demote to WEAK in place:
    /// (0-based section index, symbol name).
    weaken: Vec<(u32, String)>,
    /// sh_addralign floor per 0-based section index.
    align_bumps: Vec<(u32, u64)>,
}

/// Compute fold groups from the scan and rewrite the affected inputs
/// into `<output>.graft-icf/`. Returns `None` when nothing folds.
pub fn run(scan: &ScanResult, output: &Path) -> Result<Option<IcfOutcome>> {
    use object::elf::{SHF_ALLOC, SHF_EXECINSTR, SHF_GROUP, SHF_MERGE, SHF_TLS, SHF_WRITE};

    let mut stats = IcfStats::default();

    // ---- group formation ------------------------------------------------
    // th → copies as (input idx, section0). Eligibility mirrors the
    // module-doc criteria; identity-level dedup guards against the same
    // archive appearing twice in argv.
    let mut groups: HashMap<[u8; 16], Vec<(usize, u32)>> = HashMap::new();
    let mut seen_identity: HashSet<(PathBuf, Option<String>, u32)> = HashSet::new();
    for (nid, nm) in scan.graph.nodes.iter().enumerate() {
        if nm.is_aggregator() {
            continue;
        }
        let [seg] = nm.segments.as_slice() else { continue };
        if seg.range.is_some() {
            continue;
        }
        let input = &scan.inputs[seg.object as usize];
        let is_rcgu = match &input.member_name {
            Some(m) => m.ends_with(".rcgu.o"),
            None => input
                .source_path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.ends_with(".rcgu.o")),
        };
        if !is_rcgu {
            continue;
        }
        let sec = &scan.objects[seg.object as usize].sections[seg.section as usize];
        let flags = sec.sh_flags;
        let want = u64::from(SHF_ALLOC | SHF_EXECINSTR);
        let veto = u64::from(SHF_WRITE | SHF_TLS | SHF_MERGE | SHF_GROUP);
        if flags & want != want || flags & veto != 0 {
            continue;
        }
        if sec.bytes.is_empty() || !sec.name.starts_with(".text.") {
            continue;
        }
        // ELF32 st_shndx is u16 with SHN_LORESERVE at 0xff00; the +1
        // header index of both keeper and dropped sections must encode.
        if seg.section + 1 >= 0xff00 {
            continue;
        }
        let identity = (
            std::fs::canonicalize(&input.source_path)
                .unwrap_or_else(|_| input.source_path.clone()),
            input.member_name.clone(),
            seg.section,
        );
        if !seen_identity.insert(identity) {
            continue; // same file listed twice in argv
        }
        groups
            .entry(scan.trans_hash[nid])
            .or_default()
            .push((seg.object as usize, seg.section));
    }

    // ---- eligibility filters + plan construction ------------------------
    // Keyed by (canonical source path, member name) — the on-disk unit
    // we rewrite.
    let mut plans: HashMap<(PathBuf, Option<String>), ObjectPlan> = HashMap::new();
    let mut group_list: Vec<([u8; 16], Vec<(usize, u32)>)> = groups
        .into_iter()
        .filter(|(_, v)| v.len() >= 2)
        .collect();
    group_list.sort_by_key(|(th, _)| *th); // deterministic output
    for (th, mut copies) in group_list {
        copies.sort();
        let class0 = name_class(&scan.objects[copies[0].0].sections[copies[0].1 as usize].name);
        if copies
            .iter()
            .any(|&(o, s)| name_class(&scan.objects[o].sections[s as usize].name) != class0)
        {
            stats.skipped_name_mismatch += 1;
            continue;
        }
        // Per-copy global definitions in the section. WEAK defs mean
        // some other vague-linkage scheme is already in play — refuse.
        // st_value/st_size beyond the section is malformed — refuse.
        let mut copy_globals: Vec<Vec<(String, u64, u64)>> = Vec::with_capacity(copies.len());
        let mut weird = false;
        for &(o, s) in &copies {
            let sec_size = scan.objects[o].sections[s as usize].sh_size;
            let mut globals = Vec::new();
            for sym in &scan.objects[o].symbols {
                if sym.defining_section != Some(s as usize) {
                    continue;
                }
                match sym.bind {
                    crate::elf::SymbolBind::Local => {}
                    crate::elf::SymbolBind::Global => {
                        if sym.name.is_empty() || sym.value.saturating_add(sym.size) > sec_size {
                            weird = true;
                        }
                        globals.push((sym.name.clone(), sym.value, sym.size));
                    }
                    crate::elf::SymbolBind::Weak => weird = true,
                }
            }
            globals.sort();
            copy_globals.push(globals);
        }
        if weird {
            stats.skipped_weak_def += 1;
            continue;
        }

        if copies.len() > MAX_PARTICIPANTS {
            stats.groups_chunked += 1;
        }
        let hex: String = th.iter().map(|b| format!("{b:02x}")).collect();
        // Oversized groups fold as independent ≤MAX_PARTICIPANTS
        // chunks, each under its own weak name so resolution never
        // crosses chunk boundaries: one survivor per chunk, and every
        // chunk member carries aliases for all of its chunk-mates'
        // names. A trailing single-copy chunk has nothing to fold
        // against and is left untouched.
        for (chunk_idx, (chunk, chunk_globals)) in copies
            .chunks(MAX_PARTICIPANTS)
            .zip(copy_globals.chunks(MAX_PARTICIPANTS))
            .enumerate()
        {
            if chunk.len() < 2 {
                continue;
            }
            let icf_name = if chunk_idx == 0 {
                format!("__graft_icf_{hex}")
            } else {
                format!("__graft_icf_{hex}_c{chunk_idx}")
            };
            // Any chunk member can win the weak resolution, so every
            // member's alignment must satisfy the chunk's strictest
            // requirement.
            let mut max_align = 0u64;
            for &(o, s) in chunk {
                let inp = &scan.inputs[o];
                max_align = max_align.max(
                    surgery::section_addralign(&inp.bytes, s).unwrap_or(0),
                );
            }
            // Symmetric: every participant defines the weak chunk name
            // at its own copy, redirects its own references through
            // it, demotes its own global defs to WEAK, and carries
            // WEAK aliases for every other chunk member's global
            // names.
            for (ci, &(o, s)) in chunk.iter().enumerate() {
                let inp = &scan.inputs[o];
                let key = (
                    std::fs::canonicalize(&inp.source_path)
                        .unwrap_or_else(|_| inp.source_path.clone()),
                    inp.member_name.clone(),
                );
                let plan = plans.entry(key).or_default();
                plan.adds.push((icf_name.clone(), s, 0, scan.objects[o].sections[s as usize].sh_size));
                plan.align_bumps.push((s, max_align));
                plan.redirects.insert(s, icf_name.clone());
                for (cj, globals) in chunk_globals.iter().enumerate() {
                    if cj == ci {
                        for (name, _, _) in globals {
                            plan.weaken.push((s, name.clone()));
                        }
                    } else {
                        for (name, value, size) in globals {
                            plan.adds.push((name.clone(), s, *value, *size));
                        }
                    }
                }
            }
            stats.copies_dropped += chunk.len() - 1;
            stats.bytes_dropped += chunk[1..]
                .iter()
                .map(|&(o, s)| scan.objects[o].sections[s as usize].sh_size)
                .sum::<u64>();
        }
        stats.groups_folded += 1;
    }

    if plans.is_empty() {
        return Ok(None);
    }

    // ---- rewrite objects -------------------------------------------------
    // One representative input per (path, member): find its bytes.
    let mut input_bytes: HashMap<(PathBuf, Option<String>), &[u8]> = HashMap::new();
    for inp in &scan.inputs {
        let key = (
            std::fs::canonicalize(&inp.source_path)
                .unwrap_or_else(|_| inp.source_path.clone()),
            inp.member_name.clone(),
        );
        input_bytes.entry(key).or_insert(&inp.bytes);
    }

    use rayon::prelude::*;
    let plan_list: Vec<((PathBuf, Option<String>), ObjectPlan)> =
        plans.into_iter().collect();
    let rewritten: Vec<((PathBuf, Option<String>), Vec<u8>)> = plan_list
        .par_iter()
        .map(|(key, plan)| {
            let bytes = input_bytes
                .get(key)
                .ok_or_else(|| anyhow!("no scan bytes for {:?}", key))?;
            let out = surgery::rewrite_object(bytes, plan).with_context(|| {
                format!("rewrite {}::{}", key.0.display(), key.1.as_deref().unwrap_or("-"))
            })?;
            Ok((key.clone(), out))
        })
        .collect::<Result<_>>()?;
    stats.rewritten_objects = rewritten.len();

    // ---- write replacements ----------------------------------------------
    let work_dir = {
        let mut p = output.as_os_str().to_os_string();
        p.push(".graft-icf");
        PathBuf::from(p)
    };
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("create {}", work_dir.display()))?;

    // Loose objects: write directly. Archive members: batch per archive.
    // The symbol index needs no new entries — the weak defs are only
    // ever referenced from their own object — but member offsets shift,
    // so the index is still remapped by rebuild_archive.
    let mut per_archive: HashMap<PathBuf, HashMap<String, Vec<u8>>> = HashMap::new();
    let mut replacements: HashMap<PathBuf, PathBuf> = HashMap::new();
    for ((path, member), bytes) in rewritten {
        match member {
            None => {
                let file_name = path
                    .file_name()
                    .ok_or_else(|| anyhow!("input path has no file name: {}", path.display()))?;
                let dest = work_dir.join(file_name);
                std::fs::write(&dest, &bytes)
                    .with_context(|| format!("write {}", dest.display()))?;
                replacements.insert(path, dest);
            }
            Some(m) => {
                per_archive.entry(path).or_default().insert(m, bytes);
            }
        }
    }
    let archive_jobs: Vec<(PathBuf, HashMap<String, Vec<u8>>)> =
        per_archive.into_iter().collect();
    let rebuilt: Vec<(PathBuf, PathBuf)> = archive_jobs
        .par_iter()
        .map(|(path, members)| {
            let orig = std::fs::read(path)
                .with_context(|| format!("read archive {}", path.display()))?;
            let out = surgery::rebuild_archive(&orig, members, &[])
                .with_context(|| format!("rebuild archive {}", path.display()))?;
            let file_name = path
                .file_name()
                .ok_or_else(|| anyhow!("archive path has no file name: {}", path.display()))?;
            let dest = work_dir.join(file_name);
            std::fs::write(&dest, &out)
                .with_context(|| format!("write {}", dest.display()))?;
            Ok((path.clone(), dest))
        })
        .collect::<Result<_>>()?;
    stats.rewritten_archives = rebuilt.len();
    replacements.extend(rebuilt);

    Ok(Some(IcfOutcome { stats, replacements, work_dir }))
}

/// The linker-script scooping class of an input section name: the
/// prefix before the final (mangled-symbol) component, with LLVM
/// internalization suffixes stripped first. `.text._RNvfoo` and
/// `.text._RNvbar.llvm.123` are both class `.text`;
/// `.text.unlikely._RNvfoo` is class `.text.unlikely`. Mangled Rust
/// names (v0 and legacy) contain no `.`, so the final component is
/// exactly the symbol part.
fn name_class(name: &str) -> &str {
    let mut base = name;
    // `.llvm.<id>` — <id> is hex digits; strip iteratively is not
    // needed (LLVM appends at most one).
    if let Some(pos) = base.rfind(".llvm.")
        && base[pos + 6..].bytes().all(|b| b.is_ascii_hexdigit())
        && pos + 6 < base.len()
    {
        base = &base[..pos];
    }
    match base.rfind('.') {
        Some(p) if p > 0 => &base[..p],
        _ => base,
    }
}

/// Test-only surface for the archive rebuilder (integration tests live
/// outside the crate and can't reach `surgery`).
pub fn rebuild_archive_for_tests(
    orig: &[u8],
    replaced: &HashMap<String, Vec<u8>>,
    index_adds: &[(String, String)],
) -> Result<Vec<u8>> {
    surgery::rebuild_archive(orig, replaced, index_adds)
}

/// Substitute rewritten input paths into the link argv. Tokens are
/// matched by canonical path; non-path tokens pass through untouched.
pub fn substitute_argv(argv: Vec<String>, replacements: &HashMap<PathBuf, PathBuf>) -> Vec<String> {
    argv.into_iter()
        .map(|tok| {
            if tok.starts_with('-') {
                return tok;
            }
            let canon = std::fs::canonicalize(&tok).unwrap_or_else(|_| PathBuf::from(&tok));
            match replacements.get(&canon) {
                Some(new) => new.to_string_lossy().into_owned(),
                None => tok,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::name_class;

    #[test]
    fn name_class_strips_symbol_and_llvm_suffix() {
        assert_eq!(name_class(".text._RNvfoo"), ".text");
        assert_eq!(name_class(".text._ZN3foo17h0123456789abcdefE"), ".text");
        assert_eq!(name_class(".text.unlikely._RNvfoo"), ".text.unlikely");
        assert_eq!(name_class(".text._RNvfoo.llvm.12AB"), ".text");
        assert_eq!(name_class(".text.unlikely._RNvfoo.llvm.99"), ".text.unlikely");
        // Degenerate shapes must not panic or produce "".
        assert_eq!(name_class(".text"), ".text");
        // A non-hex "llvm" tail is part of the name, not a suffix.
        assert_eq!(name_class(".text.foo.llvm.xyz"), ".text.foo.llvm");
    }
}

/// Byte-level ELF and `ar` surgery. Reading goes through manual header
/// walks (both ELF32 and ELF64, little-endian only); edits are either
/// in-place field patches (relocation entries, sh_addralign) or
/// append-and-repoint (symtab/strtab grow by relocating to EOF —
/// section data may live anywhere, headers just point at it).
mod surgery {
    use super::*;

    const SHT_SYMTAB: u32 = 2;
    const SHT_RELA: u32 = 4;
    const SHT_REL: u32 = 9;
    const SHF_ALLOC: u64 = 0x2;

    struct Layout {
        is64: bool,
        shoff: usize,
        shentsize: usize,
        shnum: usize,
        shstrndx: usize,
    }

    fn u16le(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes([b[o], b[o + 1]])
    }
    fn u32le(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }
    fn u64le(b: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
    }

    fn layout(bytes: &[u8]) -> Result<Layout> {
        if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
            bail!("not an ELF object");
        }
        if bytes[5] != 1 {
            bail!("big-endian ELF unsupported");
        }
        let is64 = match bytes[4] {
            1 => false,
            2 => true,
            c => bail!("bad EI_CLASS {c}"),
        };
        let (shoff, shentsize_off, shnum_off, shstrndx_off) = if is64 {
            (u64le(bytes, 0x28) as usize, 0x3a, 0x3c, 0x3e)
        } else {
            (u32le(bytes, 0x20) as usize, 0x2e, 0x30, 0x32)
        };
        let shnum = u16le(bytes, shnum_off) as usize;
        if shnum == 0 {
            bail!("extended section counts (e_shnum=0) unsupported");
        }
        Ok(Layout {
            is64,
            shoff,
            shentsize: u16le(bytes, shentsize_off) as usize,
            shnum,
            shstrndx: u16le(bytes, shstrndx_off) as usize,
        })
    }

    struct Shdr {
        name_off: u32,
        sh_type: u32,
        flags: u64,
        offset: usize,
        size: usize,
        link: u32,
        info: u32,
        entsize: usize,
        /// File offset of this header entry (for in-place patches).
        hdr_pos: usize,
    }

    fn shdrs(bytes: &[u8], l: &Layout) -> Result<Vec<Shdr>> {
        let mut out = Vec::with_capacity(l.shnum);
        for i in 0..l.shnum {
            let p = l.shoff + i * l.shentsize;
            if p + l.shentsize > bytes.len() {
                bail!("section header {i} out of bounds");
            }
            let s = if l.is64 {
                Shdr {
                    name_off: u32le(bytes, p),
                    sh_type: u32le(bytes, p + 4),
                    flags: u64le(bytes, p + 8),
                    offset: u64le(bytes, p + 24) as usize,
                    size: u64le(bytes, p + 32) as usize,
                    link: u32le(bytes, p + 40),
                    info: u32le(bytes, p + 44),
                    entsize: u64le(bytes, p + 56) as usize,
                    hdr_pos: p,
                }
            } else {
                Shdr {
                    name_off: u32le(bytes, p),
                    sh_type: u32le(bytes, p + 4),
                    flags: u64::from(u32le(bytes, p + 8)),
                    offset: u32le(bytes, p + 16) as usize,
                    size: u32le(bytes, p + 20) as usize,
                    link: u32le(bytes, p + 24),
                    info: u32le(bytes, p + 28),
                    entsize: u32le(bytes, p + 36) as usize,
                    hdr_pos: p,
                }
            };
            out.push(s);
        }
        Ok(out)
    }

    fn section_name<'a>(bytes: &'a [u8], shstr: &Shdr, s: &Shdr) -> &'a str {
        let start = shstr.offset + s.name_off as usize;
        let end = bytes[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(start, |p| start + p);
        std::str::from_utf8(&bytes[start..end]).unwrap_or("")
    }

    /// sh_addralign of 0-based section `sec0` (header index sec0+1).
    pub(super) fn section_addralign(bytes: &[u8], sec0: u32) -> Result<u64> {
        let l = layout(bytes)?;
        let idx = sec0 as usize + 1;
        if idx >= l.shnum {
            bail!("section index {idx} out of range");
        }
        let p = l.shoff + idx * l.shentsize;
        Ok(if l.is64 {
            u64le(bytes, p + 48)
        } else {
            u64::from(u32le(bytes, p + 32))
        })
    }

    struct Sym {
        name_off: u32,
        value: u64,
        shndx: u16,
    }

    fn strtab_name<'a>(strtab: &'a [u8], off: u32) -> &'a [u8] {
        let start = off as usize;
        if start >= strtab.len() {
            return &[];
        }
        let end = strtab[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(strtab.len(), |p| start + p);
        &strtab[start..end]
    }

    pub(super) fn rewrite_object(bytes: &[u8], plan: &super::ObjectPlan) -> Result<Vec<u8>> {
        let l = layout(bytes)?;
        let headers = shdrs(bytes, &l)?;
        let shstr = headers
            .get(l.shstrndx)
            .ok_or_else(|| anyhow!("bad e_shstrndx"))?;

        let symtab_idx = headers
            .iter()
            .position(|s| s.sh_type == SHT_SYMTAB)
            .ok_or_else(|| anyhow!("no .symtab"))?;
        let symtab = &headers[symtab_idx];
        let strtab_idx = symtab.link as usize;
        let strtab = headers
            .get(strtab_idx)
            .ok_or_else(|| anyhow!("bad symtab sh_link"))?;
        let sym_entsize = if l.is64 { 24 } else { 16 };
        if symtab.entsize != sym_entsize {
            bail!("unexpected symtab entsize {}", symtab.entsize);
        }
        let sym_count = symtab.size / sym_entsize;
        let mut syms: Vec<Sym> = Vec::with_capacity(sym_count);
        for i in 0..sym_count {
            let p = symtab.offset + i * sym_entsize;
            let (name_off, value, shndx) = if l.is64 {
                (u32le(bytes, p), u64le(bytes, p + 8), u16le(bytes, p + 6))
            } else {
                (u32le(bytes, p), u64::from(u32le(bytes, p + 4)), u16le(bytes, p + 14))
            };
            syms.push(Sym { name_off, value, shndx });
        }
        let strtab_bytes = &bytes[strtab.offset..strtab.offset + strtab.size];

        // 1-based header index of each redirected section → UND name.
        let dropped: HashMap<u16, &String> = plan
            .redirects
            .iter()
            .map(|(&sec0, name)| ((sec0 + 1) as u16, name))
            .collect();

        // ---- pass 1: find relocations that need retargeting ----------
        // Collect (rela entry file offset, new symbol name, addend delta)
        // so UND symbols are only created for names actually referenced.
        let mut patches: Vec<(usize, String, i64)> = Vec::new();
        for rs in &headers {
            let is_rela = rs.sh_type == SHT_RELA;
            if !is_rela && rs.sh_type != SHT_REL {
                continue;
            }
            if rs.link as usize != symtab_idx {
                continue;
            }
            let applied_idx = rs.info as usize;
            let Some(applied) = headers.get(applied_idx) else { continue };
            if applied.flags & SHF_ALLOC == 0 {
                continue; // debug & friends: ld tombstones refs into gc'd sections
            }
            if dropped.contains_key(&(applied_idx as u16)) {
                continue; // the dying section's own relocs die with it
            }
            let aname = section_name(bytes, shstr, applied);
            if aname.starts_with(".eh_frame")
                || aname.starts_with(".xt.")
                || aname.starts_with(".gcc_except_table")
            {
                continue; // ld edits these tables itself when gc drops the section
            }
            let rela_entsize = if l.is64 {
                if is_rela { 24 } else { 16 }
            } else if is_rela {
                12
            } else {
                8
            };
            if rs.entsize != rela_entsize {
                bail!("unexpected reloc entsize {} in {aname}", rs.entsize);
            }
            let n = rs.size / rela_entsize;
            for i in 0..n {
                let p = rs.offset + i * rela_entsize;
                let sym_idx = if l.is64 {
                    (u64le(bytes, p + 8) >> 32) as usize
                } else {
                    (u32le(bytes, p + 4) >> 8) as usize
                };
                let Some(sym) = syms.get(sym_idx) else { continue };
                let Some(&name) = dropped.get(&sym.shndx) else { continue };
                if !is_rela {
                    // REL stores the addend in the field bytes; adjusting
                    // it means patching section data. Not needed on
                    // x86-64/xtensa — refuse rather than guess.
                    bail!("REL-format relocation into folded section in {aname}");
                }
                patches.push((p, name.clone(), sym.value as i64));
            }
        }

        // Weak definitions: one per group name, at offset 0 of this
        // object's own copy. Redirected relocs resolve through these —
        // within this object when it wins the weak resolution, or to
        // another object's identical copy when it loses.
        let mut adds_sorted = plan.adds.clone();
        adds_sorted.sort();
        let mut new_syms: Vec<(String, u8 /*info*/, u16 /*shndx*/, u64, u64)> = Vec::new();
        let mut name_index: HashMap<&str, usize> = HashMap::new();
        for (name, sec0, value, size) in &adds_sorted {
            if name_index.contains_key(name.as_str()) {
                continue; // two copies of one group in one object: first def suffices
            }
            name_index.insert(name.as_str(), sym_count + new_syms.len());
            // STB_WEAK=2, STT_FUNC=2; STV_HIDDEN via st_other below.
            new_syms.push((name.clone(), 0x22, (*sec0 + 1) as u16, *value, *size));
        }
        for (_, name, _) in &patches {
            if !name_index.contains_key(name.as_str()) {
                bail!("redirect to {name} has no weak definition in this object");
            }
        }
        if plan.adds.is_empty() {
            bail!("empty rewrite plan"); // caller bug — plans imply edits
        }

        // Locate the GLOBAL definitions to demote to WEAK. Patched in
        // the relocated symtab blob below (the in-place original
        // becomes a dead gap once the symtab moves).
        let mut demote_indexes: Vec<usize> = Vec::new();
        for (sec0, name) in &plan.weaken {
            let want_shndx = (*sec0 + 1) as u16;
            let found = syms.iter().enumerate().find(|(_, sym)| {
                sym.shndx == want_shndx && strtab_name(strtab_bytes, sym.name_off) == name.as_bytes()
            });
            match found {
                Some((i, _)) => demote_indexes.push(i),
                None => bail!("weaken: no symbol {name} defined in section {sec0}"),
            }
        }

        // ---- emit ------------------------------------------------------
        let mut out = bytes.to_vec();

        // In-place reloc retargets.
        for (p, name, delta) in &patches {
            let new_sym = name_index[name.as_str()] as u64;
            if l.is64 {
                let old_info = u64le(&out, p + 8);
                let new_info = (new_sym << 32) | (old_info & 0xffff_ffff);
                out[p + 8..p + 16].copy_from_slice(&new_info.to_le_bytes());
                let addend = i64::from_le_bytes(out[p + 16..p + 24].try_into().unwrap());
                out[p + 16..p + 24].copy_from_slice(&(addend + delta).to_le_bytes());
            } else {
                let old_info = u32le(&out, p + 4);
                if new_sym > 0x00ff_ffff {
                    bail!("symbol index overflow in ELF32 r_info");
                }
                let new_info = ((new_sym as u32) << 8) | (old_info & 0xff);
                out[p + 4..p + 8].copy_from_slice(&new_info.to_le_bytes());
                let addend = i32::from_le_bytes(out[p + 8..p + 12].try_into().unwrap());
                let new_addend = i64::from(addend) + delta;
                let new_addend32 = i32::try_from(new_addend)
                    .map_err(|_| anyhow!("addend overflow in ELF32 rela"))?;
                out[p + 8..p + 12].copy_from_slice(&new_addend32.to_le_bytes());
            }
        }

        // Alignment bumps (in-place sh_addralign patch).
        for (sec0, min_align) in &plan.align_bumps {
            let idx = *sec0 as usize + 1;
            let s = headers
                .get(idx)
                .ok_or_else(|| anyhow!("add-symbol section {idx} out of range"))?;
            let (pos, cur) = if l.is64 {
                (s.hdr_pos + 48, u64le(bytes, s.hdr_pos + 48))
            } else {
                (s.hdr_pos + 32, u64::from(u32le(bytes, s.hdr_pos + 32)))
            };
            if *min_align > cur {
                if l.is64 {
                    out[pos..pos + 8].copy_from_slice(&min_align.to_le_bytes());
                } else {
                    let v = u32::try_from(*min_align)
                        .map_err(|_| anyhow!("alignment overflow"))?;
                    out[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
        }

        if new_syms.is_empty() {
            return Ok(out);
        }

        // Grow symtab + strtab by relocating both to EOF with the new
        // entries appended. Old data stays as a dead gap (ELF allows it).
        let mut sym_blob = bytes[symtab.offset..symtab.offset + symtab.size].to_vec();
        let mut str_blob = bytes[strtab.offset..strtab.offset + strtab.size].to_vec();
        // GLOBAL → WEAK demotions (bind bits only; type/visibility kept).
        let info_off = if l.is64 { 4 } else { 12 };
        for &i in &demote_indexes {
            let p = i * sym_entsize + info_off;
            sym_blob[p] = 0x20 | (sym_blob[p] & 0x0f);
        }
        for (name, info, shndx, value, size) in &new_syms {
            let name_off = str_blob.len() as u32;
            str_blob.extend_from_slice(name.as_bytes());
            str_blob.push(0);
            if l.is64 {
                sym_blob.extend_from_slice(&name_off.to_le_bytes());
                sym_blob.push(*info);
                sym_blob.push(2); // st_other = STV_HIDDEN
                sym_blob.extend_from_slice(&shndx.to_le_bytes());
                sym_blob.extend_from_slice(&value.to_le_bytes());
                sym_blob.extend_from_slice(&size.to_le_bytes());
            } else {
                sym_blob.extend_from_slice(&name_off.to_le_bytes());
                sym_blob.extend_from_slice(&(*value as u32).to_le_bytes());
                sym_blob.extend_from_slice(&(*size as u32).to_le_bytes());
                sym_blob.push(*info);
                sym_blob.push(2); // st_other = STV_HIDDEN
                sym_blob.extend_from_slice(&shndx.to_le_bytes());
            }
        }
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let new_sym_off = out.len();
        out.extend_from_slice(&sym_blob);
        let new_str_off = out.len();
        out.extend_from_slice(&str_blob);

        let patch_shdr = |out: &mut Vec<u8>, s: &Shdr, off: usize, size: usize| {
            if l.is64 {
                out[s.hdr_pos + 24..s.hdr_pos + 32]
                    .copy_from_slice(&(off as u64).to_le_bytes());
                out[s.hdr_pos + 32..s.hdr_pos + 40]
                    .copy_from_slice(&(size as u64).to_le_bytes());
            } else {
                out[s.hdr_pos + 16..s.hdr_pos + 20]
                    .copy_from_slice(&(off as u32).to_le_bytes());
                out[s.hdr_pos + 20..s.hdr_pos + 24]
                    .copy_from_slice(&(size as u32).to_le_bytes());
            }
        };
        patch_shdr(&mut out, symtab, new_sym_off, sym_blob.len());
        patch_shdr(&mut out, strtab, new_str_off, str_blob.len());
        // Appending globals at the end preserves the locals-first
        // invariant, so symtab sh_info (first non-local index) stands.

        Ok(out)
    }

    // ---- ar archive rebuild ---------------------------------------------

    struct Member {
        hdr_pos: usize,
        data_start: usize,
        data_len: usize,
        /// Resolved member name ("/" and "//" keep their raw names).
        name: String,
    }

    fn parse_members(bytes: &[u8]) -> Result<Vec<Member>> {
        if !bytes.starts_with(b"!<arch>\n") {
            bail!("not an ar archive");
        }
        // First locate "//" (extended names) so headers can be resolved.
        let mut members = Vec::new();
        let mut pos = 8usize;
        let mut longnames: Option<(usize, usize)> = None;
        while pos + 60 <= bytes.len() {
            let hdr = &bytes[pos..pos + 60];
            if &hdr[58..60] != b"`\n" {
                bail!("bad ar member header at {pos:#x}");
            }
            let size: usize = std::str::from_utf8(&hdr[48..58])
                .map_err(|_| anyhow!("bad size field"))?
                .trim()
                .parse()
                .map_err(|_| anyhow!("bad size field at {pos:#x}"))?;
            let raw_name = std::str::from_utf8(&hdr[..16])
                .map_err(|_| anyhow!("bad name field"))?
                .trim_end();
            if raw_name == "//" {
                longnames = Some((pos + 60, size));
            }
            members.push(Member {
                hdr_pos: pos,
                data_start: pos + 60,
                data_len: size,
                name: raw_name.to_string(),
            });
            pos += 60 + size + (size & 1);
        }
        // Resolve "/<offset>" names through the longname table.
        if let Some((lo, ln)) = longnames {
            let table = &bytes[lo..lo + ln];
            for m in &mut members {
                if let Some(off_str) = m.name.strip_prefix('/')
                    && let Ok(off) = off_str.parse::<usize>()
                {
                    let end = table[off..]
                        .iter()
                        .position(|&b| b == b'\n')
                        .map_or(table.len(), |p| off + p);
                    let mut n = &table[off..end];
                    if n.ends_with(b"/") {
                        n = &n[..n.len() - 1];
                    }
                    m.name = String::from_utf8_lossy(n).into_owned();
                }
            }
        }
        // Short names end with '/'.
        for m in &mut members {
            if m.name.len() > 1 && m.name.ends_with('/') && m.name != "//" {
                m.name.pop();
            }
        }
        Ok(members)
    }

    /// Rebuild `orig` with `replaced` member bodies substituted and
    /// `index_adds` (symbol name → defining member name) appended to
    /// the `/` symbol index. Existing index entries are remapped to the
    /// members' new offsets; member order and the `//` longname table
    /// are preserved verbatim.
    pub(super) fn rebuild_archive(
        orig: &[u8],
        replaced: &HashMap<String, Vec<u8>>,
        index_adds: &[(String, String)],
    ) -> Result<Vec<u8>> {
        let members = parse_members(orig)?;
        let index_member = members
            .first()
            .filter(|m| m.name == "/")
            .ok_or_else(|| anyhow!("archive has no leading symbol index"))?;

        // Parse old index: count, offsets, then NUL-terminated names.
        let idx_data = &orig[index_member.data_start..index_member.data_start + index_member.data_len];
        if idx_data.len() < 4 {
            bail!("truncated archive index");
        }
        let count = u32::from_be_bytes(idx_data[..4].try_into().unwrap()) as usize;
        let names_start = 4 + 4 * count;
        if idx_data.len() < names_start {
            bail!("truncated archive index offsets");
        }
        let mut old_entries: Vec<(u32, &[u8])> = Vec::with_capacity(count);
        {
            let mut name_pos = names_start;
            for i in 0..count {
                let off = u32::from_be_bytes(idx_data[4 + 4 * i..8 + 4 * i].try_into().unwrap());
                let end = idx_data[name_pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| name_pos + p)
                    .ok_or_else(|| anyhow!("unterminated index name"))?;
                old_entries.push((off, &idx_data[name_pos..end]));
                name_pos = end + 1;
            }
        }

        // New body sizes per member (skipping the index itself).
        let body_len = |m: &Member| -> usize {
            match replaced.get(&m.name) {
                Some(b) if m.name != "/" && m.name != "//" => b.len(),
                _ => m.data_len,
            }
        };

        // New index size: old names + appended entries.
        let mut new_names_len: usize = old_entries.iter().map(|(_, n)| n.len() + 1).sum();
        for (sym, _) in index_adds {
            new_names_len += sym.len() + 1;
        }
        let new_count = count + index_adds.len();
        let mut new_idx_len = 4 + 4 * new_count + new_names_len;
        if new_idx_len % 2 == 1 {
            new_idx_len += 1; // pad the index body itself to even
        }

        // Lay out new header positions.
        let mut new_pos: HashMap<usize, usize> = HashMap::new(); // hdr_pos → new hdr_pos
        let mut cursor = 8usize;
        for m in &members {
            new_pos.insert(m.hdr_pos, cursor);
            let len = if m.name == "/" { new_idx_len } else { body_len(m) };
            cursor += 60 + len + (len & 1);
        }

        // Old index offsets point at member header positions.
        let remap = |old: u32| -> Result<u32> {
            let np = new_pos
                .get(&(old as usize))
                .ok_or_else(|| anyhow!("index offset {old:#x} matches no member"))?;
            Ok(*np as u32)
        };
        let member_new_off = |name: &str| -> Result<u32> {
            let m = members
                .iter()
                .find(|m| m.name == name)
                .ok_or_else(|| anyhow!("index add references unknown member {name}"))?;
            Ok(new_pos[&m.hdr_pos] as u32)
        };

        let mut new_idx = Vec::with_capacity(new_idx_len);
        new_idx.extend_from_slice(&(new_count as u32).to_be_bytes());
        for (off, _) in &old_entries {
            new_idx.extend_from_slice(&remap(*off)?.to_be_bytes());
        }
        for (_, member_name) in index_adds {
            new_idx.extend_from_slice(&member_new_off(member_name)?.to_be_bytes());
        }
        for (_, name) in &old_entries {
            new_idx.extend_from_slice(name);
            new_idx.push(0);
        }
        for (sym, _) in index_adds {
            new_idx.extend_from_slice(sym.as_bytes());
            new_idx.push(0);
        }
        while new_idx.len() < new_idx_len {
            new_idx.push(0);
        }

        // Emit.
        let mut out = Vec::with_capacity(cursor);
        out.extend_from_slice(b"!<arch>\n");
        for m in &members {
            let mut hdr = orig[m.hdr_pos..m.hdr_pos + 60].to_vec();
            let body: &[u8] = if m.name == "/" {
                &new_idx
            } else {
                match replaced.get(&m.name) {
                    Some(b) if m.name != "//" => b,
                    _ => &orig[m.data_start..m.data_start + m.data_len],
                }
            };
            let size_field = format!("{:<10}", body.len());
            hdr[48..58].copy_from_slice(size_field.as_bytes());
            debug_assert_eq!(out.len(), new_pos[&m.hdr_pos]);
            out.extend_from_slice(&hdr);
            out.extend_from_slice(body);
            if body.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        Ok(out)
    }
}
