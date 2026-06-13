//! relaxwalk — corpus harness for the relaxation reconciliation walk
//! (docs/16-relaxation-walk.md §7).
//!
//! Two modes, one engine:
//!
//! - `--arch xtensa` (default): for every *relaxed* input section in a
//!   GNU ld -Map, reconcile pristine archive-member bytes against the
//!   linked image through ld's transform alphabet. Bar: 100%
//!   reconciled-or-provably-refused.
//! - `--arch x86`: verify-identity mode (docs/16 §8) over *every*
//!   placed input section — x86 ld never resizes sections, so the walk
//!   degenerates to byte-compare modulo reloc masks. This is the
//!   safety check that sections ended up where the map (and graft's
//!   positional model) says.
//!
//! Run from the directory the map's relative archive paths resolve
//! against. Examples:
//!
//!   relaxwalk --map corpus.map --elf <linked-elf> \
//!             --path-map /workspaces/roborack=/home/eric/roborack2
//!   relaxwalk --arch x86 --map base.graft-map --elf <base-elf>

use graft::relax::engine;
use graft::relax::x86;
use graft::relax::xtensa::{self, Xtensa};
use graft::relax::{Census, Fate, FateCell, InputSection, RegionKind, Verdict};
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq)]
enum Arch {
    Xtensa,
    X86,
}

// ---------- map parsing ----------

#[derive(Debug)]
struct MapEntry {
    in_name: String,
    addr: u64,
    out_size: u64,
    in_size: u64,
    obj: String, // "path/lib.a(member.o)" or "path/file.o"
}

/// Input-section placements from a GNU ld -Map. With `relaxed_only`,
/// keep only entries whose next line ends "(size before relaxing)"
/// (xtensa corpus); otherwise keep every placed entry (x86 verify).
/// Long names wrap onto their own line.
///
/// The v1 prototype classified name lines with `!line.contains("0x")`,
/// which silently dropped 796 sections whose Rust v0-mangled names
/// contain a literal "0x" (`...10xtensa_cli...`); parse by token shape
/// instead.
fn parse_map(text: &str, relaxed_only: bool) -> Vec<MapEntry> {
    let mut out = Vec::new();
    let mut pending_name: Option<String> = None;
    let mut last: Option<MapEntry> = None;
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if line.trim_end().ends_with("(size before relaxing)") {
            if let (Some(mut e), Some(sz)) = (last.take(), toks.first().and_then(|t| hex(t))) {
                e.in_size = sz;
                out.push(e);
            }
            pending_name = None;
            continue;
        }
        if relaxed_only {
            last = None;
        }
        // input-section lines: exactly one leading space, name starts '.'
        let named = line.starts_with(' ')
            && !line.starts_with("  ")
            && toks.first().is_some_and(|t| t.starts_with('.'));
        if named && toks.len() == 1 {
            pending_name = Some(toks[0].to_string()); // wrapped long name
            continue;
        }
        let (name, rest) = if named {
            (Some(toks[0].to_string()), &toks[1..])
        } else {
            (pending_name.take(), &toks[..])
        };
        pending_name = None;
        if let (Some(name), [a, s, obj, ..]) = (name, rest)
            && let (Some(addr), Some(size)) = (hex(a), hex(s))
        {
            let e = MapEntry {
                in_name: name,
                addr,
                out_size: size,
                in_size: size,
                obj: obj.to_string(),
            };
            if relaxed_only {
                last = Some(e); // confirmed by the annotation line
            } else if addr != 0 && size != 0 {
                out.push(e); // discarded/non-alloc sit at addr 0
            }
        }
    }
    out
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

// ---------- archive + member caches ----------

/// (member name → byte ranges) per archive; duplicate member names are
/// real in esp-idf (libmbedcrypto.a carries two bignum.c.obj).
type MemberIndex = HashMap<String, Vec<std::ops::Range<usize>>>;

fn index_members(data: &[u8]) -> Result<MemberIndex, String> {
    use object::read::archive::ArchiveFile;
    let mut idx: MemberIndex = HashMap::new();
    if data.starts_with(b"!<arch>\n") {
        let ar = ArchiveFile::parse(data).map_err(|e| e.to_string())?;
        for member in ar.members() {
            let member = member.map_err(|e| e.to_string())?;
            let name = String::from_utf8_lossy(member.name()).into_owned();
            let (off, len) = member.file_range();
            idx.entry(name).or_default().push(off as usize..(off + len) as usize);
        }
    } else {
        // bare object file
        idx.entry(String::new()).or_default().push(0..data.len());
    }
    Ok(idx)
}

/// A parsed member with a name → sections index: at x86 scale (632k
/// map entries over ~2k members) re-parsing and linear name scans per
/// entry would dominate the run.
struct Member<'a> {
    file: object::File<'a>,
    by_name: HashMap<String, Vec<(object::SectionIndex, u64)>>,
}

fn parse_member(data: &[u8]) -> Option<Member<'_>> {
    let file = object::File::parse(data).ok()?;
    let mut by_name: HashMap<String, Vec<(object::SectionIndex, u64)>> = HashMap::new();
    for sec in file.sections() {
        if let Ok(name) = sec.name() {
            by_name.entry(name.to_string()).or_default().push((sec.index(), sec.size()));
        }
    }
    Some(Member { file, by_name })
}

fn main() {
    let mut map_path = None;
    let mut elf_path = None;
    let mut path_maps: Vec<(String, String)> = Vec::new();
    let mut verbose = false;
    let mut ambiguity = false;
    let mut arch = Arch::Xtensa;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--map" => map_path = args.next(),
            "--elf" => elf_path = args.next(),
            "--arch" => {
                arch = match args.next().as_deref() {
                    Some("xtensa") => Arch::Xtensa,
                    Some("x86") => Arch::X86,
                    other => panic!("--arch xtensa|x86, got {other:?}"),
                }
            }
            "--path-map" => {
                let v = args.next().expect("--path-map A=B");
                let (from, to) = v.split_once('=').expect("--path-map A=B");
                path_maps.push((from.to_string(), to.to_string()));
            }
            "-v" | "--verbose" => verbose = true,
            "--ambiguity" => ambiguity = true,
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    let map_path = map_path.expect("--map <file> required");
    let elf_path = elf_path.expect("--elf <file> required");

    let map_text = std::fs::read_to_string(&map_path).expect("read map");
    let entries = parse_map(&map_text, arch == Arch::Xtensa);
    println!("{} input sections from map", entries.len());
    drop(map_text);

    // linked image: section bytes by vaddr + unique-address symbol table
    let elf_bytes = std::fs::read(&elf_path).expect("read elf");
    let elf = object::File::parse(&*elf_bytes).expect("parse elf");
    let mut out_secs: Vec<(u64, &[u8])> = Vec::new();
    for sec in elf.sections() {
        if sec.address() != 0
            && sec.size() > 0
            && sec.kind() != object::SectionKind::UninitializedData
            && let Ok(data) = sec.data()
            && !data.is_empty()
        {
            out_secs.push((sec.address(), data));
        }
    }
    // the symbol table only feeds xtensa literal-value resolution
    let mut out_syms: HashMap<String, u64> = HashMap::new();
    if arch == Arch::Xtensa {
        let mut ambiguous: std::collections::HashSet<String> = Default::default();
        for sym in elf.symbols() {
            if sym.is_undefined()
                || matches!(sym.kind(), object::SymbolKind::Section | object::SymbolKind::File)
            {
                continue;
            }
            let Ok(name) = sym.name() else { continue };
            if name.is_empty() {
                continue;
            }
            match out_syms.entry(name.to_string()) {
                std::collections::hash_map::Entry::Occupied(e) => {
                    if *e.get() != sym.address() {
                        ambiguous.insert(name.to_string());
                    }
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(sym.address());
                }
            }
        }
        for name in &ambiguous {
            out_syms.remove(name);
        }
        println!(
            "{} unique-address output symbols ({} ambiguous dropped)",
            out_syms.len(),
            ambiguous.len()
        );
    }

    // phase 1: load every referenced archive once (the v1 prototype
    // re-read archives per section: 95% of its wall time)
    let remap = |p: &str| -> String {
        for (from, to) in &path_maps {
            if let Some(rest) = p.strip_prefix(from.as_str()) {
                return format!("{to}{rest}");
            }
        }
        p.to_string()
    };
    let split_obj = |obj: &str| -> (String, String) {
        match obj.split_once('(') {
            Some((path, member)) => (remap(path), member.trim_end_matches(')').to_string()),
            None => (remap(obj), String::new()),
        }
    };
    let mut archive_bytes: HashMap<String, Vec<u8>> = HashMap::new();
    let mut load_errors: HashMap<String, String> = HashMap::new();
    for e in &entries {
        let (path, _) = split_obj(&e.obj);
        if archive_bytes.contains_key(&path) || load_errors.contains_key(&path) {
            continue;
        }
        match std::fs::read(&path) {
            Ok(b) => {
                archive_bytes.insert(path, b);
            }
            Err(err) => {
                load_errors.insert(path, err.to_string());
            }
        }
    }
    let total: usize = archive_bytes.values().map(|b| b.len()).sum();
    println!("{} archives loaded ({} MB)", archive_bytes.len(), total >> 20);
    let members: HashMap<&String, MemberIndex> = archive_bytes
        .iter()
        .map(|(p, b)| (p, index_members(b).unwrap_or_default()))
        .collect();
    let mut parsed: HashMap<(String, usize), Option<Member>> = HashMap::new();
    // per-member: target section index → in-section offsets referenced
    // by OTHER alloc sections of the same object (the harness proxy
    // for channel-2 interior anchor queries)
    let mut query_cache: HashMap<(String, usize), HashMap<object::SectionIndex, Vec<usize>>> =
        HashMap::new();

    // walk every entry
    let mut attempted = 0usize;
    let mut reconciled = 0usize;
    let mut fast_verified = 0usize;
    let mut diagnostic_uses = 0u64;
    let mut census = Census::default();
    let mut skips: HashMap<String, usize> = HashMap::new();
    let mut dirty: Vec<String> = Vec::new();
    let mut amb = AmbStats::default();

    for e in &entries {
        let (path, member_name) = split_obj(&e.obj);
        if path.ends_with(".graft-slack.o") {
            *skips.entry("graft synthetic slack object".into()).or_default() += 1;
            continue;
        }
        let Some(data) = archive_bytes.get(&path) else {
            *skips.entry(format!("archive read failed: {path}")).or_default() += 1;
            continue;
        };
        let member_ranges = members
            .get(&path)
            .and_then(|m| m.get(&member_name))
            .cloned()
            .unwrap_or_default();

        // candidates across duplicate member names AND duplicate
        // same-named sections within a member; bail unless exactly
        // one. Section identity: xtensa disambiguates by (name, input
        // size) — the relaxed map size differs; x86 selects by name
        // alone and treats a size mismatch as a verdict, not a lookup
        // miss (the placed size must equal the input size for
        // everything verified).
        let mut candidates: Vec<(usize, object::SectionIndex)> = Vec::new();
        for r in &member_ranges {
            let m = parsed
                .entry((path.clone(), r.start))
                .or_insert_with(|| parse_member(&data[r.clone()]));
            let Some(m) = m else { continue };
            if let Some(secs) = m.by_name.get(&e.in_name) {
                for &(idx, size) in secs {
                    if arch == Arch::X86 || size == e.in_size {
                        candidates.push((r.start, idx));
                    }
                }
            }
        }
        if candidates.len() != 1 {
            *skips
                .entry(format!("ambiguous-or-missing section ({} candidates)", candidates.len()))
                .or_default() += 1;
            continue;
        }
        let member = parsed
            .get(&(path.clone(), candidates[0].0))
            .and_then(|m| m.as_ref())
            .expect("member parsed above");
        let sec = member
            .file
            .section_by_index(candidates[0].1)
            .expect("section by index");

        // section classes the walk does not cover
        let skip_reason = match arch {
            // non-exec relaxed entries are SHF_MERGE string folding
            Arch::Xtensa
                if sec.kind() != object::SectionKind::Text
                    && !e.in_name.contains(".literal") =>
            {
                Some("merge-fold (non-exec)")
            }
            Arch::X86 => {
                let sh_flags = match sec.flags() {
                    object::SectionFlags::Elf { sh_flags } => sh_flags,
                    _ => 0,
                };
                if sh_flags & u64::from(object::elf::SHF_ALLOC) == 0 {
                    // debug/non-alloc "addresses" in the map are
                    // offsets inside a vma-0 output section — they can
                    // collide with real vaddrs in a big image
                    Some("non-alloc")
                } else if sh_flags & u64::from(object::elf::SHF_MERGE) != 0 {
                    Some("merge section (folded)") // per-entry identity, graft v7
                } else if matches!(
                    sec.kind(),
                    object::SectionKind::UninitializedData
                        | object::SectionKind::UninitializedTls
                        | object::SectionKind::Common
                ) {
                    Some("nobits")
                } else if e.in_name == ".eh_frame" {
                    Some(".eh_frame (CIE-edited by ld)")
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(why) = skip_reason {
            *skips.entry(why.to_string()).or_default() += 1;
            continue;
        }
        if arch == Arch::X86 && sec.size() != e.out_size {
            // x86 ld never resizes a (non-merge) input section: a
            // placed size differing from the input size means the
            // positional model is wrong for this section
            dirty.push(format!(
                "SIZE {} {} input {:#x} placed {:#x}",
                e.in_name,
                e.obj,
                sec.size(),
                e.out_size
            ));
            attempted += 1;
            continue;
        }

        // output bytes at the section's placed address
        let out_bytes: &[u8] = if e.out_size == 0 {
            &[]
        } else {
            match out_secs.iter().find_map(|&(addr, data)| {
                (e.addr >= addr && e.addr + e.out_size <= addr + data.len() as u64).then(|| {
                    let s = (e.addr - addr) as usize;
                    &data[s..s + e.out_size as usize]
                })
            }) {
                Some(b) => b,
                None => {
                    *skips.entry("output bytes not found".to_string()).or_default() += 1;
                    continue;
                }
            }
        };

        let input = match arch {
            Arch::Xtensa => xtensa::extract_input(&member.file, &sec, &out_syms),
            Arch::X86 => x86::extract_input(&sec),
        };
        let input = match input {
            Ok(i) => i,
            Err(err) => {
                *skips.entry(format!("extract failed: {err}")).or_default() += 1;
                continue;
            }
        };

        attempted += 1;
        // x86: same-size masked compare IS the degenerate walk, and
        // with equal sizes the min-cost path is replace-only — extract
        // mismatch runs directly instead of searching for them
        if arch == Arch::X86 {
            match masked_compare(&input, out_bytes) {
                Ok(()) => {
                    reconciled += 1;
                    fast_verified += 1;
                    census.data_bytes += out_bytes.len() as u64;
                }
                Err(runs) => {
                    let desc: Vec<String> = runs
                        .iter()
                        .take(4)
                        .map(|r| format!("({},{},{})", r.in_off, r.in_len, r.out_len))
                        .collect();
                    dirty.push(format!("{} {} runs {}", e.in_name, e.obj, desc.join(" ")));
                }
            }
            continue;
        }
        let verdict = engine::reconcile(&input, out_bytes, &Xtensa);
        match verdict {
            Verdict::Reconciled(c) => {
                reconciled += 1;
                diagnostic_uses += c.diagnostics();
                if verbose && c.diagnostics() > 0 {
                    println!("DIAG {} {} ({})", e.in_name, e.obj, c.diagnostics());
                }
                census.absorb(&c);
                if ambiguity {
                    let queries = query_cache
                        .entry((path.clone(), candidates[0].0))
                        .or_insert_with(|| collect_queries(&member.file))
                        .get(&candidates[0].1)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    amb.add(&input, out_bytes, queries, &format!("{} {}", e.in_name, e.obj));
                }
            }
            Verdict::Dirty(c, runs) => {
                let desc: Vec<String> = runs
                    .iter()
                    .take(4)
                    .map(|r| format!("({},{},{})", r.in_off, r.in_len, r.out_len))
                    .collect();
                dirty.push(format!("{} {} runs {}", e.in_name, e.obj, desc.join(" ")));
                census.absorb(&c);
            }
            Verdict::Refused(why) => {
                *skips.entry(format!("refused: {why}")).or_default() += 1;
            }
        }
    }

    println!("\n=== relaxwalk results ===");
    let pct = if attempted > 0 { 100.0 * reconciled as f64 / attempted as f64 } else { 0.0 };
    println!("attempted: {attempted}   reconciled: {reconciled} ({pct:.1}%)");
    if arch == Arch::X86 {
        println!("  fast-path verified: {fast_verified}");
    }
    println!("  of which used NON-SOURCE diagnostic rules: {diagnostic_uses}");
    println!("actions: {census:?}");
    if !dirty.is_empty() {
        println!("\n{} dirty sections:", dirty.len());
        for d in &dirty {
            println!("  DIRTY {d}");
        }
    }
    let mut skips: Vec<_> = skips.into_iter().collect();
    skips.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (why, n) in &skips {
        println!("load-skip[{n}]: {why}");
    }
    for (path, err) in &load_errors {
        println!("load-error: {path}: {err}");
    }
    if ambiguity {
        amb.report();
    }
    if reconciled < attempted {
        std::process::exit(1);
    }
}

/// Same-object reloc targets, bucketed by target section: which
/// in-section offsets would channel-2 anchor resolution actually ask
/// the walk to translate. Cross-object references into another
/// object's literal pool don't exist (pools are function-local), so
/// same-object is the full query population for pools; for code it
/// undercounts cross-object callers, which target symbol offsets the
/// same way.
fn collect_queries(
    obj: &object::File,
) -> HashMap<object::SectionIndex, Vec<usize>> {
    use object::{ObjectSection, ObjectSymbol, RelocationTarget};
    let mut out: HashMap<object::SectionIndex, Vec<usize>> = HashMap::new();
    for x in obj.sections() {
        let alloc = matches!(x.flags(), object::SectionFlags::Elf { sh_flags }
            if sh_flags & u64::from(object::elf::SHF_ALLOC) != 0);
        if !alloc {
            continue; // debug/.xt.prop relocs are not runtime references
        }
        if x.name().is_ok_and(|n| n.starts_with(".xt.")) {
            continue;
        }
        for (_, rel) in x.relocations() {
            let RelocationTarget::Symbol(si) = rel.target() else { continue };
            let Ok(sym) = obj.symbol_by_index(si) else { continue };
            let Some(target) = sym.section_index() else { continue };
            if target == x.index() {
                continue; // intra-section: prune wires these internally
            }
            let off = sym.address() as i64 + rel.addend();
            if off >= 0 {
                out.entry(target).or_default().push(off as usize);
            }
        }
    }
    out
}

/// Corpus-wide DP-intersection accounting (docs/16 §8): how often do
/// equal-cost parses disagree about a byte's fate, and where.
#[derive(Default)]
struct AmbStats {
    sections: usize,
    sections_ambiguous: usize,
    sections_code_ambiguous: usize,
    kept: u64,
    deleted: u64,
    interior: u64,
    /// ambiguous bytes by region: code, literal, unreachable, data
    by_region: [u64; 4],
    /// (ambiguous bytes, code-region share, description)
    offenders: Vec<(u64, u64, String)>,
    no_parse: usize,
    /// channel-2 query population × fate, split code/literal:
    /// [kept, deleted, interior, ambiguous]
    q_code: [u64; 4],
    q_lit: [u64; 4],
    q_other: u64,
    /// sections whose QUERIED offsets include a problem (deleted /
    /// interior / ambiguous): the set that must pull or hard-fail
    q_problem_sections: Vec<String>,
}

impl AmbStats {
    fn add(&mut self, input: &InputSection, out: &[u8], queries: &[usize], desc: &str) {
        let Some(fates) = engine::translations(input, out, &Xtensa) else {
            self.no_parse += 1;
            return;
        };
        let mut kind = vec![0u8; input.bytes.len()];
        for (r, k) in &input.regions {
            let c = match k {
                RegionKind::Literal => 1,
                RegionKind::Unreachable => 2,
                RegionKind::Data => 3,
            };
            for b in r.start.min(kind.len())..r.end.min(kind.len()) {
                kind[b] = c;
            }
        }
        let mut n_amb = 0u64;
        let mut code_amb = 0u64;
        let mut first: Vec<usize> = Vec::new();
        for (b, f) in fates.iter().enumerate() {
            match f {
                FateCell::Agreed(Fate::Kept(_)) => self.kept += 1,
                FateCell::Agreed(Fate::Deleted) => self.deleted += 1,
                FateCell::Agreed(Fate::Interior) => self.interior += 1,
                FateCell::Ambiguous => {
                    n_amb += 1;
                    self.by_region[kind[b] as usize] += 1;
                    if kind[b] == 0 {
                        code_amb += 1;
                    }
                    if first.len() < 4 {
                        first.push(b);
                    }
                }
            }
        }
        self.sections += 1;
        if n_amb > 0 {
            self.sections_ambiguous += 1;
            if code_amb > 0 {
                self.sections_code_ambiguous += 1;
            }
            self.offenders.push((n_amb, code_amb, format!("{desc} first@{first:?}")));
        }
        // cross the real query population against the fates
        let mut problem = false;
        for &q in queries {
            if q >= fates.len() {
                self.q_other += 1; // off-section addend arithmetic
                continue;
            }
            let fate_idx = match fates[q] {
                FateCell::Agreed(Fate::Kept(_)) => 0,
                FateCell::Agreed(Fate::Deleted) => 1,
                FateCell::Agreed(Fate::Interior) => 2,
                FateCell::Ambiguous => 3,
            };
            match kind[q] {
                0 => self.q_code[fate_idx] += 1,
                1 => self.q_lit[fate_idx] += 1,
                _ => self.q_other += 1,
            }
            if fate_idx != 0 {
                problem = true;
            }
        }
        if problem {
            self.q_problem_sections.push(desc.to_string());
        }
    }

    fn report(&mut self) {
        println!("\n=== ambiguity (DP-intersection over min-cost parses) ===");
        println!(
            "sections analyzed: {} · with ambiguous bytes: {} · with ambiguous CODE bytes: {}{}",
            self.sections,
            self.sections_ambiguous,
            self.sections_code_ambiguous,
            if self.no_parse > 0 { format!(" · no-parse: {}", self.no_parse) } else { String::new() },
        );
        let amb: u64 = self.by_region.iter().sum();
        println!(
            "bytes: kept {} · deleted {} · interior {} · AMBIGUOUS {} (code {} / literal {} / unreachable {} / data {})",
            self.kept,
            self.deleted,
            self.interior,
            amb,
            self.by_region[0],
            self.by_region[1],
            self.by_region[2],
            self.by_region[3],
        );
        self.offenders.sort_by_key(|(n, c, _)| std::cmp::Reverse((*c, *n)));
        for (n, c, desc) in self.offenders.iter().take(25) {
            println!("  AMBIG bytes={n} code={c} {desc}");
        }
        println!(
            "queries (same-object reloc targets): code kept {} / deleted {} / interior {} / AMBIGUOUS {} · literal kept {} / deleted {} / interior {} / AMBIGUOUS {} · other-region {}",
            self.q_code[0],
            self.q_code[1],
            self.q_code[2],
            self.q_code[3],
            self.q_lit[0],
            self.q_lit[1],
            self.q_lit[2],
            self.q_lit[3],
            self.q_other,
        );
        println!(
            "sections with problem queries (deleted/interior/ambiguous → pull-or-fail): {}",
            self.q_problem_sections.len()
        );
        for desc in self.q_problem_sections.iter().take(15) {
            println!("  QPROB {desc}");
        }
    }
}

/// The degenerate walk for resize-free targets: byte-equal modulo
/// reloc masks at identical sizes. On mismatch, returns the maximal
/// unexplained runs (with equal sizes, the engine's min-cost path is
/// replace-only, so direct extraction is exact and O(n)).
fn masked_compare(input: &InputSection, out: &[u8]) -> Result<(), Vec<graft::relax::DirtyRun>> {
    if input.bytes.len() != out.len() {
        return Err(vec![graft::relax::DirtyRun {
            in_off: 0,
            in_len: input.bytes.len(),
            out_len: out.len(),
        }]);
    }
    let mut runs: Vec<graft::relax::DirtyRun> = Vec::new();
    for (k, (a, b)) in input.bytes.iter().zip(out).enumerate() {
        if a == b || input.mask[k] {
            continue;
        }
        match runs.last_mut() {
            Some(r) if r.in_off + r.in_len == k => {
                r.in_len += 1;
                r.out_len += 1;
            }
            _ => runs.push(graft::relax::DirtyRun { in_off: k, in_len: 1, out_len: 1 }),
        }
    }
    if runs.is_empty() { Ok(()) } else { Err(runs) }
}
