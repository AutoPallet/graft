//! relaxwalk — corpus harness for the relaxation reconciliation walk
//! (docs/16-relaxation-walk.md §7).
//!
//! For every relaxed input section recorded in a GNU ld -Map file,
//! reconcile the pristine archive-member bytes against the linked
//! image via `graft::relax`. The bar: 100% of exec/literal sections
//! reconciled-or-provably-refused, zero non-source rules on clean
//! paths.
//!
//! Run from the directory the map's relative archive paths resolve
//! against (the esp-idf-sys out/build dir for the deploy corpus):
//!
//!   relaxwalk --map corpus.map --elf <linked-elf> \
//!             --path-map /workspaces/roborack=/home/eric/roborack2

use graft::relax::xtensa::{self, Xtensa};
use graft::relax::{Census, Verdict, engine};
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::HashMap;

// ---------- map parsing ----------

#[derive(Debug)]
struct MapEntry {
    in_name: String,
    addr: u64,
    out_size: u64,
    in_size: u64,
    obj: String, // "path/lib.a(member.o)" or "path/file.o"
}

/// Relaxed input sections: an input-section line whose next line ends
/// "(size before relaxing)". Long names wrap onto their own line.
///
/// The v1 prototype classified name lines with `!line.contains("0x")`,
/// which silently dropped 796 sections whose Rust v0-mangled names
/// contain a literal "0x" (`...10xtensa_cli...`); parse by token shape
/// instead.
fn parse_map(text: &str) -> Vec<MapEntry> {
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
        last = None;
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
            last = Some(MapEntry {
                in_name: name,
                addr,
                out_size: size,
                in_size: 0,
                obj: obj.to_string(),
            });
        }
    }
    out
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

// ---------- archive cache ----------

/// All referenced archives, read once and held in memory: the v1
/// prototype re-read archives per section and spent 95% of its wall
/// time in syscalls.
struct Archives {
    bytes: HashMap<String, Vec<u8>>,
}

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

fn main() {
    let mut map_path = None;
    let mut elf_path = None;
    let mut path_maps: Vec<(String, String)> = Vec::new();
    let mut verbose = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--map" => map_path = args.next(),
            "--elf" => elf_path = args.next(),
            "--path-map" => {
                let v = args.next().expect("--path-map A=B");
                let (from, to) = v.split_once('=').expect("--path-map A=B");
                path_maps.push((from.to_string(), to.to_string()));
            }
            "-v" | "--verbose" => verbose = true,
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    let map_path = map_path.expect("--map <file> required");
    let elf_path = elf_path.expect("--elf <file> required");

    let map_text = std::fs::read_to_string(&map_path).expect("read map");
    let entries = parse_map(&map_text);
    let recovered = entries.iter().filter(|e| e.in_name.contains("0x")).count();
    println!("{} relaxed sections in map ({} with 0x-bearing names)", entries.len(), recovered);

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
    let mut out_syms: HashMap<String, u64> = HashMap::new();
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

    // phase 1: load every referenced archive once
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
    let mut archives = Archives { bytes: HashMap::new() };
    let mut load_errors: HashMap<String, String> = HashMap::new();
    for e in &entries {
        let (path, _) = split_obj(&e.obj);
        if archives.bytes.contains_key(&path) || load_errors.contains_key(&path) {
            continue;
        }
        match std::fs::read(&path) {
            Ok(b) => {
                archives.bytes.insert(path, b);
            }
            Err(err) => {
                load_errors.insert(path, err.to_string());
            }
        }
    }
    let total: usize = archives.bytes.values().map(|b| b.len()).sum();
    println!("{} archives loaded ({} MB)", archives.bytes.len(), total >> 20);
    let members: HashMap<&String, MemberIndex> = archives
        .bytes
        .iter()
        .map(|(p, b)| (p, index_members(b).unwrap_or_default()))
        .collect();

    // walk every entry
    let target = Xtensa;
    let mut attempted = 0usize;
    let mut reconciled = 0usize;
    let mut diagnostic_uses = 0u64;
    let mut census = Census::default();
    let mut skips: HashMap<String, usize> = HashMap::new();
    let mut dirty: Vec<String> = Vec::new();

    'entry: for e in &entries {
        let (path, member_name) = split_obj(&e.obj);
        let Some(data) = archives.bytes.get(&path) else {
            *skips.entry(format!("archive read failed: {path}")).or_default() += 1;
            continue;
        };
        let member_ranges = members
            .get(&path)
            .and_then(|m| m.get(&member_name))
            .cloned()
            .unwrap_or_default();

        // candidates across duplicate member names AND duplicate
        // same-named sections within a member: disambiguate by
        // (section name, input size); bail if not exactly one
        let mut candidates: Vec<(std::ops::Range<usize>, object::SectionIndex)> = Vec::new();
        for r in &member_ranges {
            let Ok(obj) = object::File::parse(&data[r.clone()]) else { continue };
            for sec in obj.sections() {
                if sec.name() == Ok(&e.in_name) && sec.size() == e.in_size {
                    candidates.push((r.clone(), sec.index()));
                }
            }
        }
        if candidates.len() != 1 {
            *skips
                .entry(format!("ambiguous-or-missing section ({} candidates)", candidates.len()))
                .or_default() += 1;
            continue;
        }
        let (range, sec_index) = candidates.pop().unwrap();
        let obj = object::File::parse(&data[range]).expect("re-parse member");
        let sec = obj.section_by_index(sec_index).expect("section by index");

        // only instruction streams and literal pools walk; other
        // relaxed entries are SHF_MERGE string folding (docs/16 §4)
        if sec.kind() != object::SectionKind::Text && !e.in_name.contains(".literal") {
            *skips.entry("merge-fold (non-exec)".to_string()).or_default() += 1;
            continue;
        }

        // output bytes at the section's placed address
        let out_bytes: &[u8] = if e.out_size == 0 {
            &[]
        } else {
            let mut found = None;
            for &(addr, data) in &out_secs {
                if e.addr >= addr && e.addr + e.out_size <= addr + data.len() as u64 {
                    let s = (e.addr - addr) as usize;
                    found = Some(&data[s..s + e.out_size as usize]);
                    break;
                }
            }
            match found {
                Some(b) => b,
                None => {
                    *skips.entry("output bytes not found".to_string()).or_default() += 1;
                    continue 'entry;
                }
            }
        };

        let input = match xtensa::extract_input(&obj, &sec, &out_syms) {
            Ok(i) => i,
            Err(err) => {
                *skips.entry(format!("extract failed: {err}")).or_default() += 1;
                continue;
            }
        };

        attempted += 1;
        match engine::reconcile(&input, out_bytes, &target) {
            Verdict::Reconciled(c) => {
                reconciled += 1;
                diagnostic_uses += c.diagnostics();
                if verbose && c.diagnostics() > 0 {
                    println!("DIAG {} {} ({})", e.in_name, e.obj, c.diagnostics());
                }
                census.absorb(&c);
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
    println!("  of which used NON-SOURCE diagnostic rules: {diagnostic_uses}");
    println!("actions: {census:?}");
    if !dirty.is_empty() {
        println!("\n{} dirty sections:", dirty.len());
        for d in dirty.iter().take(40) {
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
    if reconciled < attempted {
        std::process::exit(1);
    }
}
