//! Isolated prototype of the relaxation reconciliation walk (task #32).
//!
//! Feeds on a real link: the GNU ld -Map names every input section that
//! relaxed ("(size before relaxing)") plus its output (start, size); the
//! input object supplies pre-relaxation bytes + relocs; the linked ELF
//! supplies post-relaxation bytes. The walk advances a cursor through
//! both byte streams, explaining every byte as exactly one of:
//!
//!   verbatim   same-length insn, bytes equal modulo reloc fields and
//!              pc-relative immediate fields (ld retargets in place)
//!   longcall   l32r+callx/jx (6 bytes) -> call/j (3 bytes)
//!   narrow     3-byte insn -> 2-byte density form
//!   fill       output-only nop/nop.n (alignment padding insertion)
//!   unfill     input-only nop/nop.n removal
//!   lit-del    deleted 4-byte words inside a literal region
//!
//! Anything unexplained refuses with (input offset, reason) -- the
//! prototype's job is to measure how often each verdict happens on a
//! real corpus, NOT to be complete. Greedy single parse; the only
//! backtracking is the bounded kept-word count per literal region.
//!
//! Usage:
//!   relaxwalk --map M --elf E [--path-map FROM=TO] [--limit N] [-v] [--filter S]

use std::collections::HashMap;
use std::path::PathBuf;

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

// ---------- map parsing (standalone; relaxed entries only) ----------

#[derive(Debug, Clone)]
struct RelaxedSec {
    in_name: String,
    addr: u64,
    out_size: u64,
    in_size: u64,
    obj: String, // "/path/lib.a(member.o)" or "/path/file.o"
}

fn parse_map(text: &str) -> Vec<RelaxedSec> {
    let mut out = Vec::new();
    let mut pending_name: Option<String> = None;
    let mut last: Option<RelaxedSec> = None;
    for line in text.lines() {
        let t = line.trim_start();
        // " .text.foo" alone on a line (long names wrap)
        if line.starts_with(" .") && !t.contains("0x") {
            pending_name = Some(t.to_string());
            continue;
        }
        // "(size before relaxing)" annotates the previous addr/size line
        if t.ends_with("(size before relaxing)") {
            if let (Some(mut sec), Some(sz)) = (last.take(), t.split_whitespace().next()) {
                if let Some(sz) = parse_hex(sz) {
                    sec.in_size = sz;
                    out.push(sec);
                }
            }
            continue;
        }
        // addr/size/obj line, either with inline name or following a bare-name line
        let mut words = t.split_whitespace();
        let (name, a) = if line.starts_with(" .") {
            (words.next().map(str::to_string), words.next())
        } else {
            (pending_name.take(), words.next())
        };
        let (Some(name), Some(a), Some(s), Some(obj)) = (name, a, words.next(), words.next())
        else {
            last = None;
            continue;
        };
        if let (Some(addr), Some(size)) = (parse_hex(a), parse_hex(s)) {
            last = Some(RelaxedSec { in_name: name, addr, out_size: size, in_size: 0, obj: obj.to_string() });
        } else {
            last = None;
        }
    }
    out
}

fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

// ---------- input-side extraction ----------

struct InputSec {
    bytes: Vec<u8>,
    /// byte positions covered by relocation fields (value may differ freely)
    mask: Vec<bool>,
    /// ranges that are literal words (whole .literal.* sections, or
    /// .xt.prop-flagged ranges inside text for gcc embedded literals)
    literal_ranges: Vec<(usize, usize)>,
}

fn load_input(obj_spec: &str, sec_name: &str, want_size: u64, v: bool) -> Result<InputSec, String> {
    let (path, member) = match obj_spec.split_once('(') {
        Some((p, m)) => (p.to_string(), Some(m.trim_end_matches(')').to_string())),
        None => (obj_spec.to_string(), None),
    };
    let file_data = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    let obj_data: Vec<u8> = match &member {
        Some(m) => {
            let ar = object::read::archive::ArchiveFile::parse(&*file_data)
                .map_err(|e| format!("archive {path}: {e}"))?;
            let mut found = None;
            for mem in ar.members() {
                let mem = mem.map_err(|e| e.to_string())?;
                if String::from_utf8_lossy(mem.name()) == *m {
                    found = Some(mem.data(&*file_data).map_err(|e| e.to_string())?.to_vec());
                    break;
                }
            }
            found.ok_or_else(|| format!("member {m} not in {path}"))?
        }
        None => file_data.clone(),
    };
    let obj = object::File::parse(&*obj_data).map_err(|e| format!("parse: {e}"))?;

    // same-named sections are legal; disambiguate by size
    let mut candidates: Vec<_> = obj
        .sections()
        .filter(|s| s.name().map(|n| n == sec_name).unwrap_or(false))
        .collect();
    if candidates.len() > 1 {
        candidates.retain(|s| s.size() == want_size);
    }
    if candidates.len() != 1 {
        return Err(format!("ambiguous-or-missing section ({} candidates)", candidates.len()));
    }
    let sec = &candidates[0];
    let bytes = sec.data().map_err(|e| e.to_string())?.to_vec();
    if bytes.len() as u64 != want_size {
        return Err(format!("input size {} != map before-relax {}", bytes.len(), want_size));
    }

    let mut mask = vec![false; bytes.len()];
    for (off, rel) in sec.relocations() {
        let n = match rel.size() {
            0 => 3, // xtensa SLOT*_OP relocs report size 0; mask the insn slot
            b => (b as usize) / 8,
        };
        for i in 0..n {
            if let Some(m) = mask.get_mut(off as usize + i) {
                *m = true;
            }
        }
    }

    let mut literal_ranges = Vec::new();
    if sec_name.contains(".literal") {
        literal_ranges.push((0, bytes.len()));
    } else {
        // gcc embedded literals: .xt.prop entries (addr,size,flags), flags&1,
        // addr field carries a reloc against the described section
        for prop in obj.sections().filter(|s| s.name().map(|n| n.starts_with(".xt.prop")).unwrap_or(false)) {
            let data = match prop.data() {
                Ok(d) => d,
                Err(_) => continue,
            };
            for (roff, rel) in prop.relocations() {
                let RelocationTarget::Symbol(si) = rel.target() else { continue };
                let Ok(sym) = obj.symbol_by_index(si) else { continue };
                if sym.section_index() != Some(sec.index()) {
                    continue;
                }
                let e = roff as usize; // entry start == addr field offset
                if e + 12 > data.len() {
                    continue;
                }
                let rd = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
                // RELA: offset lives in the addend, field bytes are zero
                let start = if rel.addend() != 0 { rel.addend() as u32 } else { rd(e) };
                let (size, flags) = (rd(e + 4), rd(e + 8));
                if flags & 1 != 0 && size > 0 {
                    literal_ranges.push((start as usize, (start + size) as usize));
                }
            }
        }
        literal_ranges.sort();
        literal_ranges.dedup();
    }
    if v {
        eprintln!("  input {} bytes, {} literal ranges", bytes.len(), literal_ranges.len());
    }
    Ok(InputSec { bytes, mask, literal_ranges })
}

// ---------- xtensa decode helpers (LE) ----------

fn insn_len(b: u8) -> Option<usize> {
    match b & 0x0F {
        0x0..=0x7 => Some(3),
        0x8..=0xD => Some(2),
        _ => None,
    }
}
fn is_l32r(i: &[u8]) -> bool {
    i.len() >= 3 && i[0] & 0x0F == 0x1
}
fn is_callx_or_jx(i: &[u8]) -> bool {
    // CALLX0/4/8/12 = [0xc0|0xd0|0xe0|0xf0, 0x0S, 0x00]; JX = [0xa0, 0x0S, 0x00]
    i.len() >= 3
        && i[2] == 0x00
        && i[1] & 0xF0 == 0x00
        && matches!(i[0], 0xc0 | 0xd0 | 0xe0 | 0xf0 | 0xa0)
}
fn is_call_or_j(o: &[u8]) -> bool {
    o.len() >= 3 && matches!(o[0] & 0x0F, 0x5 | 0x6)
}
fn is_nop3(i: &[u8]) -> bool {
    i.len() >= 3 && i[0] == 0xf0 && i[1] == 0x20 && i[2] == 0x00
}
fn is_nop2(i: &[u8]) -> bool {
    i.len() >= 2 && i[0] == 0x3d && i[1] == 0xf0
}
/// byte positions within a 3/2-byte insn that hold pc-relative immediates
/// ld rewrites in place (l32r, call/j, branches; density beqz.n/bnez.n)
fn pcrel_mask(i: &[u8]) -> u32 {
    match i[0] & 0x0F {
        0x1 => 0b110,                  // l32r: bytes 1,2
        0x5 | 0x6 => 0b111,            // call/j: offset spans all three (incl. byte0 high bits)
        0x7 => 0b100,                  // conditional branch: imm8 in byte 2
        0xC | 0xD => 0b10,             // beqz.n/bnez.n/movi.n: byte 1
        _ => 0,
    }
}

// ---------- the walk ----------

#[derive(Default, Debug)]
struct Counts {
    verbatim: usize,
    retarget: usize,
    longcall: usize,
    narrow: usize,
    widen: usize,
    fill: usize,
    unfill: usize,
    lit_del_words: usize,
}

enum Verdict {
    Reconciled(Counts, usize /* windows */),
    Refused { in_off: usize, out_off: usize, reason: String },
}

fn walk(inp: &InputSec, out: &[u8]) -> Verdict {
    let mut c = Counts::default();
    let mut windows = 0usize;
    match walk_from(inp, out, 0, 0, &mut c, &mut windows, 0) {
        Ok(()) => Verdict::Reconciled(c, windows),
        Err((i, o, r)) => Verdict::Refused { in_off: i, out_off: o, reason: r },
    }
}

fn walk_from(
    inp: &InputSec,
    out: &[u8],
    mut i: usize,
    mut o: usize,
    c: &mut Counts,
    windows: &mut usize,
    depth: usize,
) -> Result<(), (usize, usize, String)> {
    if depth > 64 {
        return Err((i, o, "literal backtrack depth".into()));
    }
    let inb = &inp.bytes;
    loop {
        // literal region: word-wise positional match. A masked word (has a
        // reloc) matches anything; an unmasked word must match by value or
        // it was deleted. Interior deletions handled naturally.
        if let Some(&(_ls, le)) = inp.literal_ranges.iter().find(|&&(ls, le)| i >= ls && i < le) {
            let mut in_window = false;
            while i + 4 <= le.min(inb.len()) {
                let masked = inp.mask[i..i + 4].iter().any(|&m| m);
                let matches = o + 4 <= out.len() && (masked || inb[i..i + 4] == out[o..o + 4]);
                if matches {
                    c.verbatim += 1;
                    i += 4;
                    o += 4;
                    in_window = false;
                } else {
                    c.lit_del_words += 1;
                    if !in_window {
                        *windows += 1;
                        in_window = true;
                    }
                    i += 4;
                }
            }
            i = le.min(inb.len());
            continue;
        }

        match (i < inb.len(), o < out.len()) {
            (false, false) => return Ok(()),
            (false, true) => {
                // output-only tail: fill
                if is_nop3(&out[o..]) {
                    c.fill += 1;
                    o += 3;
                    continue;
                }
                if is_nop2(&out[o..]) {
                    c.fill += 1;
                    o += 2;
                    continue;
                }
                if out[o] == 0 {
                    o += 1;
                    c.fill += 1;
                    continue;
                }
                return Err((i, o, "trailing output bytes".into()));
            }
            (true, false) => {
                // input-only tail: one end-deletion window (unreachable
                // trim / shadowed bytes); sizes were pre-sliced from the
                // map, so consuming the remainder is conservation-safe
                c.unfill += 1;
                *windows += 1;
                i = inb.len();
                continue;
            }
            (true, true) => {}
        }

        let li = match insn_len(inb[i]) {
            Some(l) if i + l <= inb.len() => l,
            _ => return Err((i, o, format!("undecodable input byte {:#04x}", inb[i]))),
        };
        let lo = match insn_len(out[o]) {
            Some(l) if o + l <= out.len() => l,
            _ => return Err((i, o, format!("undecodable output byte {:#04x}", out[o]))),
        };

        // longcall first: the l32r carries a SLOT0_OP reloc masking all
        // its bytes, so a masked compare would silently eat l32r-vs-call
        // and orphan the callx. Output opcode disambiguates: relaxed ->
        // call/j (op0 5/6); unrelaxed -> l32r (op0 1) falls through.
        if li == 3
            && is_l32r(&inb[i..])
            && i + 6 <= inb.len()
            && is_callx_or_jx(&inb[i + 3..])
            && is_call_or_j(&out[o..])
        {
            c.longcall += 1;
            *windows += 1;
            i += 6;
            o += 3;
            continue;
        }
        // same length: verbatim modulo masks / pc-rel fields
        if li == lo {
            let pm = pcrel_mask(&inb[i..i + li]);
            let mut clean = true;
            let mut used_pcrel = false;
            for k in 0..li {
                if inb[i + k] == out[o + k] || inp.mask[i + k] {
                    continue;
                }
                if pm >> k & 1 == 1 {
                    used_pcrel = true;
                    continue;
                }
                clean = false;
                break;
            }
            if clean {
                if used_pcrel {
                    c.retarget += 1
                } else {
                    c.verbatim += 1
                }
                i += li;
                o += lo;
                continue;
            }
        }
        // narrowing 3 -> 2 (structural only in v0)
        if li == 3 && lo == 2 {
            c.narrow += 1;
            *windows += 1;
            i += 3;
            o += 2;
            continue;
        }
        // widening 2 -> 3 (ld grows density insns to restore alignment)
        if li == 2 && lo == 3 {
            c.widen += 1;
            *windows += 1;
            i += 2;
            o += 3;
            continue;
        }
        // fill insertion in output
        if is_nop3(&out[o..]) || is_nop2(&out[o..]) {
            c.fill += 1;
            o += lo;
            continue;
        }
        // nop removal from input
        if is_nop3(&inb[i..]) || is_nop2(&inb[i..]) {
            c.unfill += 1;
            *windows += 1;
            i += li;
            continue;
        }
        return Err((i, o, format!("no transform explains in={:02x?} out={:02x?}", &inb[i..(i + li).min(inb.len())], &out[o..(o + lo).min(out.len())])));
    }
}

// ---------- driver ----------

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut map_p, mut elf_p, mut limit, mut verbose, mut filter) =
        (None::<PathBuf>, None::<PathBuf>, usize::MAX, false, None::<String>);
    let mut path_map = Vec::<(String, String)>::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--map" => map_p = args.next().map(Into::into),
            "--elf" => elf_p = args.next().map(Into::into),
            "--limit" => limit = args.next().and_then(|s| s.parse().ok()).unwrap_or(usize::MAX),
            "--filter" => filter = args.next(),
            "--path-map" => {
                if let Some((f, t)) = args.next().and_then(|s| s.split_once('=').map(|(a, b)| (a.to_string(), b.to_string()))) {
                    path_map.push((f, t));
                }
            }
            "-v" => verbose = true,
            other => {
                eprintln!("unknown arg {other}");
                std::process::exit(2);
            }
        }
    }
    let (map_p, elf_p) = (map_p.expect("--map"), elf_p.expect("--elf"));
    let map_text = std::fs::read_to_string(&map_p).expect("read map");
    let elf_data = std::fs::read(&elf_p).expect("read elf");
    let elf = object::File::parse(&*elf_data).expect("parse elf");

    let mut secs = parse_map(&map_text);
    if let Some(f) = &filter {
        secs.retain(|s| s.in_name.contains(f.as_str()) || s.obj.contains(f.as_str()));
    }
    eprintln!("{} relaxed sections in map", secs.len());

    let mut reconciled = 0usize;
    let mut totals = Counts::default();
    let mut total_windows = 0usize;
    let mut refusals: HashMap<String, usize> = HashMap::new();
    let mut load_errors: HashMap<String, usize> = HashMap::new();

    for sec in secs.iter().take(limit) {
        let mut obj = sec.obj.clone();
        for (f, t) in &path_map {
            obj = obj.replace(f.as_str(), t.as_str());
        }
        if verbose {
            eprintln!("== {} :: {} ({} -> {})", obj, sec.in_name, sec.in_size, sec.out_size);
        }
        let inp = match load_input(&obj, &sec.in_name, sec.in_size, verbose) {
            Ok(x) => x,
            Err(e) => {
                let key = e.split(':').next().unwrap_or("?").to_string();
                *load_errors.entry(key).or_default() += 1;
                continue;
            }
        };
        // output bytes from the linked image
        let Some(out_bytes) = elf.sections().find_map(|s| {
            let (a, sz) = (s.address(), s.size());
            (sec.addr >= a && sec.addr + sec.out_size <= a + sz)
                .then(|| s.data().ok().map(|d| d[(sec.addr - a) as usize..(sec.addr - a + sec.out_size) as usize].to_vec()))
                .flatten()
        }) else {
            *load_errors.entry("no-output-bytes".into()).or_default() += 1;
            continue;
        };
        match walk(&inp, &out_bytes) {
            Verdict::Reconciled(c, w) => {
                reconciled += 1;
                totals.verbatim += c.verbatim;
                totals.retarget += c.retarget;
                totals.longcall += c.longcall;
                totals.narrow += c.narrow;
                totals.widen += c.widen;
                totals.fill += c.fill;
                totals.unfill += c.unfill;
                totals.lit_del_words += c.lit_del_words;
                total_windows += w;
                if verbose {
                    eprintln!("  OK {c:?} windows={w}");
                }
            }
            Verdict::Refused { in_off, out_off, reason } => {
                if verbose {
                    eprintln!("  REFUSE @in+{in_off:#x}/out+{out_off:#x}: {reason}");
                }
                let key = reason.split(['[', '{']).next().unwrap_or("?").trim().to_string();
                *refusals.entry(key).or_default() += 1;
            }
        }
    }

    let attempted = reconciled + refusals.values().sum::<usize>();
    println!("\n=== relaxwalk results ===");
    println!("attempted: {attempted}   reconciled: {reconciled} ({:.1}%)", 100.0 * reconciled as f64 / attempted.max(1) as f64);
    println!("actions: {totals:?}");
    println!("deletion windows: {total_windows}");
    let mut r: Vec<_> = refusals.into_iter().collect();
    r.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (k, n) in r.iter().take(12) {
        println!("refused[{n}]: {k}");
    }
    let mut l: Vec<_> = load_errors.into_iter().collect();
    l.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (k, n) in l {
        println!("load-skip[{n}]: {k}");
    }
}
