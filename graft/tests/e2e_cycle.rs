//! End-to-end cycle test: base build → edit → overlay build → run.
//!
//! With single-ELF mode, overlay's link produces the combined ELF
//! directly at cargo's `-o` path (the underlying combine logic still
//! lives in `combine.rs` and is exercised internally). No separate
//! `graft combine` invocation needed for the normal build loop.
//!
//! Ignored by default because it shells out to `cargo build` twice per
//! scenario. Run with:
//!
//!   cargo test -p graft --test e2e_cycle -- --ignored --nocapture
//!
//! Requires:
//!   - `cargo` on PATH, with the `x86_64-unknown-linux-musl` target
//!     installed (`rustup target add x86_64-unknown-linux-musl`).
//!   - A built `graft` binary at `target/debug/graft` (cargo test
//!     produces this as a side-effect when testing this package).
//!
//! The test mutates fixture source files in-place and restores them on
//! completion (even on panic, via Drop). Do not run concurrently with
//! another test touching `e2e/x86/`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

/// Both tests mutate the single `e2e/x86/` fixture in place and exec the
/// same combined binary, so they cannot run concurrently — a parallel
/// run produces confusing "Text file busy" / "fixture missing … stale?"
/// failures as one test's edit (or its Drop-time restore) clobbers the
/// other's. Serialize them on a process-wide lock instead of relying on
/// the caller to pass `--test-threads=1`. Poison-tolerant: a panicking
/// test still releases the fixture for the next one.
static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

fn lock_fixture() -> MutexGuard<'static, ()> {
    FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

struct Fixture {
    dir: PathBuf,
    original_lib: String,
    original_main: String,
    original_inner: String,
    _guard: MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let _guard = lock_fixture();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../e2e/x86")
            .canonicalize()
            .expect("canonicalize e2e/x86 fixture path");
        let original_lib = std::fs::read_to_string(dir.join("base/src/lib.rs")).unwrap();
        let original_main = std::fs::read_to_string(dir.join("app/src/main.rs")).unwrap();
        let original_inner = std::fs::read_to_string(dir.join("base/cshim/inner.c")).unwrap();
        Fixture { dir, original_lib, original_main, original_inner, _guard }
    }

    fn edit(&self, rel: &str, from: &str, to: &str) {
        let path = self.dir.join(rel);
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.contains(from), "fixture {rel} missing {from:?} — stale?");
        std::fs::write(&path, s.replace(from, to)).unwrap();
    }

    fn cargo_build(&self, env: &[(&str, &str)]) {
        // Cargo doesn't track env vars like `GRAFT`, so switching between
        // base and overlay mode with unchanged sources wouldn't trigger
        // a relink. Clean `app` specifically (leaving `base`'s rlib
        // cached — it's not mode-sensitive) so cargo re-invokes graft.
        // The fixture's `.cargo/config.toml` pins target=musl, so we
        // must pass `--target` to clean — `cargo clean -p app` alone
        // only touches the host target dir, leaving stale binaries
        // (notably prior overlay-mode combined ELFs) under the musl
        // target dir and cargo treating the build as fresh.
        let clean = Command::new("cargo")
            .current_dir(&self.dir)
            .args(["clean", "-p", "app", "--target", "x86_64-unknown-linux-musl"])
            .output()
            .expect("spawn cargo clean");
        assert!(clean.status.success(), "cargo clean -p app failed");

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&self.dir).args(["build", "--bin", "app"]);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("spawn cargo");
        if !out.status.success() {
            panic!(
                "cargo build failed ({:?})\nstderr:\n{}",
                env,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    fn combine_stats(&self) -> Stats {
        let work_dir = self.graft_work_dir();
        let stats_path = work_dir.join("combine-stats.json");
        let s = std::fs::read_to_string(&stats_path)
            .unwrap_or_else(|_| panic!("read {}", stats_path.display()));
        Stats::parse(&s)
    }

    fn graft_work_dir(&self) -> PathBuf {
        let deps = self.dir.join("target/x86_64-unknown-linux-musl/debug/deps");
        for e in std::fs::read_dir(&deps).unwrap_or_else(|_| panic!("read {}", deps.display())) {
            let p = e.unwrap().path();
            if p.is_dir() && p.extension().and_then(|s| s.to_str()) == Some("graft-work") {
                return p;
            }
        }
        panic!("no *.graft-work dir inside {}", deps.display());
    }

    fn graft_log_path(&self) -> PathBuf {
        self.dir.join("target").join("graft-summary.log")
    }

    /// Read graft's overlay summary line (which carries closure-size,
    /// payload-size, per-phase timings) from the GRAFT_LOG sidecar
    /// the most recent overlay run wrote.
    fn graft_summary(&self) -> String {
        let log = self.graft_log_path();
        std::fs::read_to_string(&log)
            .unwrap_or_else(|_| panic!("read {}", log.display()))
    }

    /// Pull `closure N sections` out of the graft summary.
    fn closure_sections(&self) -> usize {
        let s = self.graft_summary();
        let key = "closure ";
        let i = s.find(key).expect("no `closure ` in graftlog");
        let rest = &s[i + key.len()..];
        let n_end = rest.find(' ').expect("no space after closure number");
        rest[..n_end].parse().expect("closure size not numeric")
    }

    /// Pull `overlay payload N` out of the graft summary.
    fn overlay_payload(&self) -> usize {
        let s = self.graft_summary();
        let key = "overlay payload ";
        let i = s.find(key).expect("no `overlay payload ` in graftlog");
        let rest = &s[i + key.len()..];
        let n_end = rest.find(' ').expect("no space after payload number");
        rest[..n_end].parse().expect("payload size not numeric")
    }

    fn app_bin(&self) -> PathBuf {
        self.dir.join("target/x86_64-unknown-linux-musl/debug/app")
    }
}

/// Just the bits we need to assert on. Hand-parsed from the JSON
/// sidecar so this test stays free of serde dependencies.
struct Stats {
    trampolines: usize,
}

impl Stats {
    fn parse(s: &str) -> Self {
        let key = "\"trampolines\":[";
        let start = s.find(key).expect("no trampolines key") + key.len();
        let end = start
            + s[start..]
                .find(']')
                .expect("unclosed trampolines array");
        let body = &s[start..end];
        let trampolines = if body.trim().is_empty() {
            0
        } else {
            body.matches("\"name\"").count()
        };
        Stats { trampolines }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::write(self.dir.join("base/src/lib.rs"), &self.original_lib);
        let _ = std::fs::write(self.dir.join("app/src/main.rs"), &self.original_main);
        let _ = std::fs::write(self.dir.join("base/cshim/inner.c"), &self.original_inner);
    }
}

fn make_executable(p: &Path) {
    let mut perms = std::fs::metadata(p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(p, perms).unwrap();
}

fn run_combined(path: &Path) -> String {
    let out = Command::new(path).output().expect("exec combined");
    eprintln!("run_combined({}): status={:?} stdout-len={} stderr-len={}", path.display(), out.status, out.stdout.len(), out.stderr.len());
    assert!(
        out.status.success(),
        "combined exited {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore]
fn full_cycle() {
    let fx = Fixture::new();

    // Base build. GRAFT_MAP_ORACLE makes base verify every recovered
    // section address against the linker's own map — the no-hardware
    // ground-truth check for the address-recovery machinery.
    fx.cargo_build(&[("GRAFT", "base"), ("GRAFT_MAP_ORACLE", "1")]);
    let base_elf = std::env::temp_dir().join("graft-e2e-base.elf");
    std::fs::copy(fx.app_bin(), &base_elf).unwrap();
    make_executable(&base_elf);
    let base_out = run_combined(&base_elf);
    assert!(base_out.contains("hello, graft!"), "baseline: {base_out}");
    assert!(base_out.contains("sum = 105"), "baseline: {base_out}");
    assert!(base_out.contains("mixed = 14280"), "baseline: {base_out}");
    assert!(base_out.contains("ticks = 1,1,2,2"), "baseline: {base_out}");
    assert!(base_out.contains("cycle = 10,21"), "baseline: {base_out}");
    assert!(base_out.contains("tls = 42,1,44,2,45,1"), "baseline: {base_out}");

    let base_env = base_elf.to_string_lossy().into_owned();
    let log_path = fx.graft_log_path();
    let log_env_owned = log_path.to_string_lossy().into_owned();
    let overlay_env = [
        ("GRAFT", "overlay"),
        ("GRAFT_BASE_ELF", base_env.as_str()),
        ("GRAFT_LOG", log_env_owned.as_str()),
    ];

    // A. Leaf: edit compute. Cascades up to mix, app::main, main. Every
    //    nonempty-closure rebuild yields exactly 1 trampoline — at base's
    //    entry symbol (main). All inner cross-section calls are resolved
    //    inside overlay's own link.
    fx.edit("base/src/lib.rs", "wrapping_mul(7)", "wrapping_mul(13)");
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 1, "A: trampoline count");
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("sum = 195"), "A: {out}");
    assert!(out.contains("mixed = 26520"), "A: {out}");
    fx.edit("base/src/lib.rs", "wrapping_mul(13)", "wrapping_mul(7)");

    // B. Mid-graph: edit mix only (compute stays). `compute` is NOT in
    //    the closure because its trans_hash is unchanged.
    fx.edit("base/src/lib.rs", "rotate_left(3)", "rotate_left(5)");
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 1, "B: trampoline count");
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("sum = 105"), "B (compute unchanged): {out}");
    assert!(out.contains("mixed = 57120"), "B: {out}");
    fx.edit("base/src/lib.rs", "rotate_left(5)", "rotate_left(3)");

    // C. Top: edit app only. Base unchanged.
    fx.edit("app/src/main.rs", r#"greet("graft")"#, r#"greet("world")"#);
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 1, "C: trampoline count");
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("hello, world!"), "C: {out}");
    fx.edit("app/src/main.rs", r#"greet("world")"#, r#"greet("graft")"#);

    // D. No-op: sources match base. Closure must be empty (the
    // invariant: same scan inputs produce identical trans_hashes →
    // every reachable section classifies as Provided), 0 trampolines,
    // combined ≡ base.
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.closure_sections(), 0, "D: closure must be empty for no-op");
    assert_eq!(fx.combine_stats().trampolines, 0, "D: trampoline count");
    assert_eq!(
        std::fs::read(&base_elf).unwrap(),
        std::fs::read(&fx.app_bin()).unwrap(),
        "D: combined should be byte-identical to base",
    );

    // F. Mutable-static identity (the M2 xtensa call-to-0 shape):
    //    re-emit `tick` while TICK / COUNT (two content-degenerate
    //    zero-init statics) stay base-resident. The re-emitted code's
    //    relocs must bind each static to ITS OWN base address — if the
    //    two aliased, the atomic would observe the counter's writes and
    //    the pairs would diverge from (2,1),(4,2).
    fx.edit(
        "base/src/lib.rs",
        "TICK.wrapping_add(step)",
        "TICK.wrapping_add(step.wrapping_mul(2))",
    );
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 1, "F: trampoline count");
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("ticks = 2,1,4,2"), "F (statics must not alias): {out}");
    assert!(out.contains("cycle = 10,21"), "F: {out}");
    fx.edit(
        "base/src/lib.rs",
        "TICK.wrapping_add(step.wrapping_mul(2))",
        "TICK.wrapping_add(step)",
    );

    // G. Section-cycle identity (the M2 xtensa code↔literal-pool
    //    shape): re-emit `cycle_run` while STEP_TABLE ↔ step_a (one
    //    SCC, two sections) stay base-resident. The re-emitted code's
    //    reference must land on the table, not on the cycle's other
    //    member — a shared SCC hash would make the two
    //    indistinguishable and resolution could return either address.
    fx.edit("base/src/lib.rs", ".wrapping_add(0)", ".wrapping_add(100)");
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 1, "G: trampoline count");
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("cycle = 110,121"), "G (cycle members must stay distinct): {out}");
    assert!(out.contains("ticks = 1,1,2,2"), "G: {out}");
    fx.edit("base/src/lib.rs", ".wrapping_add(100)", ".wrapping_add(0)");

    // H. TLS reference (docs/15 mechanism (c)): re-emit `tl_step` while
    //    TL_ACC / TL_ZERO stay base-resident. The re-emitted code's
    //    TPOFF relocs anchor into graft's SHF_TLS map sections and ld
    //    recomputes the SAME TP offsets from the reproduced template
    //    geometry — wrong offsets would scramble both counters, and a
    //    geometry mismatch fails the overlay link.
    fx.edit("base/src/lib.rs", "wrapping_add(n));", "wrapping_add(n.wrapping_mul(3)));");
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 1, "H: trampoline count");
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("tls = 46,1,52,2,55,1"), "H (TLS refs must keep offsets): {out}");
    assert!(out.contains("ticks = 1,1,2,2"), "H: {out}");
    fx.edit("base/src/lib.rs", "wrapping_add(n.wrapping_mul(3)));", "wrapping_add(n));");

    // I. TLS initializer edit: TL_ACC's `.tdata` content changes → the
    //    section re-emits into the GRAFT_TLS_SLACK hole (a NEW template
    //    offset), and `tl_step` re-emits with it (its hash changes
    //    transitively). The spawned thread proves the new initializer
    //    landed in the template bytes every thread copies — splice
    //    wrote it into base's in-template slack file range.
    fx.edit("base/src/lib.rs", "Cell::new(40)", "Cell::new(60)");
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 1, "I: trampoline count");
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("tls = 62,1,64,2,65,1"), "I (initializer must reach template): {out}");
    fx.edit("base/src/lib.rs", "Cell::new(60)", "Cell::new(40)");

    // J. NEW thread-local in an edit, used alongside base-resident
    //    ones: TL_NEW (non-zero init → .tdata) lands in the slack
    //    hole at an ld-assigned offset while TL_ACC/TL_ZERO references
    //    still anchor into the TLS maps — one function mixing both
    //    resolution paths. k: 7→8 (call 1), →9 (call 2); fresh thread
    //    sees the template's 7 again.
    fx.edit(
        "base/src/lib.rs",
        "static TL_ZERO: Cell<u32> = const { Cell::new(0) };",
        "static TL_ZERO: Cell<u32> = const { Cell::new(0) };\n    \
         static TL_NEW: Cell<u32> = const { Cell::new(7) };",
    );
    fx.edit(
        "base/src/lib.rs",
        "c.set(c.get().wrapping_add(1));",
        "c.set(c.get().wrapping_add(TL_NEW.with(|k| { k.set(k.get().wrapping_add(1)); k.get() })));",
    );
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 1, "J: trampoline count");
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("tls = 42,8,44,17,45,8"), "J (new thread-local in slack): {out}");
    fx.edit(
        "base/src/lib.rs",
        "c.set(c.get().wrapping_add(TL_NEW.with(|k| { k.set(k.get().wrapping_add(1)); k.get() })));",
        "c.set(c.get().wrapping_add(1));",
    );
    fx.edit(
        "base/src/lib.rs",
        "static TL_ZERO: Cell<u32> = const { Cell::new(0) };\n    \
         static TL_NEW: Cell<u32> = const { Cell::new(7) };",
        "static TL_ZERO: Cell<u32> = const { Cell::new(0) };",
    );
}

/// The single-trampoline cut, x86 edition (no hardware): with the entry
/// symbol on `cshim_inner`, an edit to inner.c must re-emit inner.o but
/// NOT outer.o — outer reaches the new code through the trampoline at
/// base's `cshim_inner`, exactly how esp32's `main` reaches an edited
/// `graft_entry`. This is the "function above the entry is not
/// re-emitted" invariant as a checked assertion instead of a closure-dump
/// eyeball.
#[test]
#[ignore]
fn entry_cut_keeps_caller_in_base() {
    let fx = Fixture::new();

    fx.cargo_build(&[
        ("GRAFT", "base"),
        ("GRAFT_ENTRY_SYMBOL", "cshim_inner"),
        ("GRAFT_MAP_ORACLE", "1"),
    ]);
    let base_elf = std::env::temp_dir().join("graft-e2e-entrycut-base.elf");
    std::fs::copy(fx.app_bin(), &base_elf).unwrap();
    make_executable(&base_elf);
    let base_out = run_combined(&base_elf);
    assert!(base_out.contains("cshim = 149"), "baseline: {base_out}");

    let base_env = base_elf.to_string_lossy().into_owned();
    let log_env = fx.graft_log_path().to_string_lossy().into_owned();
    fx.edit("base/cshim/inner.c", "* 7u + 1u", "* 7u + 2u");
    fx.cargo_build(&[
        ("GRAFT", "overlay"),
        ("GRAFT_BASE_ELF", base_env.as_str()),
        ("GRAFT_LOG", log_env.as_str()),
    ]);
    assert_eq!(fx.combine_stats().trampolines, 1, "trampoline at cshim_inner");
    let dump = fx.graft_summary();
    assert!(dump.contains("inner"), "closure must re-emit inner.o:\n{dump}");
    assert!(
        !dump.contains("outer"),
        "trampoline cut: outer.o (the caller above the entry) must NOT be re-emitted:\n{dump}"
    );
    let out = run_combined(&fx.app_bin());
    assert!(out.contains("cshim = 151"), "edited inner, via base's outer + trampoline: {out}");
    assert!(out.contains("sum = 105"), "rest of base unchanged: {out}");
}

/// For small, focused source mutations, graft's *overlay payload*
/// (the bytes that get spliced/appended into the combined ELF and
/// flashed) should be proportional to the source change — a few
/// hundred bytes to a few KB, not megabytes. The closure section
/// count itself is less interesting (it can include linker-noise
/// inputs like `.note.gnu.property` that pass through to overlay's
/// link as KEEP()'d but don't materially inflate the output), so we
/// assert on payload bytes and leave room for the closure to carry
/// dozens of trivial-pass-through sections.
///
/// This test mirrors the M1.q.1 roborack3 mutation matrix on x86 so
/// we can iterate the canonicalization fixes locally.
#[test]
#[ignore]
fn payload_sizes_for_typical_edits() {
    let fx = Fixture::new();
    let log_path = fx.graft_log_path();

    fx.cargo_build(&[("GRAFT", "base"), ("GRAFT_MAP_ORACLE", "1")]);
    let base_elf = std::env::temp_dir().join("graft-e2e-tight-base.elf");
    std::fs::copy(fx.app_bin(), &base_elf).unwrap();
    make_executable(&base_elf);

    let base_env_owned = base_elf.to_string_lossy().into_owned();
    let log_env_owned = log_path.to_string_lossy().into_owned();
    let overlay_env: &[(&str, &str)] = &[
        ("GRAFT", "overlay"),
        ("GRAFT_BASE_ELF", base_env_owned.as_str()),
        ("GRAFT_LOG", log_env_owned.as_str()),
    ];

    // Loose ceiling: any small-source-mutation overlay should fit in
    // 4 KB. Anything more means a real cascade — trans_hash
    // canonicalization is letting name-noise propagate through the
    // SCC graph and pulling unrelated sections into the closure.
    // 4 KB is comfortably above what each scenario actually
    // produces (A/B/C ~1 KB, D ~1.5 KB) — adjust down if any
    // scenario regresses well below.
    const TIGHT: usize = 4096;

    let mut report = Vec::<(&str, usize, usize)>::new();
    let mut run = |label: &'static str| {
        fx.cargo_build(overlay_env);
        let n = fx.closure_sections();
        let p = fx.overlay_payload();
        println!("{label}: closure={n} payload={p}");
        report.push((label, n, p));
        assert!(
            p <= TIGHT,
            "{label} payload={p} > {TIGHT} — cascade pulled \
             unrelated content into the overlay output"
        );
    };

    // A. leaf arithmetic edit (no new strings/format).
    fx.edit("base/src/lib.rs", "wrapping_mul(7)", "wrapping_mul(13)");
    run("A leaf-arith");
    fx.edit("base/src/lib.rs", "wrapping_mul(13)", "wrapping_mul(7)");

    // B. mid-graph edit (mix). compute stays.
    fx.edit("base/src/lib.rs", "rotate_left(3)", "rotate_left(5)");
    run("B mid-graph");
    fx.edit("base/src/lib.rs", "rotate_left(5)", "rotate_left(3)");

    // C. top-level edit (app/main, base unchanged).
    fx.edit("app/src/main.rs", r#"greet("graft")"#, r#"greet("world")"#);
    run("C top-edit");
    fx.edit("app/src/main.rs", r#"greet("world")"#, r#"greet("graft")"#);

    // D. introduce a format/println call into a function that
    //    previously had none. This is the roborack3 fallback-string
    //    pattern. Format infra is already in base (app uses println!
    //    everywhere); reaching it from compute should hit Provided
    //    after one hop, not cascade through everything.
    fx.edit(
        "base/src/lib.rs",
        "    acc\n}",
        "    println!(\"compute trace acc={acc}\");\n    acc\n}",
    );
    run("D introduce-format");
    fx.edit(
        "base/src/lib.rs",
        "    println!(\"compute trace acc={acc}\");\n    acc\n}",
        "    acc\n}",
    );

    // E. change a string literal in a function that already uses
    //    format (greet uses `format!`).
    fx.edit("base/src/lib.rs", r#""hello, {name}!""#, r#""HOWDY, {name}!""#);
    run("E string-edit");
    fx.edit("base/src/lib.rs", r#""HOWDY, {name}!""#, r#""hello, {name}!""#);
}
