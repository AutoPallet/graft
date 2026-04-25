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

struct Fixture {
    dir: PathBuf,
    original_lib: String,
    original_main: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../e2e/x86")
            .canonicalize()
            .expect("canonicalize e2e/x86 fixture path");
        let original_lib = std::fs::read_to_string(dir.join("base/src/lib.rs")).unwrap();
        let original_main = std::fs::read_to_string(dir.join("app/src/main.rs")).unwrap();
        Fixture { dir, original_lib, original_main }
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
        let clean = Command::new("cargo")
            .current_dir(&self.dir)
            .args(["clean", "-p", "app"])
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
        let deps = self.dir.join("target/x86_64-unknown-linux-musl/debug/deps");
        for e in std::fs::read_dir(&deps).unwrap_or_else(|_| panic!("read {}", deps.display())) {
            let p = e.unwrap().path();
            if p.is_dir() && p.extension().and_then(|s| s.to_str()) == Some("graft-work") {
                let stats_path = p.join("combine-stats.json");
                let s = std::fs::read_to_string(&stats_path)
                    .unwrap_or_else(|_| panic!("read {}", stats_path.display()));
                return Stats::parse(&s);
            }
        }
        panic!("no *.graft-work dir inside {}", deps.display());
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
    }
}

fn make_executable(p: &Path) {
    let mut perms = std::fs::metadata(p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(p, perms).unwrap();
}

fn run_combined(path: &Path) -> String {
    let out = Command::new(path).output().expect("exec combined");
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

    // Base build.
    fx.cargo_build(&[("GRAFT", "base")]);
    let base_elf = std::env::temp_dir().join("graft-e2e-base.elf");
    std::fs::copy(fx.app_bin(), &base_elf).unwrap();
    make_executable(&base_elf);
    let base_out = run_combined(&base_elf);
    assert!(base_out.contains("hello, graft!"), "baseline: {base_out}");
    assert!(base_out.contains("sum = 105"), "baseline: {base_out}");
    assert!(base_out.contains("mixed = 14280"), "baseline: {base_out}");

    let base_env = base_elf.to_string_lossy().into_owned();
    let overlay_env = [("GRAFT", "overlay"), ("GRAFT_BASE_ELF", base_env.as_str())];

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

    // D. No-op: sources match base. 0 trampolines, combined ≡ base.
    fx.cargo_build(&overlay_env);
    assert_eq!(fx.combine_stats().trampolines, 0, "D: trampoline count");
    assert_eq!(
        std::fs::read(&base_elf).unwrap(),
        std::fs::read(&fx.app_bin()).unwrap(),
        "D: combined should be byte-identical to base",
    );
}
