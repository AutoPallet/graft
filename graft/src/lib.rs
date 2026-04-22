//! graft — incremental compilation overlays for bare-metal Rust.
//!
//! This library surface mirrors the binary's entry points so integration
//! tests can drive work in-process. See `docs/06-graft-wrapper.md`.

pub mod archive;
pub mod elf;
pub mod graph;
pub mod hash;
pub mod metadata;
pub mod scan;

pub use metadata::{GraftManifest, SymHashEntry, GRAFT_MAGIC, SCHEMA_VERSION};
