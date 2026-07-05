# 04 — Wire protocol (CLI ↔ running app)

Status: reference research on Dioxus's Subsecond. graft does not use this
wire protocol (it flashes an ordinary ELF); kept for context.

The CLI needs to send the finished `JumpTable` and a reference to the patch
file to every running client. Dioxus uses a dedicated websocket endpoint via
the `devtools` / `devtools-types` crates.

## Messages

`packages/devtools-types/src/lib.rs`:

```rust
pub enum DevserverMsg {
    HotReload(HotReloadMsg),
    HotPatchStart,
    FullReloadStart,
    FullReloadFailed,
    FullReloadCommand,
    Shutdown,
}

pub struct HotReloadMsg {
    pub templates: Vec<HotReloadTemplateWithLocation>,
    pub assets: Vec<PathBuf>,
    pub ms_elapsed: u64,
    pub jump_table: Option<JumpTable>,
    pub for_build_id: Option<u64>,
    pub for_pid: Option<u32>,
}

pub enum ClientMsg {
    Log { level: String, messages: Vec<String> },
}
```

`HotReloadMsg` is a union of three orthogonal reloads: RSX templates
(zero-rebuild template-only edits), assets (CSS / images), and a binary
patch (the `JumpTable`). Any combination can be present; Dioxus always
tries template hotreload first and only falls through to the patch flow if
the RSX diff fails.

The transport is plain JSON over a websocket. The client connects with a
query string carrying its ASLR reference and PID so that the server can
build a patch targeting the exact process:

```
ws://<host>/_dioxus?aslr_reference=0x55f5a4c3b120&pid=12345&build_id=...
```

`packages/cli/src/serve/server.rs:302-357` formats and broadcasts the
`DevserverMsg`. The server keeps a table of connected clients and fans out
to all of them when a patch is ready.

## Client side

`packages/devtools/src/lib.rs:78-82`:

```rust
if let DevserverMsg::HotReload(msg) = msg {
    if let Some(jumptable) = msg.jump_table {
        unsafe { subsecond::apply_patch(jumptable).unwrap() };
    }
}
```

That's it on the receiving end. The devtools crate handles the websocket
plumbing but the actual patch application is one call into
`subsecond::apply_patch`.

Note that the websocket ships the `JumpTable` struct — which includes a
`PathBuf` — *not* the patch binary bytes. The client is expected to be able
to read the path the CLI wrote. On desktop that's the shared filesystem; on
Android the CLI adb-pushes the file first; on iOS the simulator shares the
filesystem. On WASM the path is a URL and `apply_patch` `fetch`es it.

## ASLR reference exchange

The client reports its `aslr_reference` (its own in-process address of
`main`) via the query string on connect. The server stashes it and uses it
when calling `create_native_jump_table` / `create_wasm_jump_table`. Without
this, patches would have the wrong absolute addresses baked into the
undefined-symbol stubs (see `03-build-pipeline.md`).

On reconnect with a different `aslr_reference` (e.g. user restarted the
app), any queued patches for the old address are discarded. The server only
keeps patches valid for the *current* fat binary + *current* ASLR slide.

## Failure modes

- **Patch doesn't apply**: `apply_patch` returns `PatchError::Dlopen(_)`.
  Client can reconnect and request a `FullReloadCommand`.
- **Fat binary changed** (unrelated to patches — e.g. user added a new
  dependency): server emits `FullReloadStart`, builds a new fat binary,
  restarts the app, emits `FullReloadCommand` so the client wipes state.
- **RSX diff fails**: server sends templates-empty HotReload and sets
  `needs_full_rebuild = true` on the builder; next build is a full rebuild
  rather than a patch.

## What this means for our use case

The protocol is deliberately generic. The relevant pieces:

- `JumpTable` serde-serializes cleanly. JSON over websockets is fine but not
  essential.
- The client doesn't need Dioxus at all — it just needs a way to receive a
  `HotReloadMsg` and call `subsecond::apply_patch`. For embedded we can
  substitute the transport (UART, TCP, HTTP POST, OTA partition write…)
  and keep the rest.
- The file-path assumption is the one thing that breaks down off-PC. For
  ESP32 we'll push the bytes directly and have the on-device apply_patch
  variant work from bytes rather than a path.
