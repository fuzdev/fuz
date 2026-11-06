# Deferred Items

Ideas evaluated and intentionally deferred. Not forgotten, just not worth the
complexity now.

Security deferrals are ./deferred_security.md. There is deliberately no
S3-compatible storage backend (./storage_backends.md).

---

## Windows support

No Windows users; it would add conditional compilation throughout
(./platform_support.md has what it would take). **Revisit when** Windows
deployment is a requirement.

---

## Further workload kinds

fuzd's built kinds are the observer and the watcher. Further kinds, ranked
ahead of the dormant sidecar kind: a memo cache (content-addressed
`(function, input) → output` lookups), a fact store host, and a language-server
host. **Revisit when** a consumer needs one.

---

## XDG directories

Mapping `~/.fuz` onto XDG: `config/` → `$XDG_CONFIG_HOME/fuz`, `state/` →
`$XDG_STATE_HOME/fuz`, `cache/` → `$XDG_CACHE_HOME/fuz`, `run/` →
`$XDG_RUNTIME_DIR/fuz` (truly ephemeral, where `run/` today survives reboots
for crash recovery); `bin/` has no clean mapping. **Revisit when** the
directory design stabilizes.

---

## Compile-time RPC Dispatch

**For type-safe routing.** Proc-macro to generate method routing from trait
definitions.

**Why deferred**: The hand-written dispatch `match` is clear at its current size.
Proc-macro adds compile-time complexity and makes debugging harder.

**Revisit when**: the request kinds reach about 30, or routing errors become
common.

---

## Prune that reads the release log

**For keeping what a log pointer names.** A `cargo xtask prune --log-repo` that
reads the release log's `latest/` pointers and keeps every release they name,
the way it keeps the ones the `latest-<target>.json` pointers name.

**Why deferred**: storage holds no pointer to the log, so prune cannot see one
without a log clone, and the failure it would prevent fails closed:
`install.sh` with `FUZ_RELEASE_LOG_URL` set gets a 404 for a pruned flat binary
and refuses. The workaround is in ./release_workflow.md § Pruning Old Releases.

**Revisit when**: a public release log is live and revokes happen in practice.

---

## Cross-compilation

**For `fuz artifact build --target <triple>`.** The publish side is done:
`cargo xtask publish` and `fuzf tool publish` take `--target`, every binary's
header is held to it, and each target has its own keys and latest pointer
(./release_workflow.md § Publishing for another target). The build side is
not: `fuz artifact build` builds for the host only and refuses a binary cargo
built for another target (`CARGO_BUILD_TARGET`, a `build.target`). It would
pass `--target` to cargo and record the target in the artifact's metadata; it
needs a cross toolchain (rustup target, linker config), an explicit target in
the hash inputs (today the `rustc -vV` host triple), and per-target artifact
storage (`<hash>-<target>/`, or the target in `meta.json`).

**Revisit when**: distributing pre-built binaries for multiple platforms.

---

## musl builds

**For `fuz`, `fuzd`, and the other binaries** — only `fuzi` builds for musl
(./platform_support.md § musl).

**Revisit when**: container or Alpine users ask for them.
