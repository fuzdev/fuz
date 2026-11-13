# Fuz

> the fuz CLI, fuzd daemon, and Rust crates beneath the Fuz stack's servers

A Rust workspace: the `fuz` CLI (installs signed first-party tools), the
optional `fuzd` daemon (demand-driven workloads), the `fuzi` npm installer,
and the shared spine crates that server apps build on.

## Scope

**fuz is a tool that installs other tools** — minimal, Rust-only, no HTTP
server, no embedded JS runtime. It installs only what is inside its **seal**:
signed, blake3-pinned, audited @fuzdev artifacts. Things that look like part of
fuz from outside are *separate binaries fuz installs*:

- `fuzd` — the daemon. Built in this repo but installed separately: the fuz
  self artifact is fuz-only, and fuzd lands under `~/.fuz/tools/fuzd/` via
  `cargo xtask install` (dev) or `fuz tool install fuzd`. An **optional dep**:
  `fuz self` / `tool` / `artifact` work standalone; `fuz workload observe`, the
  one fuzd-backed surface, fails with a `fuzd start` hint when the daemon isn't
  reachable.
- `fuzi` — pragmatic lockfile-driven npm installer (pnpm's mold, non-resolving).
  Reads npm's `package-lock.json` v2 and v3 (through their shared `packages`
  map; a lock without one refuses); its own `fuzi.lock` is planned; the
  lockfile surface is closed at those two (no pnpm/bun/deno). fuzi sits on
  the seal's edge: it is a first-party tool (signed, installed with
  `fuz tool install fuzi` once published), but the npm trees it installs are
  trust-anchored only by npm's integrity metadata.
- Planned, not built: `fuzp` (a pure-registry package manager, installs only
  inside the seal), `fuzb` (a Vite replacement), and the `fuz_registry` crate.
- `zap`, `zzz`, `tsv` — installable via `fuz tool install` once published (the
  `FIRST_PARTY_TOOLS` allowlist, which also reserves names for unbuilt tools).

fuzd's organizing primitive is the **workload** — a long-running thing tied to
client demand, over a generic registry (refcount / idle-grace / sharing) with
streaming responses. Built kinds: the **observer** (poll-driven process /
network / services sampler) and the **watcher** (event-driven
`notify`/inotify filesystem watch, one watcher serving many clients). The
sidecar kind is dormant (§ Sidecar workload); other kinds wait on a consumer.

**No surprising hidden behavior.** fuz never installs, modifies, or runs
anything the user didn't explicitly request: a config change doesn't trigger
an install, a workload registration doesn't auto-install its dependencies (it
errors with an actionable hint), `fuz self bootstrap` doesn't chain a fuzd
install. fuz doesn't **proxy** another binary's CLI under `fuz <noun>` (no
`fuz daemon start`), and doesn't **delegate** — it never shells out to another
tool on the user's behalf. Its subprocesses are the dev-path `fuz artifact
build`'s toolchain (`cargo`, `rustc -vV`, `git`), the `ssh` / `scp` transport
of an `ssh://` store, and a `fish --version` probe in `self bootstrap`. Out of
scope → name the right tool in the error and stop.

**fuz vs Zap trust boundary is strict.** fuz installs only inside its seal; Zap
bridges to arbitrary code with the supply-chain surface that entails. The
boundary holds because fuz declines to grow general-installer capability.

**CLI grammar: noun-first uniform.** Every `fuz` verb hangs off a typed noun —
`self`, `tool`, `artifact`, `workload` — with no bare-verb top-level forms.
Signing is publisher-only (`cargo xtask key …`, `cargo xtask publish`); end
users only verify, automatically, during install/upgrade. Daemon lifecycle is
fuzd's own CLI. No command aliases: predictable mistakes (`fuz install <name>`,
`fuz bootstrap`, `fuz daemon …`) print "did you mean …?" and exit 2.

## Status

Pre-alpha. Built: daemon lifecycle, the workload registry with its observer and
watcher kinds, the dormant sidecar machinery, artifact management, Ed25519
signing (producer side in `fuz_sign`; `fuz` verifies only), storage backends
(local / `forge://` / `ssh://` / read-only `https://`; deliberately no S3), and
distribution (fetch/verify/upgrade on `fuz`; producing on `fuzf` — the
[fuz_forge](https://github.com/fuzdev/fuz_forge) CLI — and `xtask`).

- **Validated end to end**: the `ssh://` loop on a real OpenSSH host (signed
  publish → fetch → verify → install; the `#[ignore]` `fuz_storage`
  `test_ssh_round_trip` and `fuz_sign` `signed_trust_ssh` suites), and the
  `forge://` read path against a live fuz_forge.
- **Not yet**: `install.sh` on a clean host (implemented, with a local e2e
  harness); the hosted install channel (nothing published to fetch); the
  `https://` backend against a live TLS host (loopback tests only); a public
  release log (the check is built and inactive unless `FUZ_RELEASE_LOG_URL` is
  set).

## Docs

Start with ./docs/fuz_home.md (layout) and ./docs/daemon_lifecycle.md (the
daemon); read the rest as needed.

- ./docs/crates.md — per-crate reference: purpose, boundaries, cross-crate
  rules, consumers, error rendering
- ./docs/testing.md — CI jobs, the Postgres suites recipe, the cross-backend
  suite, known flakes
- ./docs/fuz_home.md — the `~/.fuz/` layout, run vs state, PATH setup
- ./docs/daemon_lifecycle.md — daemon state machine, health check, graceful
  shutdown
- ./docs/artifacts.md — the two-hash model, build flow, verification,
  store-entry policy
- ./docs/signing.md — Ed25519 keys, signature format, key files
- ./docs/security-model.md — trust model, bootstrap, rollback, key compromise
- ./docs/release_log_check.md — the consumer-side release log check
- ./docs/storage_backends.md — the `Storage` trait and its backends
- ./docs/release_format.md — manifest, tarball, storage keys, verification flow
- ./docs/release_workflow.md — cutting a release
- ./docs/release_log.md — release log writers: publish `--log-repo`, backfill,
  revoke, recovery
- ./docs/fuzi.md — the npm installer: verbs, inputs, cache, exit codes
- ./docs/sidecars.md — the dormant sidecar workload
- ./docs/platform_support.md — target platforms, platform-code rules, and the
  platform-specific code inventory
- ./docs/deferred.md / ./docs/deferred_security.md — evaluated and deferred,
  with revisit triggers

## Values and policy

- **Self-hosted, local-first** — infrastructure you can own; works offline;
  sensitive data in local files, not network storage.
- **Security first, then performance** — minimize information leakage; lazy
  is secure; power users get control with clear visibility. Fast startup,
  minimal overhead, efficient IPC; measure rather than guess.
- **Honest** — say "planned" when things aren't built.
- **No backwards compatibility** (pre-1.0) — no re-exports, shims, or
  deprecation wrappers; break and update every consumer.
- **Extract early when reuse is known** — lift a primitive a sibling module
  will need on first use (common in the spine's parallel handlers: timing
  floors, audit-emit helpers, error mapping).
- **Twin-impl convergence.** The Rust spine and fuz_app's TS are observably
  equivalent implementations; whichever lands the better shape (security,
  correctness, abstraction, forensic detail) becomes canonical and the other
  ports (fuz_forge runs both and is held to both). Parity runs
  **migration-identity-deep** — namespaces, migration names,
  and per-namespace partitioning match so `schema_version` trackers are
  byte-identical and a consumer can swap TS↔Rust over one DB (gated by the
  `_testing_migration_tracker` parity check). Migration names are descriptive
  (`full_<domain>_schema` + named appends, no `_vN`). **Before settling a Rust
  shape on a TS-existing subsystem, read the fuz_app implementation** — it
  often encodes a deliberate choice the nearest Rust precedent doesn't.
- **Commons, not a product** — 0BSD, free forever.

## Dependency injection

The [fuz-stack skill](https://docs.fuz.dev/skills/fuz-stack)'s Rust DI escalation ladder applies: import-and-call for
pure helpers; a concrete `*Options` struct with `Arc<T>` fields by default (no
`*Deps` suffix in Rust; route-group state is `*RouteState`); capability traits
(pure nouns: `PasswordHasher`, `Storage`, `ConnectionCloser`) only when
polymorphism is real; `Arc<T>` on hot paths, `Arc<dyn Trait>` on cold ones;
RPITIT for generic use and a manual `BoxFuture` (not `#[async_trait]`) for
`dyn`, pairing an RPITIT trait with an object-safe `*Dyn` companion when both
are needed. Every deps-surface trait states `**Object-safe**` or
`**Not object-safe**` in its doc. tokio, tracing, `std::fs`, `std::env`, and
`std::time` stay concrete; the clock seam is tokio's `start_paused`.

**Test injection** is concrete impls in the `fuz_testing` crate, never
`cfg(test)` shadows. The one sanctioned exception — a seam in the production
path itself — is a **dev-dependency-only `test_*` feature**:
`fuz_crypto/test_trust_anchor` (a runtime trusted-key registry),
`fuz_home/test_home_override` (a `FUZ_HOME` redirect, since
`unsafe_code = "forbid"` rules out `set_var`),
`fuz_http/test_router_access` (`GatedRouter::into_router_for_testing`, for
in-process router tests), and `fuz_artifact/test_binary_stubs` (minimal
executables per target for the publish and install suites, kept beside the
header parser they invert). `cargo xtask check-release`
refuses any `test_*` feature enabled on a normal or build edge. Don't "fix"
these into separate crates.

## Quick start

```bash
cargo xtask install   # build fuz + fuzd, install, restart the daemon — after any change
fuz self status       # version, current artifact, daemon presence
```

`fuz artifact build` rebuilds and switches the fuz CLI only — it neither
rebuilds fuzd nor restarts it. Put `~/.fuz/bin` on `PATH` (./docs/fuz_home.md
§ PATH).

## Commands

Every shipped binary (and `xtask`) parses through
`fuz_sys::cli::parse_env_args`: an unparseable command line exits `2` (`fuzi`:
`64`, `EX_USAGE`) with argh's message on stderr, never `1`; `--help` prints to
stdout and exits `0`. `testing_spine_stub` hand-parses its `--port` to the same
contract. `--json` is on `fuz self status`, `fuzd status`, `fuz artifact list` /
`log`, the `--check` flows, and `fuzi`'s verbs.

```bash
# Checks — local equivalents of the CI gates (exact list: docs/testing.md § CI)
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(umask 000; cargo test --workspace)   # CI's umask leg: the ~/.fuz mode assertions
cargo xtask check-release        # release audit: forbidden crates, layering, test_* features on release edges, re-declared lint tables
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --document-private-items

# Development
cargo xtask install [--no-restart | --build-only]
cargo xtask clean                # remove ~/.fuz/, stop the daemon

# fuz self — the fuz binary itself
fuz self bootstrap [--no-modify-path] [--quiet]   # copy fuz to ~/.fuz/bin, update shell PATH (install.sh runs this)
fuz self version | status [--json]
fuz self upgrade --storage <uri> [--check [--json]] [--force] [--allow-downgrade]

# fuz tool — first-party binaries (FIRST_PARTY_TOOLS) into ~/.fuz/tools/<name>/v1-<hash>/
fuz tool install <name> --storage <uri> [--version X] [--allow-downgrade] [--force]
fuz tool upgrade <name> --storage <uri> [--check [--json]] [--allow-downgrade] [--force]
fuz tool verify <name>           # re-hash against meta.json
fuz tool list

# fuz artifact — the local content-addressed store (flags: docs/artifacts.md § CLI Commands)
fuz artifact build | use <hash|-> | list | verify [hash] | log [-n N]
fuz artifact prune [--keep N] [--wetrun]    # dry-run by default, like xtask prune

# fuz workload — observe fuzd's observer workloads (needs fuzd running)
fuz workload observe process|network|services [--follow]

# fuzd — daemon lifecycle (bare `fuzd` runs in the foreground)
fuzd start [--quiet] | stop [--force] [--quiet] | restart [--force] [--quiet]
fuzd status [--json | --quiet | -v]   # exit 0 = answers, 1 = stopped or not answering, 2 = bad fuz home
fuzd logs [--no-follow] [-n N]

# fuzi — lockfile-driven npm installer (flags are per-verb: fuzi <verb> --help)
fuzi install | verify | clean    # clean sweeps crash-leaked staging dirs, never node_modules or the CAS; never run it during an install
scripts/fuzi-gate.sh [--glibc-only | --musl-only]   # acceptance gate (scripts/fuzi-gate/README.md)
scripts/fuzi-bench.sh [--compare <other-fuzi>]      # perf claims about fuzi come from here, not reasoning; TMPDIR picks the filesystem it measures

# install.sh end-to-end + mutation gate (scripts/install-test/README.md)
scripts/install-test.sh && scripts/install-test-mutants.sh

# Publisher-only (producing is never on fuz; steady-state per-tool publish is `fuzf tool publish`)
cargo xtask key generate | info | export | list-trusted        # docs/signing.md § CLI Commands
cargo xtask publish self --storage <uri> [--log-repo <path>] [--target <triple>]   # docs/release_workflow.md
cargo xtask publish tool <name> <bin> --version <v> --storage <uri> [--log-repo <path>] [--target <triple>]
cargo xtask release-log backfill|revoke … --log-repo <path> [--wetrun]   # dry-run by default; docs/release_log.md
cargo xtask prune --storage <uri> [--tool <name>] [--keep N] [--wetrun]  # dry-run by default
```

**Storage URIs** (`--storage`): a local path, `forge://<host>`,
`ssh://user@host[:port]/path`, or read-only `https://host[:port][/base]`;
ambient auth, no credentials file (./docs/storage_backends.md). Only a publish
creates a store — everything else refuses a local path that isn't an existing
directory.

**Exit codes** (`fuz`; the classification: ./docs/release_format.md § Version
Safety):

- `0` ok · `1` failure
- `2` the caller must change something local: an unparseable command line, a
  bad flag combination, an unusable release log configuration, or a fuz home
  that can't be used as configured (an unusable `HOME` with `FUZ_HOME` unset, a
  relative `FUZ_HOME`, a world-writable `~/.fuz` where a command writes under
  it, a `FUZ_HOME` too long for fuzd's socket where a command looks for it)
- `10` `--check` found an update (or not installed / unreadable)
- `65` bytes not to trust — a bad signature, a download hash mismatch, a
  verified tarball that won't parse, a release the log refuses, a tampered
  local install; don't retry
- `73` no disk space · `75` artifact lock held, or the release log check
  couldn't confirm

A `~` or `HOME` problem reached through `--storage`, the forge token's home, or
`fuz artifact build`'s default repo keeps that command's own code.
`fuzd` exits `75` when another fuzd holds the socket, and `2` for the same
unusable home (./docs/daemon_lifecycle.md). `fuzi` uses the sysexits classes
and `128 + signum` on signals (./docs/fuzi.md § Exit codes).

## Crates

./docs/crates.md is the per-crate reference (boundaries, the rules a change must
keep, consumers); module invariants, gate orders, and error cases are each
crate's rustdoc. Read both before working in a crate, and put new detail there,
not here.

**Cross-crate invariants** (★ = enforced by `cargo xtask check-release` via
`fuz_audit`):

- ★ `fuz` is consumer-only — fetches and verifies, never signs or publishes.
  `fuz_sign` is forbidden in every production binary (`xtask` is
  `dev_only`-exempt); signing is a crate, not a feature, so feature
  unification can't route it in.
- ★ `fuz`/`fuzd` never depend on `fuzi`/`fuzi_core`.
- ★ `fuz_testing` and `fuz_audit` never reach a production binary: no local
  package outside `testing_*`/`dev_only` declares a normal or build dep on
  them.
- ★ A local `test_*` feature is enabled only from `[dev-dependencies]`.
- ★ Layering (`BUILTIN_CRATE_LAYERING`): `fuz_fact` ⊥ `{axum, fuz_http,
  fuz_cell, fuz_auth, fuz_actions}`; `fuz_cell` ⊥ `fuz_actions`; `fuz_sys` ⊥
  `{axum, fuz_http}`; `fuz_home` ⊥ `{axum, fuz_db, fuz_http}`.
- ★ A member that re-declares its own `[lints.<tool>]` tables keeps the
  workspace's: the same tool tables as `[workspace.lints.*]`, and every
  workspace lint at the same level and priority except `rust.unsafe_code`,
  which, where the workspace sets it, it declares at `deny` or `forbid` at the
  workspace's priority (`allow` / `warn` fail; no opt-out). Additions are listed in the output. When
  `unsafe_code` isn't `forbid`, no lib or bin crate root lifts it with a
  top-of-file `#![allow(unsafe_code)]` / `#![expect(unsafe_code, …)]` (a
  submodule's own lift isn't checked).
- `testing_`-prefixed binaries never ship (packaging filter +
  `check_no_test_binaries`).
- The spine crates are **twins of fuz_app** — wire literals, close codes, DDL,
  and error bodies match it (§ Values and policy).
- `fuz_pty` is the one crate allowed `unsafe`: `unsafe_code = "deny"`, lifted
  per item with `#[expect(unsafe_code, reason = "…")]`, and a `// SAFETY:`
  comment on every `unsafe` block (`clippy::undocumented_unsafe_blocks`).
- `fuz` never drives fuzd's lifecycle: it doesn't link `fuz_daemon`, probes
  fuzd passively, and speaks the wire only for `workload observe`.

**Binaries** — `fuz` (the CLI client) · `fuzd` (the daemon; lifecycle in
`fuz_daemon`) · `xtask` (dev + publisher automation, the bootstrap signer) ·
`fuzi` (the npm installer over `fuzi_core`) · `testing_spine_stub` (test-only
spine server for fuz_app's cross-backend suites; never shipped) ·
`testing_fake_fgro` (`fuz_eval`'s stand-in for `fgro eval` in its suites; never
shipped).

**Foundation and distribution**

- `fuz_sys` — home-agnostic OS primitives; the one `$HOME` lookup and the
  untrusted-text escaping.
- `fuz_home` — the `~/.fuz` layer: paths, `daemon.json`, logs.
- `fuz_artifact` — content-addressed artifacts, tool installs, the store-entry
  policy.
- `fuz_crypto` — verify-only Ed25519, canonical JSON, `ContentHash`.
- `fuz_sign` — the producer side: keys, signing, publish, prune, release log
  writers.
- `fuz_storage` — the `Storage` backends.
- `fuz_archive` — hardened streaming `.tar.gz` extraction.
- `fuz_release` — fetch / verify / install and the release log reader.
- `fuz_audit` — the `check-release` audit: the dep graph, and re-declared
  lint tables held to the workspace's.

**Daemon**

- `fuz_daemon` — fuzd lifecycle, behind `fuzd`'s own CLI.
- `fuzd_server` — the UDS server and the workload registry.
- `fuz_wire` / `fuz_client` — the UDS protocol and its async client.
- `fuz_sidecar`, `fuz_deno`, `fuz_python` — the dormant sidecar workload.

**Libraries for other workspaces**

- `fuz_eval` — one-shot config eval through a pinned `fgro eval`; sole consumer
  zap.
- `fuz_pty` — Linux-only PTY library; sole consumer `zzz_server`.

**Spine** (twins of fuz_app)

- `fuz_db` — pool, migrations, query helpers (commit with `commit_checked`).
- `fuz_http` — JSON-RPC envelopes, gates, and `compose_stack`, the one
  composition root.
- `fuz_auth` — credentials, sessions, roles, rate limits, audit.
- `fuz_realtime` — WS + SSE transport.
- `fuz_actions` — `ActionSpec` / `perform_action`, the top of the spine, and
  `server`, the toolkit a spine server's `run_app` composes.
- `fuz_cell` / `fuz_cell_actions` — cell storage and authz / the cell RPC verbs.
- `fuz_fact` / `fuz_fact_serving` — the content-addressed byte store / its sole
  authz'd reader.
- `fuz_db_admin` — the allowlist-gated table browser.
- `fuz_testing` — test-only spine fixtures and the Postgres harness.

**npm bridge** — `fuzi_core`, the engine behind `fuzi`: prints nothing, never
runs package code.

## Sidecar workload

Dormant and feature-gated off (`cargo build -p fuzd --features sidecar`
revives it); ./docs/sidecars.md.

## Wire protocol

fuzd binds a Unix domain socket at `~/.fuz/run/socket` (mode 0600), speaks a
postcard envelope, and authenticates by `SO_PEERCRED` UID match — fail-closed:
a cross-uid peer or one whose credential can't be read is dropped at accept
(`fuzd_server::conn::should_accept_peer`, the daemon's sole auth boundary).
fuzd speaks no HTTP; HTTP/JSON-RPC lives in *consumer* binaries on the spine
crates, keeping fuz's own binaries free of web-framework deps.

Postcard-framed action pairs over the UDS. The `ActionId` constants and id
ranges are in `fuz_wire` (`actions.rs`); the frame layout and stream flags are
the header of `crates/fuz_wire/src/codec.rs`; the version history is
`fuz_wire::PROTOCOL_VERSION`'s doc — **bump it with any wire-shape change**.
Hello is the liveness probe (`fuz_client::check_health`). Observer and watcher
subscriptions stream frames on their `request_id` until the connection closes;
other streams end on a header `FINAL` flag. The `WORKLOAD_*` pairs are
wire-only (the `fuz workload list/status/stop` verbs are planned), and the
`SIDECAR_*` pairs are dormant (dispatched, never sent, answered from the empty
pool).

## Environment variables

For `fuz`, `fuzd`, and `scripts/install.sh`. The spine servers' shared
variables (`FUZ_ALLOWED_ORIGINS`, `FUZ_ALLOW_ORIGIN_WILDCARDS`, the cookie
keys, a per-server trusted-proxy var, …) are read by consumer servers and
`testing_spine_stub`; `fuz_http::server_env` has the list and rules, and the
stub's own test knobs are its rustdoc's.

- `FUZ_HOME` (default `~/.fuz`) — the root; empty reads as unset, relative is
  refused, and the default needs an absolute `HOME` (rules:
  ./docs/fuz_home.md § Environment). It relocates fuzd's socket,
  `daemon.json`, and logs — fuzd's only other knob is `RUST_LOG`.
- `SHELL` — picks the rc file `fuz self bootstrap` manages (bash, zsh, fish;
  any other shell gets no rc edit).
- `FUZ_DEV_REPO` — source repo for `fuz artifact build` when the checkout isn't
  at the default path.
- `FUZ_FORGE_TOKEN` — bearer token for `forge://`; falls back to `api_token` in
  `FUZ_FORGE_HOME` (default `~/.fuz_forge`, shared with `fuzf`).
  `FUZ_FORGE_BASE_URL` (blank = unset) serves a host-less `forge://` and is
  `fuzf`'s server URL. Rules:
  ./docs/storage_backends.md.
- `FUZ_RELEASE_LOG_URL` — the release log witnesses (comma-separated origins).
  **Unset or empty, no check runs**; no public release log exists.
  `FUZ_RELEASE_LOG=off` is the per-user opt-out (any other value is exit 2).
  Both are honored by `scripts/install.sh` too. ./docs/release_log_check.md.
- `FUZ_INSTALL_BASE_URL` — `install.sh` only: the release host (default
  `https://releases.fuz.dev`, not yet live).
- `RUST_LOG` — the `tracing` filter; `fuzd` defaults to `info`.

## Used by

Other repos path-depend on these crates from an adjacent checkout (nothing is
published):

- [fuz_forge](https://github.com/fuzdev/fuz_forge) — `fuz_forge_server`
  (`fuzfd`) mounts the spine incl. cells and facts, plus `fuz_storage` and
  `fuz_db_admin` (its sole consumer); the `fuzf` client publishes with
  `fuz_release` / `fuz_sign` / `fuz_storage`. It runs both twins (the TS
  reference server and the Rust production one) — the canonical
  cross-backend consumer.
- Other app servers on the spine mount `fuz_actions`, `fuz_auth`, `fuz_db`,
  `fuz_http`, `fuz_sys` (most also `fuz_realtime`; for cells and facts,
  `fuz_cell`, `fuz_cell_actions`, `fuz_crypto`, `fuz_fact`, `fuz_fact_serving`).
  One of them also takes the fuzd client surface (`fuz_client` +
  `fuz_wire`, plus `fuzd_server` as a dev-dep for an isolated-fuzd test), so a
  wire change reaches it. Everywhere, `fuz_testing` is confined to `testing_*`
  binaries and dev-deps and `fuz_audit` to xtasks.
- `zzz` — `zzz_server` mounts the spine and is the **sole consumer of
  `fuz_pty`**.
- `zap` — the **sole consumer of `fuz_eval`** (plus `fuz_audit` for its
  xtask); its engine is spine-free.

A breaking change sweeps every consumer.

## Build configuration

Edition 2024; `rust-toolchain.toml` pins the toolchain for local builds and
CI. Lints: `unsafe_code = "forbid"`; clippy `all` + `pedantic` + `nursery` +
`cargo` at warn, plus `clone_on_ref_ptr` / `dbg_macro` / `expect_used` /
`panic` / `todo` / `unwrap_used` (test carve-outs in `clippy.toml`) and extra
rustc lints.
`clippy.toml` disallows `std::env::home_dir` — every `$HOME` read goes through
`fuz_sys::home_dir`. `fuzi`, `fuzi_core` and `fuz_archive` carry their own
`clippy.toml` (the exec-free disallows), which replaces the root one rather
than merging; `fuzi_core/tests/exec_free.rs` checks they carry its settings
and stay byte-identical.
`fuz_pty` re-declares the workspace lint tables (Cargo replaces a crate's
`[lints]` whole), differing only in `unsafe_code = "deny"` and an added
`clippy::undocumented_unsafe_blocks = "warn"`; `check-release` holds the copy
to the workspace's.
Release profile: `lto`, `codegen-units = 1`, `panic = "abort"`
(`catch_unwind` is dead), `strip` —
abort fits this workspace's binaries (CLIs, the local daemon, test stubs);
the consumer workspaces that build spine servers set `panic = "unwind"` so
`compose_stack`'s catch-panic layer can answer a request panic `500`.
Dependencies: smallest crate that does the job, shared through the workspace;
tokio + postcard for fuzd's IPC, reqwest as the outbound HTTP client, blake3,
ed25519, thiserror.

Moving one crate in `Cargo.lock` (version moves are the maintainer's call): `cargo
update -p <crate> --precise <version> --dry-run` and read every `Updating` /
`Downgrading` / `Adding` / `Removing` line, then run it without `--dry-run`,
then check that `git diff Cargo.lock` moves only that crate plus what its new
version requires — revert any other movement. Prefer a networked run:
`--offline` resolves from the locally cached index and can pick different
versions.

## Error handling

Typed `thiserror` errors throughout; binaries render them with hints and exit
codes (hand-written `Display` only in `fuz_pty`, `fuz_crypto::witness`, and
`fuz_testing`'s `DbResetError`). Untrusted text is escaped in the `Display` of
the type that holds it; `fuz`, `fuzd`, `fuzf`, `xtask`, and the spine servers print the
whole source chain; `is_security_violation` / `is_unconfirmed` /
`is_unusable_home` stay complete at every wrapper level. The rules:
./docs/crates.md § Error rendering.

## Platform support

Linux. The `fuz` CLI is POSIX-only and expected to work on macOS (untested);
`fuzd` does not run there; Windows is unsupported; `fuzi` alone also builds on
musl. ./docs/platform_support.md.
