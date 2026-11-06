# Sidecars

The sidecar workload kind: long-running non-Rust runtime processes (Deno,
Python) that host operations from an embedded script. **Dormant** — no @fuzdev
tool uses it (tsv self-hosts), and it's gated behind `fuzd`'s off-by-default
`sidecar` feature. This doc describes the machinery as it stands.

## Position in the design

The built workload kinds are the observer and the watcher; the other planned
kinds (./deferred.md § Further workload kinds) rank ahead of sidecars, which
return only on real demand for user-supplied non-Rust tooling. There is no
`fuz sidecar` CLI surface.

The default `fuzd` links neither `fuz_deno` nor `fuz_python`, embeds no
`sidecar.ts`, and runs an empty `SidecarPool`; the `SIDECAR_*` wire actions
answer from it and nothing in the workspace sends them.
`cargo build -p fuzd --features sidecar` registers the Deno and Python factories
at startup (`crates/fuzd/src/main.rs`); their processes spawn on the first tool
call. `SidecarPool` and `fuzd_server::WorkloadRegistry` are separate; a
revival would move sidecars onto the registry.

## Architecture

```
┌─────────────┐     mpsc channel        ┌──────────────────┐     stdio      ┌─────────────┐
│ SidecarPool │◄───────────────────────►│ SidecarController│◄─────────────►│   Runtime   │
│  (router)   │     ControllerCommand   │    (generic)     │  JSON-lines   │ (deno/python)│
└─────────────┘                         └──────────────────┘                └─────────────┘
```

- `fuz_sidecar` — `SidecarPool` routes tool requests and owns lifecycle;
  `SidecarController` / `SidecarControllerFactory` do the subprocess I/O and
  request multiplexing, configured by a `SpawnConfig` (command builder,
  embedded script, optional config file, tool list).
- `fuz_deno` / `fuz_python` supply only the embedded script
  (`SIDECAR_SCRIPT`), the tool list, the command builder, and `factory()`.

## Protocol

JSON-lines over stdio. A request is `{id, tool, content, options?}`; a response
is `{id, ok, output | error, duration_ms}`. The `id` matches responses to
requests, so several can be in flight. An internal `__version_info` tool
(`__`-prefixed names skip tool-list validation) returns `{runtime, typescript?,
dependencies}` from version constants the script keeps in sync with its imports
by hand; `fuzd status -v` shows them, and a failed version fetch is ignored.

## Security

- **Embedded script on disk.** The script is compiled into the binary and
  written at spawn to an owner-only (0600) tempfile in the system temp
  directory, kept for the controller's lifetime. Not `memfd_create`: it would
  keep the script off disk but is Linux-only, and an attacker who can replace a
  `0600` file under your uid before Deno reads it already owns your session, so
  the gap isn't material (./platform_support.md § Rules).
- **Environment.** `fuz_sidecar::secure_command` strips the variables in
  `SENSITIVE_ENV_VARS`. The list is empty — fuzd authenticates by UDS +
  `SO_PEERCRED` and holds no credential in its environment — and the hook stays
  so a future credential is a one-line addition.
- **Privileges.** Sidecars run as child processes with the daemon's privileges;
  the Deno sidecar runs with `--allow-read`, `--allow-env`, `--allow-sys=cpus`.
  Isolation, IPC, and supply-chain hardening are deferred:
  ./deferred_security.md § Sidecar hardening (dormant).

## Defined sidecars (dormant)

- **Deno** (`fuz_deno/sidecar.ts`) — `prettier` (with `prettier-plugin-svelte`),
  `svelte-parse`, `acorn-ts-parse`. tsv covers what these offer.
- **Python** (`fuz_python/sidecar.py`) — a placeholder; `hello-python` returns
  `21 * 2`.

## Lifecycle

A sidecar is `Unloaded` (factory registered, no process), `Loading`, `Running`,
`ShuttingDown`, or `Failed`. The first tool request loads it; a crash while
running reloads it automatically; a stop goes through `ShuttingDown` back to
`Unloaded`.

Crash recovery counts restarts in a window (default 3 in 60 s) with exponential
backoff (100 ms up to 5 s); past the limit the sidecar is `Failed`. Intentional
shutdowns (idle timeout, daemon shutdown) never trigger recovery; on daemon exit
a sidecar is killed when its controller drops, with no graceful handshake.
`SidecarConfig` sets the idle timeout (default 30 s) and the `FailurePolicy`:
`RetryOnNextCall` (default) moves `Failed` back to `Loading` on the next
request; `StayFailed` keeps it failed until the daemon restarts.
