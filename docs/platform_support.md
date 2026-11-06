# Platform Support

The target platforms, the rules for platform-specific code, and its
inventory. The goal is the best Linux implementation that doesn't preclude
other platforms.

## Target Platforms

| Platform              | Priority    | Status                    |
| --------------------- | ----------- | ------------------------- |
| Linux x86_64 (glibc)  | Primary     | Supported                 |
| Linux aarch64 (glibc) | Primary     | Expected to work (no CI)  |
| macOS (arm64, x86_64) | Planned     | `fuz` expected to work; `fuzd` does not start (§ macOS) |
| Linux x86_64 (musl)   | Partial     | `fuzi` only (§ musl) |
| Windows               | Deferred    | Not supported (§ Windows, ./deferred.md § Windows support) |

## Rules

1. **Use cross-platform APIs when they meet requirements.** Don't use
   platform-specific APIs just because they exist.
2. **Use platform-specific APIs when cross-platform alternatives have material
   gaps.** "Material" means the security posture changes, not a
   micro-optimization.
3. **Don't abstract until needed.** No `Platform` traits or `#[cfg]` blocks for
   hypothetical platforms.
4. **Record what's platform-specific** in § Platform-Specific Code.

**Unsafe code**: `unsafe_code = "forbid"` workspace-wide, except `fuz_pty`,
which allows it for its libc PTY calls and re-declares the other workspace
lints. Unsafe is justified only when the alternative has a material security
gap (attacker capabilities change, not a slightly wider timing window) that
can't be mitigated otherwise, and the unsafe code is minimal and auditable.
Performance alone doesn't justify it.

## Platform-Specific Code

Unix-only code is `std::os::unix`, `cfg(unix)` / `cfg(target_os)`, nix / libc,
and Linux `/proc` reads. Regenerate the file list with
`grep -rln 'std::os::unix\|cfg(target_os\|cfg(unix)\|/proc/\|nix::\|libc::' crates/*/src`
(it also matches test modules). By category:

- **Unix domain sockets** — fuzd's listener (`fuzd_server`), its clients
  (`fuz_client`, `fuz/src/fuzd.rs`), and the `SO_PEERCRED` gate (tokio's
  portable `UCred`, so `getpeereid` on macOS); `fuz_db`'s Unix-socket Postgres
  host. **The largest Windows blocker.**
- **Mode on create / mode reads** (`DirBuilderExt`, `OpenOptionsExt`,
  `PermissionsExt`) — `fuz_home` (the `0700` home, the world-writable refusal,
  `daemon.json` `0600`), `fuz_sys::fs` (`write_atomic`), `fuz_artifact` (staging
  and tool dirs `0700`, finished artifact `0755`), `fuz_archive` (extraction
  modes, setuid/setgid refusal), `fuz_daemon` (logs `0600`), `fuzd_server`
  (socket `0600`, dir `0700`), `fuz_release` fetch, `fuz` bootstrap, `fuz_sign`
  scratch dirs, `fuz_storage` file backend, `fuzi_core` (cache, staging,
  extraction), `fuz_eval`, `fuz_testing`.
- **No-follow opens** (`O_NOFOLLOW`, `fchmod` on the fd) — `fuz_sys::secure_file`
  and `fuz_sys::fs`, through which the artifact and tool stores read `meta.json`
  and binaries; `fuz_auth`'s bootstrap token store.
- **Symlinks** — `fuz_sys::fs::replace_symlink_atomic` (`current`, `bin/`);
  `fuzi_core` (`node_modules` links, `.bin`).
- **Locks and free space** — `fuz_sys::file_lock` (`flock(2)`), `fuz_sys::fs`
  (`statvfs` before creating an artifact).
- **Signals** — `fuz_sys::signal` (SIGINT/SIGTERM → shutdown token; degrades to
  `ctrl_c()` off Unix), `fuzi/src/signal.rs` (the staging drain on
  SIGINT/SIGTERM/SIGHUP, exit `128 + signum`; off Linux the ignore mask is
  unreadable, so SIGHUP keeps its default disposition).
- **Processes** — `fuz_sys::pid` (`is_pid_alive`: `/proc/<pid>` on Linux, nix
  `kill(pid, None)` on other Unix; `send_signal` for the SIGTERM / SIGKILL
  `fuz_daemon` sends),
  `fuz_home::pid` (`/proc/<pid>/comm` for `verify_pid_is_fuzd`; fails closed, so
  without `/proc` every pid reads as not-fuzd), and `fuz_eval` (exec of the
  pinned `fgro` through `/proc/self/fd`, its own process group, `killpg`, and
  under root the uid drop, with its passwd lookup).
- **Linux `/proc` self-uid** — `fuzd_server` (the accept gate's baseline),
  `fuz_eval`'s trust root and pin cache, and `fuzi/src/signal.rs`'s inherited-ignore read
  (all `/proc/self/status`).
- **Observer sources** — `fuzd_server/src/workload/`: `/proc` and `/proc/net`
  for the process and network domains, `systemctl --user` for services. The
  `fuz_wire` observer DTOs carry `/proc` semantics too (the `stat` start-time
  identity, `VmRSS`, socket inodes).
- **Filesystem watcher** — `notify` (inotify on Linux, FSEvents on macOS);
  portable, not a blocker.
- **Executable format** — `fuz_artifact::platform` reads a binary's header on
  any host: a 64-bit little-endian ELF's architecture and loader (glibc, musl,
  or static), or a 64-bit Mach-O's architecture (universal binaries are
  refused), held to a release target from the closed supported set
  (`{x86_64,aarch64}-unknown-linux-{gnu,musl}`, `{x86_64,aarch64}-apple-darwin`).
  A built artifact, every published binary, and every installed one are
  checked (./release_format.md § Binary platform).
- **libc detection** — `fuzi_core::platform` (`/usr/bin/ldd` contents, else
  the loader files; for npm's libc-specific packages; Linux only — elsewhere
  no libc is reported).
- **PTY** — `fuz_pty`: `posix_openpt`, `TIOCGPTPEER`, `fork` / `execvpe`,
  `setsid`, `dup2`, signal masks, `waitpid`, … — **Linux-only** (kernel ≥ 4.13;
  `execvpe` is GNU); macOS would need `ptsname` + an `execve` PATH walk, Windows
  ConPTY.
- **Path bytes** (`OsStrExt`) — `fuz_artifact` (`vcs`, `types`),
  `fuz_sys::fs::is_plain_file_name`.
- **Home lookup** — `fuz_sys::home_dir` (`$HOME`, then
  `std::env::home_dir`, which answers from `USERPROFILE` on Windows).

## macOS

The `fuz` CLI uses only POSIX APIs and is expected to work, untested (no CI, no
binaries). Three things are Linux-bound:

1. **Self-uid** — `fuzd_server` and `fuz_eval` read `/proc/self/status`, so
   `fuzd` refuses to start and `fuz_eval` can't settle a trust root. A portable
   `geteuid()` fixes both (nix's `user` feature is already on for `fuz_eval`).
   `fuz_eval` also execs through `/proc/self/fd`, and `fgro eval` is
   Linux-only.
2. **Observer process / network domains** read `/proc` with no fallback, so
   they error; the port is a libproc/sysctl `ObserverSource`.
3. **Observer services domain** shells out to `systemctl --user` and degrades
   to an empty unit set; the port is a `launchctl` source.

Shipping macOS also needs a macOS CI runner and arm64 + x86_64 builds.

## musl

`fuzi` builds musl-native in `rust:alpine` (`scripts/fuzi-gate/Dockerfile.musl`)
and passes the gate's musl leg, which is run by hand (CI runs only the glibc
leg). The other binaries aren't built for musl; the `rustls`/`ring` TLS choice
keeps a static-musl build open. `install.sh` refuses a musl host before
downloading (exit 1) rather than fetch a glibc binary that verifies and then
fails at `self bootstrap`; an undetermined libc reads as glibc. Detection:
`is_musl` in `scripts/install.sh`, covered by the `musl` and
`libc_undetermined` cases (../scripts/install-test/README.md).

To ship musl builds: add the `*-unknown-linux-musl` targets, build and test
them in CI, and map musl hosts to them in `install.sh`
(./deferred.md § musl builds).

## Windows

**Scope**: Significant. Windows has different models for permissions,
processes, and PATH setup.

| Area               | Unix                         | Windows                                      | Complexity |
| ------------------ | ---------------------------- | -------------------------------------------- | ---------- |
| File permissions   | mode bits (0600)             | ACLs via `windows-acl` crate, or skip        | Medium     |
| Secure file create | `OpenOptionsExt::mode()`     | ACLs, or accept default perms                | Medium     |
| Symlinks           | `std::os::unix::fs::symlink` | `symlink_file/dir` (needs admin or dev mode) | Medium     |
| Signal handling    | SIGTERM + SIGINT             | `ctrl_c()` only (no SIGTERM)                 | Low        |
| Process inspection | `/proc/`                     | `OpenProcess` / `QueryFullProcessImageNameW` | Medium     |
| Local IPC          | Unix domain socket           | named pipes, or AF_UNIX on recent Windows    | High       |
| Path separators    | `/`                          | `\` (std::path handles this)                 | None       |
| Temp directory     | `/tmp` or `$TMPDIR`          | `%TEMP%` (tempfile handles this)             | None       |

**Work needed**:

- Add `#[cfg(unix)]` / `#[cfg(windows)]` conditional compilation
- Decide on permission strategy
- Windows CI runner
- Manual testing (CI can build but behavior testing needs real Windows)

## Adding Platform Support

When adding a new platform:

1. **Inventory**: Review this document for affected code
2. **Decide**: For each item, choose: conditional compilation, abstraction, or
   platform-specific behavior
3. **CI first**: Add build + test before claiming support
4. **Document**: Update this file with platform-specific notes
