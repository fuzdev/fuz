# install.sh end-to-end tests

Exercises `scripts/install.sh` against a local HTTPS server, covering the
download → checksum → bootstrap-handoff path without a real release or a VPS —
both the default path (the release host's own sidecar) and the release log
path (`FUZ_RELEASE_LOG_URL` set).

## Run

```sh
scripts/install-test.sh
```

Needs `deno`, `openssl`, and `curl` (skips cleanly with `SKIP:` if one is
absent); `install.sh` itself uses `curl`. Because `install.sh` forces `--proto '=https'
--tlsv1.2`, the server speaks TLS with a throwaway self-signed `localhost` cert,
trusted for the run via `CURL_CA_BUNDLE`. The downloaded "binary" is a stub
shell script — `install.sh` only `chmod +x`'s it and runs `<it> self bootstrap`,
so no build is needed. (Real `self bootstrap` behavior — artifact creation,
symlinks, rc editing, corrupt-state recovery — is covered by the Rust
`crates/fuz/tests/self_cli.rs` suite.)

## Scenarios and cases

`serve.ts`'s header lists the server scenarios: release host ones by name,
release log ones as `w<name>`. `install-test.sh` holds the cases, each a
`run_case <case> <release host scenario> <exit> <expected text>` line under a
comment saying what it pins. A default-path case is named after its scenario
and a release log case is `witness_<name>` for origin `w<name>`; the rest
(`shasum_fallback`, `config_*`, `switch_*`, `wget_*`, …) name what they vary.
Every case asserts no temp directory is left behind, and every refusal that
the stub never ran. The suite unsets `FUZ_RELEASE_LOG_URL` / `FUZ_RELEASE_LOG`
first, so the caller's environment can't change a case.

## Mutation gate

```sh
scripts/install-test-mutants.sh
```

Tests the tests. Each row in `install-test-mutants.sh` pairs a minimal `sed`
edit that breaks one behavior of `install.sh` with the case(s) that must catch
it, and carries a comment saying what it breaks — for example dropping
`--proto '=https'` → `redirect` and `witness_redirect`, weakening the
128-length guard → `sha256len` and `witness_sha256len`, pointing a digest
mismatch at the public issue tracker → `badsum` and `witness_mismatch`. The
release log rows cover the origin classes, each pointer-shape and name guard,
the switch and configuration checks, temp-directory cleanup, and the signal
handler.

For each row it copies `install.sh`, applies the mutation, and re-runs the
whole e2e suite via `INSTALL_SH_PATH` (under the default `sh` only,
`INSTALL_SH_SHELL=sh` — shell portability is the suite's job), requiring a
nonzero suite exit and a `FAIL: <case>` line for every case the row names.
Other cases failing too is fine.

- **Shared code names both paths.** The rows for code the default and release
  log paths share — the length guard, the case fold, the digest compare,
  `curl -f`, `--retry` — name a case from each, so a refactor that routes one
  path around the shared code shows up as a miss.
- **Terminal guards.** The malformed guard's `exit 1` row is why
  `malformed` / `sha256len` assert `checksum mismatch` is absent: without that,
  neutralizing the `exit` falls through to the digest compare, which also exits
  1 after "malformed" was printed, and the case still passes.
- **Baseline first.** It runs the unmutated suite first and aborts unless it is
  fully green. A row whose named case didn't run in the baseline
  (`witness_dir_unreadable` as root) is reported as skipped.
- **Drift guard.** A row whose `sed` no longer changes the file fails loudly
  (`mutation did not apply`). A row nothing catches is a finding, not a row to
  delete — it names an untested property.

Mutants run several at a time (`INSTALL_MUTANT_JOBS`; default the CPU count, at
most 8), each a whole suite run with its own server and port.

## CI

Both scripts run in CI as the `install-test` job (`.github/workflows/check.yml`),
which installs `deno` and runs `scripts/install-test.sh` then
`scripts/install-test-mutants.sh` (`openssl` + `curl` are preinstalled on the
runner). The mutation gate matters here beyond testing the tests: it is what
keeps the `redirect` case non-vacuous — a silently-regressed HTTP listener would
leave `redirect` passing on its own, since `curl` refuses `http://localhost:0/…`
before it connects.

## Shell portability

`curl … | sh` inherits whoever's `/bin/sh` is, so which shell the script runs
under is a real property. `install-test.sh` takes `INSTALL_SH_SHELL` (default
bare `sh`); the whole suite passes under **dash** (Debian/Ubuntu `/bin/sh`),
**busybox ash** (Alpine's `/bin/sh`, which must still run the script far enough
to print the musl refusal), and **bash**. Run it under each before touching
the script — a `sh -n` syntax check does not catch runtime divergence.

## Not covered here

- The `wget` branch beyond GNU `wget`: the `wget_*` cases (success, not found,
  and `wget_redirect` — `--max-redirect=0` refusing a 301 to plain HTTP) run
  against GNU `wget` only. The release log read stays curl-only: `wget` can't
  report the HTTP status it needs.
- A release host that redirects. curl follows an https→https redirect; the
  `wget` branch refuses every redirect, so a host answering with one (a CDN, an
  alias served as a 302) fails `wget` installs while curl installs work.
- `SIGINT`. The interrupt case sends `SIGTERM`: a shell started in the
  background without job control ignores `SIGINT`, so the harness cannot
  deliver one. The two handlers are one line each and differ in the exit code.
- An origin that never answers, left alone: the script sets no time bound of
  its own, so it waits as long as curl does.
- `rm -f` of the pointer file before each https fetch. It matters when one
  origin's connection drops after part of a body was written (unreachable, so
  the next origin is read) and the next answers with no body: without it the
  first origin's bytes would be read as the second's. No case reaches it — the
  test server cannot drop a connection mid-body.
- The curl exit codes classed as unreachable, other than a refused connection
  and a failed TLS handshake: name resolution, a timeout, a certificate
  failure, and a dropped connection have no case of their own.
- The agreement between this script's pointer parser and the publisher's
  writer is by construction, not by test: the suite's pointers come from
  `serve.ts` and the harness, not from `fuz_sign`.
- Disk-full in `$TMPDIR` / `~/.fuz` (needs a constrained mount or a faked `df`).
- The musl loader signal. `/lib/ld-musl-<arch>.so.1`, read when no `ldd` or
  `getconf` says which libc it is, is a fixed root path a test cannot fake, so
  only its absence is exercised (`libc_undetermined`); a positive
  `getconf GNU_LIBC_VERSION` answer has no case of its own, and the suite has
  never run on a real musl host.
- A from-scratch bootstrap on a clean host against a real release host (none
  is live yet).
