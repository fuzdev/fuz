# fuzi

`fuzi` installs exactly what a `package-lock.json` names into `node_modules`,
with npm-ci semantics: no resolver, no install or lifecycle scripts, no
compilation. fuzi is a first-party fuz tool (signed, installed with `fuz tool
install fuzi` once published); the npm trees it installs are trust-anchored
only by npm's `integrity` metadata. The engine is `fuzi_core`
(./crates.md § `fuzi_core`), which prints nothing; `fuzi` is its CLI.

## Commands

Run in the project directory. Each verb takes `--help`.

```bash
fuzi install [--omit dev|optional|peer]… [--ignore-manifest] [--dry-run] [--offline] [--json] [-q] [-v]
fuzi verify [--omit …] [--json]   # structural check: presence, versions, links and their bins, platform variants
fuzi clean [--dry-run] [--json]   # sweep crash-leaked staging trees
```

- `install --dry-run` writes neither `node_modules` nor the cache, and
  re-hashes every cached tarball it would use.
- `verify --omit` must match the install's.
- `clean` never touches `node_modules` or the cache. Don't run it during an
  install in the same project: it would sweep that install's live staging tree.

## Inputs

- **Lockfile** — `package-lock.json` v2 or v3, read through its `packages`
  map; v1, a missing version, or an unknown one is refused. Other lockfile
  formats are not read; fuzi's own `fuzi.lock` is planned.
- **Drift guard** — `package.json` must agree with the lockfile;
  `--ignore-manifest` skips the check. Both files must be regular files under a
  size cap.
- **No other configuration** — no `.npmrc` and no registry auth; the
  environment it reads is `FUZ_HOME` (else `HOME`) and the standard
  `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` proxy variables.

## Fetching and placement

- Fetches exactly each entry's `resolved` URL, https only; redirects are
  refused. Every tarball is checked against its sha512 `integrity`.
- Platform packages are selected by os / cpu / libc (libc is probed on Linux
  only) and placed, never built. Skipped install scripts are reported.
- Only depth-1 sibling `link: true` entries are linked, as relative symlinks; a
  link target is local source fuzi never writes to. `.bin` links are created.

## Cache and swap

- Tarballs are cached by integrity at `~/.fuz/cache/npm/sha512-<hex>/package.tgz`
  (./fuz_home.md); `--offline` uses only the cache.
- The tree is built in a `.fuzi-installing-*` staging directory, then renamed
  over `node_modules`, keeping the previous tree as `.fuzi-old-*` until the
  swap completes. `node_modules` must be renameable in place: a symlink, a
  non-directory, or a mount point is refused.
- During an install (not `--dry-run`), SIGINT, SIGTERM, or (on Linux) SIGHUP
  drains the staging tree and exits `128 + signum`; an inherited ignore stays
  ignored. `fuzi clean` handles what a hard kill leaves behind.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | ok |
| `64` | usage |
| `65` | bad data: lockfile, drift, a refused entry, an integrity or cache mismatch, a permanent fetch failure, a link target, a failed verify, a hostile tarball |
| `66` | missing input |
| `69` | `--offline` cache miss |
| `73` | not enough disk space, or `node_modules` can't be created or replaced |
| `74` | I/O, including an oversized project file and a tarball that won't extract because of the disk |
| `75` | transient fetch failure, interrupted, or staging cut into |
| `78` | TLS configuration |
| `129` / `130` / `143` | SIGHUP / SIGINT / SIGTERM |

## Gate and bench

- `scripts/fuzi-gate.sh` — the empirical acceptance gate: a script-skipped
  install that still builds with esbuild and vite
  (../scripts/fuzi-gate/README.md).
- `scripts/fuzi-bench.sh [--compare <other-fuzi>]` — performance claims about
  fuzi come from here; `TMPDIR` picks the filesystem it measures.
