# Artifacts

Content-addressed builds of the fuz CLI in `~/.fuz/artifacts/`. Remote
distribution (manifest, tarball, verification) is ./release_format.md; the
directory layout is ./fuz_home.md. The self artifact is fuz-only — fuzd installs
as its own tool under `~/.fuz/tools/fuzd/`.

## Two hashes

- **Content hash** — from the output binaries: the artifact's identity, its
  directory name, the `fuz artifact use` prefix. Answers "what am I running?"
- **Input hash** — from git state, rustc, target, and the rustflags
  variables: cache lookup and provenance. Answers "should I build?"

Identity stays grounded in the binary bytes, with no trust in input → output
determinism.

```
content_hash = "v1-" + blake3("fuz:" + fuz_hash)      # the self artifact
input_hash   = blake3(git_commit + "\n" + git_diff_hash + "\n" + rustc_version + "\n" + target
                      + rustflags records)
```

- Every hash is lowercase hex with no trailing newline: `fuz_hash` is the
  binary's BLAKE3 (64 hex), and `content_hash` is `v1-` + 64 hex (every form
  and how strictly it is read: ./release_format.md § Digest formats).
- Per-tool artifacts hash their binary set the same way, `name:hash` lines with
  names sorted and joined by `\n` (`content_hash_from_binaries`). A binary name
  is a release token (`fuz_artifact::is_release_token`; the grammar:
  ./release_format.md § Release Log Files), so it holds no `:` or `\n` and the
  join is unambiguous; every install path refuses any other name. The `v1-`
  prefix versions the algorithm; **the format is stable** — changing it
  invalidates every artifact.
- A `fuz artifact build` and a `fuz self bootstrap` of the same bytes land on
  one directory (a build adopting a bootstrap dir keeps its provenance-less
  meta).
- `git_commit` is `git rev-parse HEAD`. `git_diff_hash` is empty for a clean
  tree, else the BLAKE3 of the length-prefixed `git diff --binary HEAD` (binary
  files' bytes included; no colour, external diff, or textconv) and each
  untracked, non-ignored file's name and content BLAKE3. A `git` command that
  fails fails the build; it never reads as clean.
- `rustc_version` is the first line of `rustc --version` and `target` the host
  triple, both run in the source repo so that, under rustup, they name the
  toolchain its `rust-toolchain.toml` selects.
- The rustflags records are `CARGO_ENCODED_RUSTFLAGS`, `RUSTFLAGS`, and
  `CARGO_BUILD_RUSTFLAGS`, each with its value or marked unset
  (`compute_input_hash`'s rustdoc has the byte layout).
- An input-hash change only costs a cache miss.

**What the input hash does not cover**, so a change to it alone reuses the
cached build: ignored files (a `.gitignore`d input a `build.rs` reads, a
vendored directory), cargo configuration outside the repo's files
(`~/.cargo/config.toml` or one above the repo, `CARGO_PROFILE_*` and the other
`CARGO_*` variables), `RUSTC` / `RUSTC_WRAPPER` (the hashed `rustc --version` is
the one on `PATH`), edits to files marked assume-unchanged or skip-worktree
(`git diff` doesn't see them), the C toolchain and system libraries (glibc
included) the build links against, and cargo features (the build is always
`cargo build --release -p fuz`). To force a rebuild, change a tracked or
untracked file's content (the tree is then dirty and the hash moves), or delete
the cached artifact: `fuz artifact list` names it, and removing
`~/.fuz/artifacts/v1-<hash>/` (not the `current` one) makes the next build a
miss. When the stale build is `current`, make the tree dirty instead (any
untracked file will do), build, then remove the file.

## Metadata

`~/.fuz/artifacts/v1-<hash>/meta.json`:

```json
{
  "hash": "v1-abc123...",
  "version": "0.1.0",
  "created_at": "2026-01-15T10:30:00Z",
  "source": "local",
  "inputs": {
    "input_hash": "def456...",
    "git_commit": "f7e8a9b...",
    "git_diff_hash": null,
    "rustc_version": "rustc 1.89.0 (...)",
    "target": "x86_64-unknown-linux-gnu"
  },
  "outputs": { "fuz": "abc123..." }
}
```

- `source` (required): `local` (built from source), `remote` (`fuz self
  upgrade`), or `bootstrap` (`fuz self bootstrap`). Remote and bootstrap
  artifacts have no `inputs`; a remote one's `outputs` come from the release
  manifest.
- `outputs.fuz` is the binary's blake3. A per-tool install writes a separate
  `ToolMeta` under `~/.fuz/tools/`.
- Read cap 1 MB.

## Build and verification

`create_artifact`'s rustdoc lists the steps: validate and hash the source
binaries before copying (opened `O_NOFOLLOW`, a regular file, 1 KB–100 MB, and
a header `fuz_artifact::platform::inspect_binary` places on the build's target,
the `rustc -vV` host triple — ./release_format.md § Binary platform); adopt a valid artifact already at the hash; otherwise copy
into a `0700` temp dir (`.building-<random>` or `.bootstrapping-<random>`),
re-hash the copies, write `meta.json`, rename to `v1-<content_hash>/`, chmod
`0755`, and fsync the parent. Any failure cleans the temp dir — no partial
artifact is left. Crash-leaked temp dirs are swept by `cleanup_incomplete()`
**under the artifact lock** (an unlocked sweep would delete a concurrent build's
live dir) at the start of `fuz artifact build` and `fuz self bootstrap`.

When the target already exists: a symlink or file there is never adopted (the
entry is unlinked, never its target); a valid artifact with the matching hash is
adopted (dedup, `Stored: <hash>`); a corrupt one (unreadable or mismatched
`meta.json`, a missing or mismatched `fuz`) is replaced; a `fuz` that exists but
fails to open is left alone and the error returned.

`fuz artifact build` (and its `--verify` rebuild) and `cargo xtask install`
never guess where cargo put a binary: they run `cargo build --release
--message-format=json-render-diagnostics` and take each binary's path from the
`executable` of its `compiler-artifact` message
(`fuz_artifact::cargo_build_release`), so `CARGO_TARGET_DIR`,
`build.target-dir`, and a build target move nothing out from under them. A
build for another target (`CARGO_BUILD_TARGET`, or a `build.target` in any
cargo config) is refused after it builds, before anything is stored or
installed: each binary's header is held to the host's target
(`fuz_artifact::check_built_for`, with the target not named, so a static
binary on a glibc host is refused as the musl build it most likely is — a
static glibc build, `+crt-static` in `RUSTFLAGS`, is refused with it). Each
cargo run builds one package: cargo unifies features across the packages of a
run, so `-p fuz -p fuzd` would link a `fuz` no `-p fuz` build reproduces. A
cache hit skips the build and the check; the input hash does not cover the
cargo build target, so a set `CARGO_BUILD_TARGET` with a hit installs the
cached host build.

**Verification** re-hashes the binaries against `outputs` before every switch —
`fuz artifact build` / `use`, `fuz self upgrade`, and `cargo xtask install`, all
through `fuz_artifact::switch_to_artifact`. (`fuz self bootstrap` activates bytes
`create_artifact` just re-hashed.) `fuz artifact verify [hash]` runs it
explicitly. It detects disk corruption, accidental modification, and tampering
by anything other than a same-user attacker.

Every atomic write here — `meta.json`, the `current` symlink, `history.json` —
writes a temp file, fsyncs it, renames, and fsyncs the parent directory.

## Artifact lock

One `flock(2)` on `~/.fuz/run/artifact.lock` serializes every operation that
mutates `artifacts/` or `current`: `fuz artifact build` / `use` / `prune`,
`fuz self bootstrap` / `upgrade`, `cargo xtask install`. A held lock is
`InProgress` (exit 75), naming the holder's pid from the file body. The body is
for humans; the kernel's `flock` is the lock, so crashed holders release
automatically. Mechanics (why the file is never unlinked, why it's not
recursive) are `fuz_sys::file_lock`'s rustdoc.

- The outer command acquires once and passes the guard down as a witness
  (`switch_to_artifact(opts, &lock)`).
- `prune --wetrun` takes the lock before listing the store; the dry run takes none.
- `fuz self upgrade` downloads before it takes the lock, so a prune in that
  window that drops the just-extracted artifact makes the switch fail (exit 1,
  nothing activated; a retry downloads again).

## CLI Commands

| Command | Creates | Activates | Verifies |
| --- | --- | --- | --- |
| `fuz artifact build` | ✓ | ✓ | ✓ |
| `… build --no-install` (CI) | ✓ | | |
| `… build --dry-run` (inputs + cache status) | | | |
| `… build --verify` (rebuild, compare output hashes) | ✓ | ✓ | ✓ |
| `fuz artifact use <hash>` (8+ char prefix) / `use -` (previous) | | ✓ | ✓ |
| `fuz artifact list [--json]` | | | |
| `fuz artifact verify [hash]` | | | ✓ |
| `fuz artifact prune [--keep N] [--wetrun]` (default keep 5 + current; dry run unless `--wetrun`) | | | |
| `fuz artifact log [-n N] [--json]` | | | |

`--quiet` / `-q` (on `build`, `use`, `prune`) suppresses progress, not errors;
a quiet `prune` dry run still says on stderr that it deleted nothing.
**Activation** switches `current` and the `bin/` links. The self artifact is
fuz-only, so a switch never touches fuzd; the "run `fuzd restart`" nudge lives
on `fuz tool install|upgrade fuzd` (./daemon_lifecycle.md).

Hash display: `fuz artifact list` and `fuz tool list` show `v1-` + 8 chars;
`use` takes 8+ chars with or without `v1-` (32 bits — an ambiguous prefix
errors with the full hashes); verification failures and `--json` show full
hashes.

`~/.fuz/state/history.json` records switches, newest first, capped at 100
entries; `use -` switches to the second entry.

## Store Entries

An artifact (`artifacts/v1-<hash>/`) or tool install (`tools/<name>/v1-<hash>/`)
is the real directory fuz renamed into place. A symlink or file at one of those
names is never something fuz wrote, and a link would make every later read
(verify, `current`, `bin/<binary>`) a read of whatever it points at. Each slot
is addressed `(store, name)` with the name one plain path component
(`store_entry_path`), and classified without following a link
(`fuz_sys::fs::probe_real_dir`); the directories above it are resolved as given.
The stores are `0700`, so this is same-user hygiene, not a privilege boundary.

- **Repair** (`reclaim_store_entry`) — paths about to write the slot
  (`create_artifact`, `fuz self upgrade`'s fetch, both tool installs) unlink the
  entry itself and install fresh.
- **Refuse** (`inspect_store_entry`) — paths with nothing to rebuild from
  (switching `current`, reading what `current` or a typed hash names, the
  installed-tool readers) leave it in place. `list` and the build cache skip it.
- `current` is only followed into its own store
  (`current_link_target`) — a link anywhere else, even at a valid copy, isn't
  read through.
- Inside a real install, `meta.json` and every binary are opened `O_NOFOLLOW`
  and must be regular files (`NotRegularFile`, exit 65) — the same hard error as
  a hash mismatch.

**An unreadable current install** (`current` outside its store, a link or file
at the install it names, a corrupt `meta.json`):

- `fuz self upgrade` and `fuz tool install` / `upgrade` refuse it ("current
  install is unreadable", exit 1, a hint naming `--force`) before any download.
  `--force` reclaims the slot and installs fresh, with no rollback target or
  "from" version recorded.
- Every other reader fails and changes nothing (exit 65 for
  `StoreEntryNotDir` / `CurrentNotStoreLink`); `fuz tool list` leaves the tool
  out.
- A `current` that is **not a symlink** is refused by every command that would
  replace it, `--force` included (exit 65, `require_current_replaceable`): fuz
  doesn't remove what it didn't write. Remove it by hand.

## Limitations

- Input capture omits what § Two hashes lists (the glibc version among them).
- No artifact pinning against `prune`.
- Release profile only; host target only.
