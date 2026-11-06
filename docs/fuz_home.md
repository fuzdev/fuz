# FUZ_HOME

`~/.fuz/` holds all fuz configuration, state, and runtime data. The paths are
`fuz_home`'s `get_*` helpers (its rustdoc); the artifact store's side is
./artifacts.md.

## Structure

```
~/.fuz/                     # Root (0700)
├── artifacts/              # Self-artifact store (0700)
│   └── v1-<hash>/          # One artifact (0755): fuz + meta.json
├── current -> artifacts/v1-<hash>
├── tools/                  # Per-tool installs (0700) — fuzd, zap, …
│   └── fuzd/
│       ├── v1-<hash>/      # fuzd + meta.json (0700)
│       └── current -> v1-<hash>
├── bin/                    # Stable PATH entries (0700)
│   ├── fuz -> ../current/fuz
│   └── fuzd -> ../tools/fuzd/current/fuzd   # only if fuzd is installed
├── config/                 # (0700)
│   └── signing.key         # Publisher signing key (0600)
├── run/                    # Runtime, ephemeral (0700)
│   ├── daemon.json         # pid + socket path + schema version (0600)
│   ├── socket              # fuzd's UDS (0600)
│   ├── socket.lock         # fuzd's socket ownership lock (flock, 0600)
│   └── artifact.lock       # every build / `current` change (flock)
├── cache/                  # Regenerable (0700)
│   └── npm/                # fuzi's tarball CAS: sha512-<hex>/package.tgz (unsealed)
└── state/                  # Persistent (0700)
    ├── history.json        # Artifact switch history
    ├── release_log/head.json  # Last accepted release log head (0600; only with
    │                          # FUZ_RELEASE_LOG_URL, written by an install or bootstrap)
    └── logs/daemon_output.log # 0600; rotated to .1 … .3 on `fuzd start`
```

Each install directory is named by its content hash: `v1-` and 64 lowercase
hex, the BLAKE3 over its binaries (./artifacts.md § Two hashes; every digest
form: ./release_format.md § Digest formats).

The only symlinks are the ones drawn — `current`, `tools/<name>/current`, and
`bin/*`. Everything they lead to is a real directory or regular file, classified
without following a link (./artifacts.md § Store Entries). `fuzd start` checks
the home before creating anything under it and opens the daemon log without
following a link (anything but a regular file refuses the start); `fuzd logs`
opens it the same way, and refuses a symlink or non-regular file that replaces
it mid-follow the same way.

`run/` survives a reboot on disk but holds session data; stale `daemon.json` and
socket files are cleaned automatically (./daemon_lifecycle.md § Behavior
Matrix). The `.lock` files are never removed (`socket.lock`:
./daemon_lifecycle.md § Socket ownership; `artifact.lock`:
`fuz_sys::file_lock`'s rustdoc).

## Ownership

- `artifacts/`, `current` — `fuz artifact build` / `use`, `fuz self bootstrap` /
  `upgrade`, `cargo xtask install`.
- `tools/` — `fuz tool install` / `upgrade`, and `cargo xtask install` (fuzd,
  via `install_local_tool`).
- `bin/` — the same writers as `current`, plus tool installs (`bin/<tool>`).
- `config/` — `cargo xtask key generate`.
- `run/` — the CLI, except fuzd's `socket` and `socket.lock`.
- `cache/` — `fuzi`, which leaves a crashed download's `cache/npm/.dl-<rand>`
  until it is an hour old, since a younger one may be another fuzi's.
- `state/` — the CLI.

The daemon writes nothing but `run/socket` and `run/socket.lock`, and it never
reads or writes `daemon.json`. It creates `run/` (and `~/.fuz` itself, if
missing) at `0700` and chmods `run/` `0700` at bind, re-tightening one a laxer
run left.

## PATH

`bin/` is the one directory to put on `PATH`. bash / zsh (`~/.bashrc`,
`~/.zshrc`):

```bash
export PATH="$HOME/.fuz/bin:$PATH"
```

fish: `fish_add_path ~/.fuz/bin`.

`cargo xtask install` edits no rc file; on a first install it prints the line to
add (fish's when `fish` is installed). `fuz self bootstrap` manages one marked
block in the shell rc file (`# >>> fuz initialize >>>` … `# <<< fuz initialize
<<<`) putting `$FUZ_HOME/bin` on `PATH`; bootstrapping under another `FUZ_HOME`
repoints that block while it still holds the single line fuz wrote. An edited
block, or an rc that is a dangling link, not a regular file, or read-only, is
left as found with a note giving the line. `--no-modify-path` leaves the rc
alone.

## Directory Modes

Every mode above is **set**, never inherited from the umask (a plain
`create_dir_all` would land `0777` under `umask 000`, routine in containers).
Each create names its mode — `ensure_fuz_home` for the dirs it makes (not
`tools/` or `cache/`, which their owners create), and
`fuz_sys::fs::create_dir_all_mode` for on-demand creates — and that includes
`~/.fuz` itself, since several flows (the artifact lock, the daemon's bind, the
tool installs, the release log cache, fuzi) can be the first to mint the home on
a fresh machine. The only non-`0700` directory is a *finished* artifact
(`0755`), set after its staging dir is renamed into place.

A pre-existing directory keeps its mode — fuz doesn't re-tighten what a user
loosened, except the daemon's `run/` chmod above. Refusing to write into a
world-writable home is a separate check (./security-model.md § Local `~/.fuz`
Integrity). The test legs that keep this honest: ./testing.md § The `umask 000`
leg.

## Environment

- `FUZ_HOME` (default `~/.fuz`) — empty reads as unset; a relative one is
  refused. fuzd's socket (`$FUZ_HOME/run/socket`) must fit a Unix socket address
  (107 bytes on Linux), so a longer `FUZ_HOME` makes `fuzd` refuse to start with
  a hint (under `fuzd start`, in the daemon log).
- `HOME` — where the default lives, read through `fuz_sys::home_dir` like every
  `$HOME` path fuz uses (the forge token, the rc file, the default source repo,
  `~` in a storage path or local log origin). It must be non-empty and absolute,
  never resolved under the cwd; an empty or relative `HOME` is an error, and
  `fuz self bootstrap` then skips the rc edit with a note. Only an unset `HOME`
  falls back to the password database. `scripts/install.sh` also refuses an
  unset one.

An unresolvable home is an error (exit 1) with a hint naming the variable,
except on `fuz self version` / `status`, which are diagnostics: they warn, exit
0, and report what lives under the home as unknown (`fuzd: unknown`; `"fuzd":
null` under `--json`).
