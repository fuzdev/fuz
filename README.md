# Fuz

> the fuz CLI, fuzd daemon, and Rust crates beneath the Fuz stack's servers 🗝 pre-alpha

This Rust workspace holds:

- `fuz` - installs first-party tools as signed, blake3-pinned binaries,
  verified against a public key embedded in `fuz`
- `fuzd` - an optional daemon for demand-driven workloads:
  a system observer and a filesystem watcher
- `fuzi` - an npm installer that materializes `node_modules` from a `package-lock.json`
  without resolving versions or running package code
- the spine crates - Rust twins of [fuz_app](https://github.com/fuzdev/fuz_app)'s
  server layers (database, auth, HTTP, realtime, actions, and the cell and fact
  content primitives) for building app servers

Each crate is described in [docs/crates.md](docs/crates.md).
APIs, CLI surfaces, wire protocols, and on-disk formats break without notice.

This repo is part of the Fuz stack
([fuz.dev](https://www.fuz.dev/), [@fuzdev](https://github.com/fuzdev)).

AI disclosure: this codebase is LLM-generated with uneven human review.

## Usage

There is no release channel, so building from source is the only way to install.
It needs Linux, git, and rustup:

```bash
git clone https://github.com/fuzdev/fuz && cd fuz
cargo xtask install              # build fuz + fuzd, install them into ~/.fuz, (re)start the daemon
cargo build --release -p fuzi    # optional, builds target/release/fuzi
```

Then put `~/.fuz/bin` on your `PATH` ([docs/fuz_home.md](docs/fuz_home.md#path)).
`fuzi` isn't installed into `~/.fuz`: run `target/release/fuzi`, or copy it onto your `PATH`.

```bash
fuz self status                            # version, current artifact, daemon
fuz tool install <name> --storage <uri>    # install a first-party tool
fuz workload observe process               # system and process snapshot, needs fuzd
fuzi install                               # node_modules from package-lock.json
```

No public storage is hosted for `--storage`
([docs/storage_backends.md](docs/storage_backends.md)).
Every command takes `--help`; the full command reference is in [CLAUDE.md](CLAUDE.md)
and the architecture in [docs/](docs/).

## Contributing

[fuz.dev/contributing](https://www.fuz.dev/contributing)

## Security

Report vulnerabilities through the [fuzdev security policy](https://github.com/fuzdev/.github/blob/main/SECURITY.md).
The trust model for signed releases is in [docs/security-model.md](docs/security-model.md),
and known gaps are in [docs/deferred_security.md](docs/deferred_security.md).

## License [🐦](https://wikipedia.org/wiki/Free_and_open-source_software)

[0BSD](LICENSE)
