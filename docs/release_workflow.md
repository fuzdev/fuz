# Release Workflow

Cutting a fuz release. Formats and the verification flow: ./release_format.md.
Signing: ./signing.md. The release log: ./release_log.md. Storage and its auth:
./storage_backends.md.

`fuz` only fetches and verifies. Producing is `cargo xtask publish` (the
bootstrap `fuz` / `fuzd` / `fuzf`; `publish tool` takes any first-party tool)
and `fuzf tool publish` (the forge client, a separate project), both over
`fuz_sign`.

## Trust root

`crates/fuz_crypto/src/public_keys.json` is the production trust anchor: every
`fuz` build embeds it and verifies releases against it. To publish under your
own trust root (a fork or a self-hosted distribution), run
`cargo xtask key generate`, then put the public key it prints into
`public_keys.json` — replacing the committed key to trust only your releases,
or beside it to trust both.

## Cutting a release

1. **Prepare** — a clean tree with the CI gates green (./testing.md § CI).
2. **Bump** `version` in the workspace `Cargo.toml`.
3. **Build** — `fuz artifact build` then `fuz artifact verify`, creating
   `~/.fuz/artifacts/v1-<hash>/` (./artifacts.md).
4. **Publish** (below).
5. **Tag and push**:

   ```bash
   git add Cargo.toml Cargo.lock
   git commit -m "release v${VERSION}"
   git tag -s "v${VERSION}"
   git push origin main --tags
   ```

## Publishing

**Bootstrap binaries** (`fuz`, `fuzd`, `fuzf` — the ones needed before a forge
client exists) are signed and published with `cargo xtask`:

```bash
# the fuz-only self artifact from ~/.fuz/current: signed manifest, tarball,
# flat binary, sha512 sidecars
cargo xtask publish self --storage /path      # or forge://host, ssh://user@host/path

# a per-tool artifact, the same shape fuzf publishes
cargo xtask publish tool fuzd target/release/fuzd --version 0.3.0 --storage /path
```

Add `--log-repo <clone>` to either to record the release in the release log
(./release_log.md), and `--target <triple>` to label it with a supported target
other than the publisher's own (./release_format.md § Release Manifest). **Other
tools** (zap, zzz, tsv, fuzfd, …) publish with the
forge client in steady state:

```bash
fuzf tool publish zap path/to/zap --version 0.1.0 [--minimum-version 0.1.0] [--target <triple>]
```

### Publishing for another target

A release's target names every key it is stored under; it is the publisher's
assertion, held to each binary's header before anything is signed or uploaded
(./release_format.md § Binary platform). Omitted, it is the publishing
binary's own target. A binary for another architecture, OS, or libc is refused
with a hint naming the `--target` it is for, and a statically linked binary on
a glibc publisher is refused until `--target` names its libc — `…-musl` for a
musl build, `…-gnu` for a static glibc one.

Cross-publishing a tool, from a Linux host (a musl build from macOS needs a
cross linker):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release -p fuzd --target x86_64-unknown-linux-musl
cargo xtask publish tool fuzd target/x86_64-unknown-linux-musl/release/fuzd \
  --version 0.3.0 --target x86_64-unknown-linux-musl --storage /path
```

Each target publishes on its own: its own manifest, tarball, and
`latest-<target>.json`, and for the self artifact its own flat binary and
`fuz-latest-<target>` copy. Publishing one target never moves another's
latest. `publish self` publishes `~/.fuz/current`, which `fuz artifact build`
makes for the host target only (it refuses a binary cargo built for another
target), so a self release for another target needs that target's `fuz`
installed as `current` first.

No credentials file: `forge://` takes the forge bearer token, `ssh://` the
ambient ssh agent or key (./storage_backends.md). A read-only `https://` store
is refused before the key is loaded.

What every publish (`fuz_sign::publish_*`) does, in order:

1. Validates the release: name, version, and target must be usable as storage
   keys (so no semver build metadata, `+…`), binary names must be release
   tokens (./release_format.md § Release Log Files, which a `--log-repo`
   publish holds the other three to as well), and the version and
   `--minimum-version` must be semver (`1.0`, `v1.0.0` are refused; a
   pre-release like `1.0.0-rc.1` is fine), since clients order releases and
   check the floor by them. The floor is at most the release's own version.
2. Holds every binary — the bytes it then signs — to the release's target
   (`--target`, else the publisher's own), and packs the tarball from them.
3. With `--log-repo`, checks the release log can take the release — before
   anything is uploaded.
4. Signs the manifest (`sign_manifest`).
5. Uploads the tarball and manifest (plus, for the self artifact, the
   versioned flat binary and its sidecar) and confirms they landed.
6. With `--log-repo`, records the release in the log.
7. Moves its target's `latest-<target>.json` (plus, for the self artifact,
   `fuz-latest-<target>` and its sidecar).

A landed self release is `fuz-<version>-<target>.tar.gz` and `.manifest.json`,
`fuz-<version>-<target>` and `fuz-latest-<target>` each with a `.sha512`, and
`latest-<target>.json` naming the version (./release_format.md § URL Scheme).

## Pruning Old Releases

`cargo xtask prune --storage <uri> [--tool <name>] [--keep N]` removes a
stream's releases past the newest `N` versions (default 5), always keeping the
version each `latest-<target>.json` names. It is a dry run unless `--wetrun`, and the dry run
lists every key it would delete. It deletes only keys it derives from a
release: the manifest the listing found, the tarball
`<name>-<version>-<target>.tar.gz`, and for a self release the flat binary
`fuz-<version>-<target>` and its `.sha512` sidecar. The moving
`fuz-latest-<target>` copy is never deleted.

A manifest whose `version` and `target` do not build its own key back, whose
`tarball.path` names any other file, or whose version is not semver (a legacy
release) refuses the whole prune before anything is deleted, and the error
names its key. Inspect that key, delete or restore the manifest by hand (with
the rest of its release, if the release is to go), and run the prune again.
After an interrupted wet run, run it again with the same `--keep`: each
release's manifest is deleted last, so the re-run finishes what it started.

Prune reads no release log. After a revoke has moved the log's `latest/`
pointer to an older release, publish the fixed release first (it moves
the latest pointer and the log's `latest/` together), or raise `--keep` until the
dry run no longer lists the version the log's `latest/` names: `install.sh`
with `FUZ_RELEASE_LOG_URL` set downloads the flat binary that pointer names.

## Security Releases

Ship a security fix as an ordinary signed release and leave `minimum_version`
alone — raising it makes vulnerable clients refuse the very update that fixes
them (./security-model.md § Rollback). A compromised key means every install
re-bootstraps (./security-model.md § Key Compromise Response).

## Local Testing

Before shipping, test the full publish/upgrade cycle locally against a local
storage directory. Publish with `cargo xtask publish` (below), then exercise the
consumer path on `fuz`. (`fuzf tool publish` publishes to a forge only — it
takes `--server`, not `--storage` — so it can't target a local directory.)

Run from the repo root:

```bash
# 0. Isolate: keep the test-key build out of your real ~/.fuz, and skip the
#    release log check (a local store is in no log)
export FUZ_HOME=/tmp/fuz-test-home
unset FUZ_RELEASE_LOG_URL

# 1. Generate a test signing key, and trust it: add its public key (printed by
#    `key export`) to crates/fuz_crypto/src/public_keys.json. `fuz` verifies
#    against the keys embedded at build time, so without this every install
#    below is refused as untrusted. This is local-only: never commit the edit,
#    and never run a `fuz` built with it outside this test home.
cargo xtask key generate --output /tmp/test-signing.key
cargo xtask key export --key-file /tmp/test-signing.key

# 2. Create a local storage directory
mkdir -p /tmp/fuz-releases

# 3. Build (embedding the test key), install that `fuz` into the test home,
#    and put it first on PATH for this shell
cargo build --release -p fuz -p fuzd
target/release/fuz self bootstrap --no-modify-path
export PATH="$FUZ_HOME/bin:$PATH"

# 4. Publish a tool artifact to local storage
cargo xtask publish tool fuzd target/release/fuzd --version 0.3.0 --storage /tmp/fuz-releases --key-file /tmp/test-signing.key

# 5. Verify the manifest was created
cat /tmp/fuz-releases/tools/fuzd/latest-*.json
ls /tmp/fuz-releases/tools/fuzd/*.manifest.json

# 6. Install (fetch + verify + install) on the consumer side
fuz tool install fuzd --storage /tmp/fuz-releases

# 7. For the fuz self artifact: publish it (xtask), then exercise upgrade
#    (it reports "already at latest": the published artifact is the installed
#    one, but the manifest fetch and signature check still run)
cargo xtask publish self --storage /tmp/fuz-releases --key-file /tmp/test-signing.key
fuz self upgrade --storage /tmp/fuz-releases

# 8. Verify state
fuz self status
fuz tool list

# 9. Clean up: drop the test key from the trust anchor, rebuild so
#    target/release no longer embeds it, and discard the test home, the storage
#    directory, and the key. Open a new shell (or unset FUZ_HOME and restore
#    PATH) before using your real install again.
git checkout crates/fuz_crypto/src/public_keys.json
cargo build --release -p fuz -p fuzd
rm -rf /tmp/fuz-test-home /tmp/fuz-releases /tmp/test-signing.key
```

**For CI**: Use ephemeral keys and temp directories. Never commit test keys.
