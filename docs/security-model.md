# Security Model

Trust model, bootstrap trust, local integrity, rollback, and incident response
for fuz distribution. Signing mechanics: ./signing.md. Version-safety mechanics
(errors, exit codes, `--check`): ./release_format.md § Version Safety. The
release log check: ./release_log_check.md. Deferred hardening:
./deferred_security.md.

## Trust Model

Two trust models for two kinds of user:

- **Source builds** (`cargo build`, `fuz artifact build`): no signature
  verification — the user trusts their checkout. The embedded public key is used
  only when fetching remote releases.
- **Binary downloads**: download a signed release, verify it against the
  embedded public key, install. Trusting the first binary means trusting every
  future release signed by its embedded key.

**Unsigned text.** A `latest-<target>.json` pointer, a manifest before verification, forge
bodies, `ssh` stderr, and a head that doesn't verify are attacker-controlled;
every error escapes and bounds what it repeats (./crates.md § Error rendering),
and `scripts/install.sh` prints them as printable ASCII.

## First Binary Bootstrap

The first release is chicken-and-egg: no existing fuz can verify it. No public
release host is live yet — today the only way to get a first `fuz` is to build
it. Once the hosted install script is live (not yet), most users will run

```bash
curl -sSf https://www.fuz.dev/install.sh | sh
```

`www` is explicit: the apex redirects, and `curl -sSf` without `-L` would pass
the redirect page to `sh`. The install has two origins — the script from
`www.fuz.dev` (static, on GitHub Pages), the binary from the release host
(`releases.fuz.dev`). This is the rustup / Homebrew model, so we say what it
does and doesn't protect rather than implying users verify signatures.

What each part trusts:

- **The script**: DNS and TLS for `www.fuz.dev`, the fuz.dev site and its
  GitHub Pages deploy, and `scripts/install.sh` in this repository (its
  source). Every check the install makes is code in the script.
- **The binary, by default** (`FUZ_RELEASE_LOG_URL` unset; the script has no
  built-in release log origin): DNS, TLS, and the integrity of the release
  host. The digest is the `.sha512` sidecar on that same host, so it catches a
  corrupted download, not a compromised host.
- **The binary, with `FUZ_RELEASE_LOG_URL` set**: the digest and version come
  from a release log origin, and the release host supplies only bytes, so a
  release host serving tampered bytes is refused
  (./release_log_check.md § The install script). This trusts the first log
  origin that answers (its DNS, TLS, and host): the pointer is unsigned and the
  script reads no other origin.

What it doesn't protect against:

- **A compromised release host, by default.** Without a release log origin the
  host serving the bytes also serves their digest.
- **A compromised script origin.** A rewritten script can skip the release log
  read, fake its output, or fetch anything; that reaches whoever can change
  `scripts/install.sh` here or the fuz.dev site that serves it, its Pages
  deploy, or DNS for `www.fuz.dev`.
- **A GitHub-side compromise.** The script is served by GitHub Pages and the
  public release log is planned as a GitHub repository, so GitHub, or the
  account that publishes both, reaches the script and the log together.
- **A tampered script, in general.** `curl | sh` verifies no signature on the
  script; it runs what arrives.
- **A substituted binary, from inside it.** `fuz self bootstrap` holds the
  binary to the signed head, but that check runs in the downloaded binary;
  against substitution the gate is the script's digest compare.
- **An older release on a first install.** Without the log the release host
  picks the version. With it, whoever controls the first log origin picks it,
  and any logged release that isn't revoked is accepted; a stale origin also
  hides a newer revocation (./release_log_check.md § Limits).
- **A compromised release key.** The same key signs releases and the log's
  head (./release_log_check.md § Limits; recovery: § Key Compromise Response
  below).

The release host will also publish the script's digest, and the release log
will record the script as a row with its SHA-512 (both planned, not yet live).
They help only someone who downloads the script, compares it, then runs it:
tampering with the script then needs both `www.fuz.dev` and the release host.
The binary is still trusted to the release host unless `FUZ_RELEASE_LOG_URL` is
set (no public origin exists yet):

```bash
curl -sSfO https://www.fuz.dev/install.sh
curl -sSfO https://releases.fuz.dev/install.sh.sha512
sha512sum -c install.sh.sha512   # macOS: shasum -a 512 -c install.sh.sha512
sh install.sh   # or: FUZ_RELEASE_LOG_URL=<origin> sh install.sh
```

What signatures provide: after the first install, `fuz self upgrade` verifies
every release against the embedded key, so a MITM can't inject an update;
security-conscious users and auditors can verify by hand.

**Establishing a trust root** (a fork or self-hosted distribution): the key in
`crates/fuz_crypto/src/public_keys.json` is the production anchor; to publish
under your own, generate a key, embed its public half, build, and publish
(./release_workflow.md § Trust root). `fuz` itself never signs or publishes.

### Manual verification

`<release-host>` stands for wherever a self artifact was published over HTTPS;
the names are the on-storage layout (./release_format.md § URL Scheme).

```bash
curl -fLO https://<release-host>/fuz-<version>-<target>
curl -fLO https://<release-host>/fuz-<version>-<target>.sha512
curl -fLO https://<release-host>/fuz-<version>-<target>.manifest.json
curl -fLO https://<release-host>/latest-<target>.json

# 1. Integrity: the binary matches its sidecar (install.sh's check without a release log)
sha512sum -c fuz-<version>-<target>.sha512
# 1b. With a release log origin: its pointer must name this <version> and pass the same check
curl -fL -o log-pointer.sha512 https://<release-log>/latest/fuz-<target>.sha512
sha512sum -c log-pointer.sha512
# 2. The manifest pins this binary: `binaries.fuz` is its blake3, bare lowercase hex
b3sum fuz-<version>-<target>
grep '"fuz"' fuz-<version>-<target>.manifest.json
# 3. The manifest names a key you trust (compare with public_keys.json in a trusted checkout)
grep public_key fuz-<version>-<target>.manifest.json

chmod +x fuz-<version>-<target> && ./fuz-<version>-<target> self bootstrap
```

Steps 1–3 show the bytes are intact and that the manifest *claims* a trusted
key; they don't check the signature. To check it by hand, verify the ed25519
`signature.sig` over `fuz-manifest-v1`, a NUL byte, then the manifest's
canonical JSON without its `signature` field (./signing.md § Signed Bytes). Or
let a `fuz` you already trust do it: with the files in one directory,
`fuz self upgrade --storage . --check` verifies the signed manifest `latest-<target>.json`
names for this machine and installs nothing — exit 0 or 10 means it verified
(`--json` reports `verified: true`).

## Local `~/.fuz` Integrity

Signatures protect the download; a separate guard protects the installed tree.
fuz refuses a pre-existing `~/.fuz` that is **world-writable** (`0o002`) — a
home any local user can write would let them swap `bin/fuz` and get code
execution on the victim's next run — failing closed with a `chmod 700 ~/.fuz`
hint.

- **Where it runs**: home creation (`ensure_fuz_home`) and every path that
  installs a binary into the home — `fuz self upgrade`, `fuz tool install` /
  `upgrade`, and the local tool install behind `cargo xtask install` — first
  thing, before any download or copy
  (`fuz_home::check_fuz_home_not_world_writable`). A `--storage` install also
  refuses names outside `FIRST_PARTY_TOOLS` and verifies a signature; the local
  one installs what `cargo xtask` hands it.
- **Not covered** — so the guard isn't over-trusted: `fuz artifact build` /
  `use` / `prune`, log writing and rotation, and fuzi's npm cache. A
  world-writable home is caught the next time fuz creates the home or installs a
  binary, not on every write. The read-only `--check` flows stay outside it.
- **Deliberately narrow**: group-write isn't flagged (a `0775` home is routine
  under private-group schemes); another user's tight-permission home fails on
  `EACCES` anyway.
- **TOCTOU residual**: the check runs up front (fail fast, before a network
  round trip), not at the rename; a home flipped world-writable mid-install
  isn't re-checked.

**fuz never makes a permissive directory.** Every directory it creates under
`~/.fuz`, the home included, names its mode instead of inheriting the umask
(./fuz_home.md § Directory Modes) — write permission on the home alone would let
someone substitute `bin/`, which the guard (it inspects `~/.fuz`, not its
children) can't catch. Directories fuz creates outside the home keep ordinary
modes.

**Links in the stores are not read through** (./artifacts.md § Store
Entries); a fetched slot name is the signed `content_hash`, held to `v1-` + 64
lowercase hex at parse. The stores are `0700`, so this is same-user hygiene,
not a boundary against a same-user attacker.

## Rollback

Signatures don't expire, so old signed releases stay valid. What refuses one,
for `fuz self` and `fuz tool` alike: no-downgrade against the installed version
(`--allow-downgrade` overrides), the `minimum_version` floor, refusing an
unreadable current install unless `--force`, `Manifest::check_key` (a manifest
is only the release at the key it was read from), and `--check` reporting the
**signed** version, so a tampered latest pointer can neither fake an update nor
mask a floor (./release_format.md § Version Safety). A fresh install skips the
version checks (there is no installed version to compare); `check_key` still
applies.

**`minimum_version` is a compatibility floor, not a vulnerability floor.** It is
checked against the installed version of the same stream (`current`'s
`meta.json`), so raising it **excludes older installs**. Never raise it to force
users off a vulnerable version: every vulnerable client would then refuse the
fix (`BelowMinimum`) and have to re-bootstrap through `install.sh`, which by
default checks integrity but not authenticity — a weaker path than the signed
upgrade it replaced. Ship the fix as an ordinary release. Raise the floor only
for a real format incompatibility, and keep a signed old-format bridge release
published so excluded clients keep an authenticated route forward. A "minimum
safe installed version" has no signed representation today.

Users who never upgrade stay vulnerable — there is no remote kill switch, by
design. With a release log configured, a revoked installed version is at least
announced on every `fuz self` command.

## Key Compromise Response

**A catastrophic failure mode.** An attacker with the signing key can sign
releases every `fuz self upgrade` will accept, and the release log doesn't
help — the key signs heads too. **Speed is the mitigation**: fix it within
hours. During the window, an attacker reaches only users who upgrade from
storage the attacker controls.

**While one key is embedded, every install must re-bootstrap.** An installed
`fuz` trusts exactly the keys built into it: it keeps trusting the compromised
key until its binary is replaced, and it cannot verify a release signed by a new
key. Removing the old key protects only binaries built afterwards. An offline
root key that could sign a key rotation is deferred (./deferred_security.md).

Incident response (within hours):

1. Generate a new signing key.
2. Rotate the forge API token and SSH deploy keys.
3. Replace the compromised key in `public_keys.json` and build.
4. Sign and publish a new release with the new key.
5. Republish the bootstrap binary (and the hosted install script's target).
6. Post an advisory naming the affected version hashes and telling every user
   to re-bootstrap from the install script.

Raising `minimum_version` to skip attacker-signed versions changes nothing for
installed clients (they verify against the compromised key regardless) and
costs the exclusion above — don't treat it as a step.

Detection: a public release log and out-of-band published hashes would make an
unexpected release visible; neither exists yet, and storage monitoring isn't
built (./deferred_security.md).

Signing-key hygiene: ./signing.md § Architecture, plus a secure offline backup.
Threshold signing and hardware keys are deferred.
