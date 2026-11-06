# Release Format

The wire spec for distribution: manifest, storage keys, release log files,
digest formats, tarball, the verification flow, and version safety.
Implemented in `fuz_release` (./crates.md § `fuz_release`). Cutting a
release: ./release_workflow.md. Writing the log: ./release_log.md.
Signing: ./signing.md. Storage backends: ./storage_backends.md. Local
artifacts: ./artifacts.md.

## Release Manifest

A signed JSON manifest describing one release, downloaded before the tarball:

```json
{
  "format": 1,
  "version": "0.3.0",
  "content_hash": "v1-abc123...",
  "target": "x86_64-unknown-linux-gnu",
  "minimum_version": null,
  "tarball": {
    "path": "fuz-0.3.0-x86_64-unknown-linux-gnu.tar.gz",
    "blake3": "def456...",
    "size": 12345678
  },
  "binaries": { "fuz": "aaa111..." },
  "signature": { "format": 2, "public_key": "base64...", "algorithm": "ed25519", "signed_at": "2025-01-15T10:30:00Z", "sig": "base64..." }
}
```

- `format` — manifest format version (`MANIFEST_FORMAT_VERSION`, 1).
- `version` (semver), `target` (platform triple) — the **publisher's
  assertion**, checked against each binary. The supported targets are a
  closed set: `{x86_64,aarch64}-unknown-linux-{gnu,musl}` and
  `{x86_64,aarch64}-apple-darwin` (`fuz_artifact::platform::ReleaseTarget`).
  A publish takes it from `--target`, else the publishing binary's own, and
  refuses before anything is signed unless every binary's header is an
  executable for it (§ Binary platform); a client checks the same after
  extraction (§ Verification Flow, step 12).
- `content_hash` — the artifact content hash (`v1-<blake3>`), the same as the
  local artifact directory name (./artifacts.md § Two hashes). **Stable** —
  changing the algorithm breaks every artifact and signature.
- `minimum_version` — the oldest installed version of this stream (fuz
  itself, or the tool) allowed to upgrade to it, or `null`; a fresh install is
  exempt (§ Version Safety).
- `tarball.path` — a plain file name; a publish writes
  `<name>-<version>-<target>.tar.gz` (`ReleaseLayout::tarball_filename`) and
  prune refuses any other; `tarball.blake3`, `tarball.size`.
- `binaries` — binary name → blake3.
- `tool` — present for a **per-tool artifact** (`"tool": "fuzf"`), omitted for
  the fuz self artifact (and so absent from its signed bytes). A tool name must
  be in the `FIRST_PARTY_TOOLS` allowlist; its `binaries` map is the
  authoritative binary set (fuz carries no per-tool table). The self artifact
  declares `fuz` alone (`SELF_BINARIES`); fuzd ships as its own tool.

### What's Signed

The signature covers `fuz-manifest-v1` + NUL, then the canonical JSON of every
field but `signature` (./signing.md § Signed Bytes). The producer signs with
`fuz_sign::sign_manifest`; the consumer verifies with
`Manifest::verify_signature`; both build the bytes with
`fuz_crypto::SignedMessage::new`.

**Authenticity scope**: the signature covers `fuz tool install` and
`fuz self upgrade` end to end, not the `install.sh` flat-binary path
(./security-model.md § First Binary Bootstrap). The publisher reads the binary
once for both, so the flat binary, its sidecar, and the manifest describe one
byte string.

### Validation

On parse (`Manifest::from_json`):

1. Format version ≤ supported (`UnsupportedFormat`).
2. `tarball.path` is a plain file name (no `/`, `\`, `..`, leading `.`).
3. `content_hash` is `v1-` + 64 lowercase hex (`fuz_artifact::is_content_hash`)
   — it names the install directory before the download verifies it, so a
   path-shaped value is refused first (`InvalidContentHash`). Binary names are
   tokens (§ Release Log Files; `InvalidBinaryName`) — each becomes a path
   component and is joined into the content hash with `:` and `\n`. Digests
   are 64 lowercase hex — an uppercase spelling is refused, not read as the
   same hash (§ Digest formats).
4. `tarball.size` ≤ `MAX_TOTAL_SIZE`.
5. No `testing_`-prefixed binary (`check_no_test_binaries`).
6. A self manifest's `binaries` equal `SELF_BINARIES` (`MissingBinary` /
   `UnexpectedBinary`); a tool manifest names a `FIRST_PARTY_TOOLS` tool
   (`ToolNotAllowed`), declares a non-empty set (`EmptyBinaries`), and names no
   self binary (`ReservedBinaryName`).

Unknown fields are refused (`deny_unknown_fields` — any schema change is a
format bump), and so is a repeated key: a repeated field by serde, a binary
named twice by `fuz_crypto::unique_map` (a last-wins reader and a first-wins
reader would otherwise see different digests under one signature).

After parse, the **self fetch** rejects a manifest that declares a `tool` (the
wrong artifact kind at the self key), and both fetch paths hold the verified
manifest to the key it was read from (`Manifest::check_key`): its `version` and
`target` must rebuild that key. The key is chosen before anything at it is read
— from `fuz tool install --version` or the unsigned latest pointer — so another
release's signed manifest served there is refused (`KeyMismatch`, a security
violation).

### URL Scheme

```
# fuz self artifact (flat, at the storage root)
<root>/fuz-0.3.0-x86_64-unknown-linux-gnu.tar.gz
<root>/fuz-0.3.0-x86_64-unknown-linux-gnu.manifest.json
<root>/latest-x86_64-unknown-linux-gnu.json            # {"version": "0.3.0"}

# self artifact only: the flat binary + sha512 sidecars install.sh reads
<root>/fuz-0.3.0-x86_64-unknown-linux-gnu
<root>/fuz-0.3.0-x86_64-unknown-linux-gnu.sha512
<root>/fuz-latest-x86_64-unknown-linux-gnu
<root>/fuz-latest-x86_64-unknown-linux-gnu.sha512

# install script digest (planned; not a ReleaseLayout key)
<root>/install.sh.sha512                              # sha512 of https://www.fuz.dev/install.sh

# per-tool artifact (under tools/<name>/)
<root>/tools/fuzf/fuzf-0.1.0-x86_64-unknown-linux-gnu.tar.gz
<root>/tools/fuzf/fuzf-0.1.0-x86_64-unknown-linux-gnu.manifest.json
<root>/tools/fuzf/latest-x86_64-unknown-linux-gnu.json
```

`ReleaseLayout` is the single source of these keys. They're **storage keys**,
resolved through whichever backend `--storage` selects (a forge's file store,
an `ssh://` host, an `https://` base, a local directory). `fuzf` and `fuzfd`
are separate single-binary tool artifacts. The public release host
(`https://releases.fuz.dev/<key>`, `install.sh`'s default) is planned, not
live.

The public host will also serve `install.sh.sha512` at its root — the digest
of the script served at `https://www.fuz.dev/install.sh`, in the same sidecar
format and hash as the binaries' (`<128 lowercase hex>  install.sh`). It is
not a `ReleaseLayout` key and no publish command writes it yet.

Every key is per target, the version pointer included:
`latest-<target>.json` (`ReleaseLayout::latest_key`). A publish moves only its
own target's pointer, so publishing one target never moves another's, and a
client resolves the latest release *for its own target* — with none, it
reports that no release is published for its target (`NoReleaseForTarget`). A prune protects the
version every per-target pointer names.

The pointer is **unsigned**: it selects a release, and `check_key` keeps it
from relabeling one (why that suffices: ./security-model.md § Rollback).

### Binary platform

`fuz_artifact::platform::inspect_binary` reads what a binary's header says it
is for, from its first 64 KiB (a header, program header table, or interpreter
path past that is refused as malformed):

- **ELF** — 64-bit little-endian, `ET_EXEC` or `ET_DYN`, `e_machine` x86_64 or
  aarch64. A `PT_INTERP` of `ld-linux-x86-64.so.2` / `ld-linux-aarch64.so.1`
  is a glibc dynamic binary, `ld-musl-<arch>.so.1` a musl one (matched on the
  path's last component, the architecture held to `e_machine`'s); none is a
  static binary (static-pie included), except an `ET_DYN` with no entry
  point, which is a shared library and is refused.
- **Mach-O** — `MH_MAGIC_64`, `MH_EXECUTE`, x86_64 or arm64; a universal (fat)
  file is refused, in either byte order.

`check_binary_target` holds it to the target: another architecture or OS is
refused; a dynamic binary must use the target's libc; a static binary of the
target's architecture is accepted when the target was **named** (`--target`,
or the signed label a client reads) on either libc, and when defaulted to the
publisher's own only if that is musl — a static binary on a glibc host is most
likely a musl build that wants the musl label.

## Release Log Files

The release log is a git repository separate from release storage. Writers:
./release_log.md. Readers: ./release_log_check.md.

```
head.json                                       # the signed head: every release as a row
latest/fuz-x86_64-unknown-linux-gnu.sha512      # self artifact only, one per target
witness                                         # a co-signer's fork only
```

**`head.json`** (`fuz_release::release_log`, written by `Head::to_json`):
`format`, `seq`, `keys` (each `public_key`, `added_at`, and an optional
`retired_at`), `rows`, and an embedded `signature` over
`fuz-release-log-head-v1` + NUL and the canonical JSON of the rest. Each row is
`name`, `version`, `status` (`ok` | `revoked`), `published_at`, and a `targets`
map; each target carries the manifest's `content_hash` and `binaries`, plus,
for the self artifact, the flat binary's `sha512`. A publish always records the
`sha512`; a self row without one (backfilled with `--allow-missing-flat`)
vouches for no flat binary.

A `name`, `version`, target, and binary name are each a **token**
(`fuz_artifact::is_release_token`): ≤ 128 bytes of `A-Za-z0-9._-`, starting
with a letter or digit (a storage key segment's characters — so no `+`, and no
semver build metadata). A reader refuses a head holding anything else; a
`--log-repo` publish refuses such an entry before it opens the checkout. A
manifest holds its binary names to the same rule, so every publish refuses a
binary name that isn't one before its first upload, log or no log.

**`latest/<name>-<target>.sha512`** is one line in the sidecar format, naming
the **versioned** flat binary as keyed in storage, so one file gives a shell
both digest and version:

```
<128 lowercase hex>  fuz-0.3.0-x86_64-unknown-linux-gnu
```

It tracks the self stream's latest release (how publish, backfill, and revoke
move it: ./release_log.md). Tools publish no flat binary and get no pointer.
Pointers are unsigned — the signed record is the row. `install.sh` accepts
exactly one newline-terminated line ≤ 1024 bytes: a 128-hex digest (either
case), exactly two spaces, and `fuz-<version>-<target>` for its own target, with
a version that isn't `latest`, only `A-Za-z0-9._-`, and no `..`.

**`witness`** — only on a co-signer's fork, never written by a publish:

```
<seq> <128 lowercase hex>
-----BEGIN SSH SIGNATURE-----
<base64 lines>
-----END SSH SIGNATURE-----
```

The first line is the statement: the head's `seq` (decimal, no sign, no leading
zero), one space, the SHA-512 of the `head.json` bytes served beside it, a
newline. Then the armored signature `ssh-keygen -Y sign -n fuz_release_log`
writes for a file holding exactly that line, by an ed25519 key. Nothing before,
between, or after (the armor's final newline is optional). `fuz` reads it only
from an origin with an embedded key, at most 4242 bytes.

## Digest formats

Every digest form fuz writes or reads, and how strictly each is read. Hex is
written lowercase with no trailing newline (a sidecar line ends in one, as
`sha512sum` writes it); "strict" means exactly the written form, any other
spelling refused rather than read as the same digest.

| Form | Where | Read |
| --- | --- | --- |
| BLAKE3, 64 hex | manifest `tarball.blake3` and `binaries`; head `binaries`; `meta.json` `outputs` (self) / `binaries` (tool) | strict (`ContentHash::from_lower_hex`, the `blake3_hex` adapters) |
| `v1-` + 64 hex (BLAKE3 over `name:hash` lines, ./artifacts.md § Two hashes) | manifest and head `content_hash`; `meta.json` `hash` / `content_hash`; store directory names | strict (`fuz_artifact::is_content_hash`); a `meta.json`'s is re-derived and compared |
| BLAKE3, 64 hex | `meta.json` `inputs.input_hash`, the build cache key | compared as written; never trusted, only matched |
| SHA-512, 128 hex | head `sha512` (the flat binary) | strict |
| `<128 hex>  <name>\n` | `<binary>.sha512` sidecars and the `latest/` pointer | strict on the producer side (`parse_sidecar`: one line, two spaces, lowercase); `install.sh` folds the digest's case, reads a sidecar's first field, and holds a pointer to the shape above |
| `<seq> <128 hex>\n` | the witness statement | strict (canonical decimal `seq`, one space, lowercase) |
| `<algo>:<hex>` | errors and fact addresses only, never a release field (`ContentHash::parse_prefixed`; a fact address is `blake3:` alone, ./crates.md § `fuz_crypto`) | strict |
| `sha512-<padded base64>` (SRI) | npm `integrity`, read by fuzi | canonical base64, the sha512 token selected (other algorithms ignored, a malformed token of an algorithm fuz models refused, two different sha512 digests refused); a value without one, `sha1-`-only included, is refused |
| `sha512-<128 hex>` | fuzi's CAS directory names (`cache/npm/`) | written only, never parsed |

## Tarball

Binaries at the root, nothing else — no subdirectories, no `meta.json` (metadata
lives in the manifest):

```
fuz-0.3.0-x86_64-unknown-linux-gnu.tar.gz
└── fuz       # mode 0755
```

A per-tool tarball holds that tool's declared binaries. Extraction targets
`~/.fuz/artifacts/<content_hash>/` (self) or
`~/.fuz/tools/<name>/<content_hash>/` (tool, with its own `current` and `bin/`
links), via a `.downloading-<random>/` or `.installing-<random>/` temp dir
renamed into place, cleaned on any failure; one a crash leaves is swept by a later
fetch (self) or install of that tool once nothing in it, the streaming tarball
included, has been written for an hour. `meta.json` is then written from the
manifest (`source: "remote"`, no `inputs`, `created_at` the download time) — the
self artifact's `ArtifactMeta` or a tool's `ToolMeta`.

**Extraction security** is `fuz_archive::safe_extract` (its rustdoc has the
guard set; the limits fuz applies are `fuz_release`'s `MAX_*` constants):
download, hash, and extraction all **stream**, so the per-file and total
ceilings (`MAX_FILE_SIZE`, `MAX_TOTAL_SIZE`) are disk sanity bounds sized for
GB-scale artifacts; the compression-ratio cap (`MAX_COMPRESSION_RATIO`) is the
gzip-bomb guard over the whole decompressed stream; the header-window cap
(`MAX_HEADER_SIZE`) is the one memory guard. Only regular files with normal path
components are accepted (no symlinks, hardlinks, devices, null bytes,
setuid/setgid); directory entries are skipped, and one that declares a body is
refused. A PAX `size` record that disagrees with a non-zero header size, or a
header or PAX header tar readers could parse differently, is refused, and so is
a tar stream without its end-of-archive marker (truncated). The tarball must
hold exactly `manifest.binaries`. Modes aren't copied: `0755` if the
owner-execute bit is set, else `0644`.

## Verification Flow

Steps 1–2 parse **before** the signature is checked — the manifest is
attacker-controlled bytes then. That's kept safe by the 1 MiB cap before
parsing, a memory-safe parser, and nothing downstream accepting anything but a
`VerifiedManifest`.

```
1. Download manifest — bounded (MAX_MANIFEST_SIZE, 1 MiB); parse and validate
2. Check target == current_target()
3. Verify signature against PUBLIC_KEYS; Manifest::check_key
4. Version safety (skipped on a fresh install): installed ≥ minimum_version; target ≥ installed
5. Release log (only with FUZ_RELEASE_LOG_URL): heads from every witness, reconciled
   with the cache; row present, not revoked, this target, same content_hash + binaries
6. Local cache: an existing <content_hash>/ with matching hashes → skip to 14;
   WRONG hashes → hard fail (tampering — never re-download); a link or file → unlink, download
7. Stream the tarball to a temp file
8. Verify tarball blake3
9. Extract (allowlist, limits), hashing binaries as they land
10. Verify binary hashes against manifest.binaries
11. Recompute content_hash from the binary hashes (defense in depth)
12. Hold each binary's header to this client's target (§ Binary platform)
13. Write meta.json
14. Activate (switch current)
```

The release log step sits after version safety (a downgrade is reported as one)
and before the cache (an artifact unpacked before its revocation is refused).
The `--check` flows run steps 1–5 and report — step 4 there is a status
(`update_required`, `up_to_date`), not a refusal. **Fail closed**: any failure
aborts. I/O errors may be retried; security violations (a hash mismatch, a bad
signature, a release the log revokes or doesn't record) exit `65` and must not
be. The one retryable log outcome is "cannot confirm yet" (exit 75).

Step 12 refuses a validly signed release whose binary is not for this target
(`ReleaseError::MislabelledBinary`): exit `1`, **not** a security violation —
the signature is valid, the label is wrong, and retrying won't change it. It
runs before `meta.json` is written or the install renamed into place, so
nothing is installed and `current` doesn't move. A cache hit (step 6) skips
it: those bytes passed it when they were installed.

## Version Safety

**`minimum_version`** — a publisher-side compatibility floor (why it is never a
"minimum safe version": ./security-model.md § Rollback). It gates the
**upgrade** path, checked against the installed version of the same stream
(fuz's own for `fuz self`, the tool's for `fuz tool`): an install below it
refuses with `ManifestError::BelowMinimum` ("version below minimum: 0.2.1 <
0.3.0"). It never gates a fresh install, so a tool below its floor recovers
through one: remove `$FUZ_HOME/tools/<name>/current`, then `fuz tool install
<name>`; fuz itself re-bootstraps.

**No downgrade** — client-side: refuse a release older than the installed one,
`ManifestError::Downgrade` ("downgrade not allowed: 0.4.0 -> 0.3.2"), unless
`--allow-downgrade`. Tools enforce both (`--allow-downgrade` never waives the
floor); a fresh install is exempt from both. Together they stop an attacker
pointing a latest pointer at an old release or replaying old signed manifests.

### Unreadable current install

The installed version is *installed* (a readable `meta.json`), *not installed*
(no `current` link), or *unreadable* (a dangling or out-of-store `current`, a
link or file at the install it names, a corrupt or oversized `meta.json`). An
unreadable state is **refused loud** — the floor and downgrade guard can't be
evaluated — with `current install is unreadable: <reason>`. `--force`
reinstalls over it (signed and verified, with a warning), except a `current`
that isn't a symlink, which is refused regardless (exit 65; ./artifacts.md
§ Store Entries). Self and tool paths behave alike.

### `--check`

`fuz self upgrade --check` and `fuz tool upgrade <name> --check` fetch and
verify the signed manifest and report without downloading or installing:

- Statuses: `up_to_date` (exit `0`), `update_available`, `update_required`,
  `not_installed`, `unreadable` (exit `10` — action needed). The reported
  version is the **signed** one, never the latest pointer's.
  An `update_required` `reason` names the recovery: a re-bootstrap for fuz,
  a fresh reinstall for a tool.
- `--json`: `{kind, name, current?, latest, status, verified, reason?,
  release_log?}`.
- With `FUZ_RELEASE_LOG_URL` set, the latest release is held to the log first.
  A refused release fails the check with no report, with the exit codes of
  ./release_log_check.md § Outcomes (65 for a release the log revokes, omits,
  or contradicts; 75 when unconfirmed). A confirmed one adds
  `release_log: {"seq": N, "source": "witness" | "cache_ahead_of_witness" |
  "cache_witness_unreachable"}`, plus `co_signs`
  (`[{origin, seq, covers: "effective_head" | "older_head" | "none"}]`) when a
  co-signature was verified.

Exit codes overall: `65` for bytes not to trust — a security violation
(`ReleaseError::is_security_violation`: a bad signature, a substituted
manifest, a download hash mismatch, a verified tarball that fails to parse or
trips an extraction guard, a release the log revokes, omits, or contradicts) or
a local store that fails integrity; `1` for version-safety
refusals, storage failures, and the rest; `73` no space; `75` lock held, or log
unconfirmed; `2` for what the caller must change (an unparseable command line,
a bad flag combination, an unusable release log configuration).
