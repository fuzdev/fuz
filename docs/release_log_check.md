# Release Log Check

The consumer side of the release log: what `fuz` and `scripts/install.sh` check
against it, and what that does and doesn't buy. Writing the log (publish,
backfill, revoke) is ./release_log.md; the file formats are
./release_format.md § Release Log Files.

> **Status: implemented, inactive by default.** No public release log exists,
> `fuz` has no built-in witness origin, and nothing here happens unless
> `FUZ_RELEASE_LOG_URL` is set — no request, no cache, no output.

## What it adds

A manifest's signature says a release is **authentic**. It cannot say that the
publisher **still stands behind** it (a signature never expires, so a withdrawn
release verifies forever), or that this machine was shown **the same release
everyone else was** (a key holder could sign one build for one target).

The release log answers both. It is one signed, append-only `head.json`: every
release is a row holding, per target, the manifest's `content_hash` and binary
hashes; a withdrawn release keeps its row as `revoked`. An origin serving that
file is a **witness**. Before a release's bytes are used, `fuz` fetches the head
from every configured witness, verifies each signature against the embedded
keys, requires every head it holds (each witness's and the cached one) to be one
history at different lengths, and requires the release to be a row of the
newest — not revoked, same hashes.

## Which commands consult it

- `fuz self upgrade`, `fuz tool install`, `fuz tool upgrade` — after version
  safety and before the artifact cache or any download, so a release unpacked
  before it was revoked is refused like one never fetched.
- The `--check` flows — the latest release is held to the log before any report
  ("up to date" included); a refused release fails the check. They stay
  read-only: the cached head is used, never written.
- `fuz self bootstrap` — before anything is installed or the shell rc file is
  touched. With no manifest, the row is selected by the binary's own version and
  this machine's target and must record the BLAKE3 of the bytes being installed.
  A locally built `fuz` is not confirmable; bootstrap it with
  `FUZ_RELEASE_LOG=off`.
- Every `fuz self` command reads the **cached** head (no request) and warns on
  stderr, `--quiet` included, when the version it reports is revoked; the exit
  code is unchanged. `fuz self status --json` reports it as
  `release_log.installed_revoked`.

`fuz tool verify`, `fuz artifact …`, and `fuzd` don't consult the log.

## Outcomes

| Witnesses | The release in the effective head | Result | Exit |
| --- | --- | --- | --- |
| at least one reachable | recorded, `ok`, same hashes | confirmed; a silent witness is named in a warning | the command's own |
| any | `revoked` | refused — no flag overrides it | 65 |
| at least one reachable | no row, or no entry for this target | refused | 65 |
| any | recorded with other hashes | refused (contradiction) | 65 |
| none reachable | cached head records it, `ok`, same hashes | confirmed, with a warning | the command's own |
| none reachable | nothing cached, or the cache doesn't cover it | **cannot confirm yet** | 75 |
| a witness serves something not a valid, trusted-signed head | — | refused; never skipped for another witness | 65 (1 if it doesn't parse) |
| two heads are not one history (witness vs witness, or vs the cache) | — | refused (contradiction) | 65 |
| the cached head exists and can't be used | — | refused; never read as absent or replaced | 65 if it fails verification or isn't a regular file, else 1 |
| a keyed witness serves a `witness` file that doesn't verify or parse | — | refused; never skipped | 65 (1 if it doesn't parse) |
| a verified co-signature names its own origin's head `seq` with another digest | — | refused (contradiction) | 65 |
| a keyed witness serves no `witness` file, or one for another `seq` | as above | unchanged — a co-signature is never required | as above |

The **effective head** is the newest verified head among the witnesses' and the
cached one; a witness serving an older head of the same history is lagging, not
lying (a warning says so). The check **fails closed**: "cannot confirm yet" is
the one soft failure (`75`), so a script can tell "retry later" from
"refused". A refusal that is a security violation is `65`, fuz's code for bytes
not to trust — never retried; a benign refusal (an input that doesn't parse, a
cache it can't write) is `1`. `2` is a configuration the check can't run
under; `10` stays the `--check` flows' "action needed". `fuz self version` /
`status` never fail on the log — problems there are one-line warnings. The
installing commands refuse a world-writable fuz home before any request.

## Configuration

- `FUZ_RELEASE_LOG_URL` — comma-separated origins, each an `https://` URL
  (`http://` for a loopback host) or an **existing** local directory serving
  `head.json` at its root. A missing directory is an error, never created;
  `forge://` and `ssh://` are refused; a relative path resolves against the
  working directory; a leading `~` needs a usable `HOME`. An entry that isn't
  an origin is reported by position and never echoed (a URL can carry a
  credential).
- `FUZ_RELEASE_LOG=off` — the per-user opt-out: skips the check with a notice on
  stderr (`--quiet` too), and the cached head isn't read. The only value — `OFF`,
  `0`, `false` are configuration errors.

Each network witness has 20 s to serve its head, one after another, and a keyed
witness 20 s more for its co-signature. A local directory is plain file IO,
outside that bound.

## The cached head

`state/release_log/head.json` under the fuz home (mode `0600`) — the baseline
the next head must contain, so a witness can't roll the log back or drop a
revocation this machine has seen, and a revocation stays known offline. Written
only by the installing commands and `fuz self bootstrap`, when a witness serves
a strictly newer head or nothing is cached, and before the verdict — so a head
that revokes a release is kept even though that install is refused.

Its **authenticity** is its signature (verified on every read). Its
**freshness** rests on the home's permissions alone: whoever can write it can
put back an older signed head or delete it, which resets the continuity record.

## The install script

`scripts/install.sh` runs before any `fuz` exists, so it can't verify a
signature; it asks a second origin instead. With `FUZ_RELEASE_LOG_URL` set, it
reads `latest/fuz-<target>.sha512` from the first reachable origin — one line
naming the versioned flat binary and its SHA-512 — downloads that binary from
the release host, and requires the digest. The release host's sidecar and
moving `fuz-latest-<target>` aren't read. Unset, it compares the release host's
own sidecar, which catches a corrupted download and nothing else.

| The origin read | Result | Exit |
| --- | --- | --- |
| serves a pointer the downloaded bytes match | hands off to `fuz self bootstrap` (which then checks the signed head) | bootstrap's own |
| serves a pointer the bytes don't match | refused (host and log contradict) | 65 |
| answers with no pointer for this target (404 / 410 / no file) | refused | 65 |
| serves anything but one well-formed pointer line for this target | refused | 1 |
| fails to download for a reason that isn't the network (a URL curl can't use, a local write error) | refused | 1 |
| every origin unreachable | cannot confirm yet | 75 |

- What this protects against, and what it doesn't, is ./security-model.md §
  First Binary Bootstrap. Beyond that: a revocation reaches the edge
  (revoking moves or removes the pointer); the first origin that answers is
  final, with no comparison across origins; nothing is cached, so there is no
  continuity; and an origin that never answers stalls the install.
- With origins configured it needs `curl` (refused before any request without
  it); an `http://` origin, or an `https://` URL outside its character set, is a
  configuration error. The full unreachable-vs-refusal rules and the pinned
  cases are `scripts/install.sh`'s comments and ../scripts/install-test/README.md.

## Co-signatures

> **Status: implemented in the client, unused.** No co-signer exists and no
> witness key is embedded, so no co-signature is requested.

A co-signer's `witness` file (./release_log.md § Co-signing; format:
./release_format.md § Release Log Files) is checked only for an origin whose
SSH key is built into the binary:

1. Fetch `witness`, bounded. Absent or unreachable: nothing happens.
2. Present: it must be an SSH signature over exactly the first line, by that
   origin's key, and the line in its one spelling — else a **refusal for that
   witness** (remedy: remove the origin from `FUZ_RELEASE_LOG_URL`).
3. The statement is compared only with **the `head.json` bytes that same origin
   served in this check**, and only when that head has its `seq`; a mismatch is
   a contradiction naming the origin.

Only the origin's own bytes, because a head's bytes include encoding and the
unsigned `signed_at`, so two honest origins can serve one head differently;
every other head is tied in by signed content through the one-history rule.

A co-signature is **a beacon, not a gate**: absence is allowed and it never
expires, so it shows a co-signer saw those bytes at some time, not that they're
newest. It never confirms a release, a witness key is never a release key, and
nothing is cached. What it buys: a party outside the publisher has put its own
key behind those bytes at that `seq`, using only `curl`, `sha512sum`, and
`ssh-keygen`. Reported on stderr and in `--check --json` as
`release_log.co_signs`.

## Limits

- **Transparency, not prevention** — a key holder can still sign and log a bad
  release; it becomes a public, permanent row, and the publisher can withdraw
  it.
- **First contact is the embedded key** — a first check has no cache to compare
  against.
- **No freshness guarantee** — `signed_at` is unsigned; a witness serving an old
  head, or a network blocking every witness, hides a newer revocation from a
  machine that hasn't seen it. More independent witnesses narrow this.
- **A blocked witness delays new installs, not witnessed ones.**
- **A revocation is not a kill switch** — it stops installs and upgrades to the
  release and warns; it doesn't disable an installed binary.
- **A compromised release key signs heads too** — the log alone doesn't survive
  key compromise (./security-model.md § Key Compromise Response).
