# Storage Backends

Release storage is backend-agnostic: one `Storage` trait over a local
directory, a fuz_forge file store over HTTP, a VPS over SSH, and a public static
host over anonymous HTTPS. The same key layout (./release_format.md § URL
Scheme, from `ReleaseLayout`) works on every backend, so
`fuz tool install <name> --storage <uri>` installs the identical signed artifact
from any of them. The trait and per-backend mechanics are `fuz_storage`'s
rustdoc.

**Storage is a dumb byte pipe, not a trust boundary.** No backend signs or
verifies; `fuz` checks the ed25519 signature and blake3 pins after fetching,
whatever served the bytes. A hostile backend can deny service or serve
stale-but-signed bytes (no-downgrade refuses an older release on an existing
install; a first install has no such guard), never forge one. Backend choice
decides who can withhold releases and which credential the client holds — not
what `fuz` accepts.

**No S3-compatible backend, deliberately.** Authenticated object storage would
be a hand-rolled SigV4 signing surface and a long-lived secret at rest, for a
role `forge://` and `ssh://` already cover. Reading a public object store is a
plain anonymous `https://` GET (`HttpsStorage`); writing to one is a
producer-side, out-of-band job (`rclone`, `wrangler`).

## Backends

| URI | Backend | Use | Auth |
| --- | --- | --- | --- |
| `~/releases`, `./releases`, `/var/releases`, `file:///path` | `FileStorage` | development, testing, air-gapped | none |
| `forge://host` | `ForgeStorage` | a self-hosted fuz_forge's file store (`/api/fuz_forge/files`) | bearer token |
| `ssh://user@host[:port]/path` | `SshStorage` | a VPS-hosted tree over `ssh` / `scp` | ambient ssh agent / key |
| `https://host[:port][/base]` | `HttpsStorage` | a public static host or CDN — **read-only** | none |

No credentials file, no credentials argument. A string containing `://` is a
URI, anything else a path; a leading `~` expands against `fuz_sys::home_dir`
(an unusable home is a configuration error, never a literal `~` dir). An
`http://` URI is held to the HTTPS backend's loopback rule; any other scheme
(`s3://`) is an unknown scheme, not a path.

## The contract

- **Keys** — `validate_forge_key`: relative, `[A-Za-z0-9._/-]`, no empty / `.` /
  `..` / dot-prefixed segments. Every backend applies it before a key becomes a
  path, URL, or remote command (`InvalidKey` otherwise), so no key names a path
  outside the root; the forge server shares the validator. `list` prefixes are
  held to `validate_list_prefix`. A version with semver build metadata (`+…`)
  can't be part of a key, so a publish refuses it up front.
- **Errors** — a `StorageError` keeps outside strings as given (a key built from
  an unsigned latest pointer, a forge body, `ssh`'s stderr) and its message shows
  each bounded and escaped; a failed transfer's text is shown whole to 2 KiB,
  past that from both ends.
- **Buffered vs streaming** — `upload` / `download` for small keys (manifests,
  latest pointers, sidecars); `upload_file` / `download_to_file` stream with
  `O(chunk)` memory for tarballs. Both streaming methods and `download_capped`
  (refused past `max`, enforced while reading — the read for documents parsed
  before a signature check) are **required**, with no buffered default, so a
  new backend can't silently buffer a GB artifact. Callers pick: small keys
  buffered, tarballs streamed.
- **`list` / `delete`** — on every writable backend; `HttpsStorage` returns
  `Unsupported` for them and for uploads. They serve the producer side only
  (`cargo xtask prune`, the backfill, a first-head publish's storage check);
  `fuz` never lists or deletes.
- **Symlinks in a store** — the key contract keeps a *key* inside the root, not
  the tree: on `FileStorage` and `SshStorage` a symlinked root or directory is
  followed, and a symlink to a file is served by `download` / `exists`. No
  method creates a link. `list` returns **regular files only** (and
  `SshStorage`'s `find -H` doesn't descend a symlinked subdirectory), so what it
  omits the producer commands built on it don't see.
- **Read-only** — `StorageBackendKind::is_read_only` and
  `Storage::require_writable` say it, so callers ask the backend rather than
  naming one.

## Per-backend notes

**`FileStorage`** — `tokio::fs`, atomic temp + rename writes. Naming a store
never creates it (§ Who creates a local store); a root held by a non-directory
is refused (`LocalRootNotDir`). `list` reads one directory; a missing directory
prefix lists empty.

**`ForgeStorage`** — the forge is a dumb byte store; reads are auth-gated too
(no anonymous download from a forge).

- Base URL: `forge://<host>` → `https://<host>`; a host-less `forge://` uses
  `FUZ_FORGE_BASE_URL` (trimmed, blank = unset, refused if not UTF-8).
- Token: `FUZ_FORGE_TOKEN` (blank = unset), else the trimmed `api_token` in the
  forge home — `FUZ_FORGE_HOME` (blank = unset, `~` expanded, must be UTF-8 and
  absolute) else `~/.fuz_forge`. One resolver (`fuz_storage::forge_home`) serves
  `fuz` and `fuzf`. The file must be (or link to) a regular file of at most 4096
  bytes; the token must be printable ASCII without whitespace (refused by
  source, never echoed). Redacted in `Debug`.
- HTTPS only, except `http://` to a loopback host (which also bypasses
  proxies); userinfo, query, or fragment in the base is refused.
- Redirects: reads follow `HttpsStorage`'s policy, dropping the token on any
  scheme / host / port change; writes never follow one (a `3xx` fails the
  write). No `Referer`.
- Bounds: streaming both ways; buffered transfers capped at `MAX_TRANSFER_SIZE`;
  a file listing refused past 16 MiB (`MAX_FORGE_LIST_SIZE`); error bodies read
  to 4 KiB (`read_error_text`); a 30-second connect and 5-minute total deadline
  per request. A failed `download_to_file` once the transfer started unlinks
  `dest`.
- One exported policy: `fuzf` validates its server URL with
  `base_url::validate_base_url`, builds its client with `forge_client_builder`
  (redirects refused), words a refusal with `forge_base_url_refusal_message`,
  and reads `FUZ_FORGE_BASE_URL` with `forge_home::forge_base_url_env` — the
  same functions `ForgeStorage` calls, not a copy.

**`SshStorage`** — ambient SSH (agent, default key, `known_hosts`;
`BatchMode=yes` fails fast); a password in the URI is refused. `-F none`
ignores `~/.ssh/config` (the `ProxyCommand`-hijack defense), so per-host
`IdentityFile` / `ProxyJump` / `User` / `Port` there don't apply — put them in
the URI or the agent. No IPv6 literals.

- `scp` streams both ways; buffered `download` (`ssh cat`) is capped at
  `MAX_TRANSFER_SIZE`, and `download_capped` kills the child past `max`.
- Writes go to `<final>.tmp-<random>` then `ssh mv`. `exists` = `test -e`,
  `list` = `find -H … -print0`, `delete` = `rm -f`. A failed `download_to_file`
  always unlinks `dest`.
- Injection defense: charset validation of host / user / root / port before any
  command is built (excludes every shell metacharacter, control char, `%`, and
  glob char) carries the security; `ssh` remote paths are also single-quoted,
  `scp` paths not (OpenSSH 9+ SFTP mode would take quotes literally); `--`
  before positionals. Builders are pure and unit-tested; the end-to-end path is
  the `#[ignore]` suite against `SSH_TEST_TARGET`.

**`HttpsStorage`** — anonymous `GET` / `HEAD` against `<base>/<key>`.

- Sends no token, cookie, or `Referer`; userinfo in the base or a redirect is
  refused; `401` / `403` → `PermissionDenied`, `404` → `NotFound`, other
  failures carry the status only (error bodies are never read).
- `https` only, except `http://` to a loopback host. Redirects: bounded hops, no
  revisits, never from `https` onto `http`, plaintext only loopback → loopback;
  an `https` base's client can't issue a plaintext request at all.
- Size: `download_to_file` ≤ `MAX_TRANSFER_SIZE`, buffered `download` ≤
  `MAX_BUFFERED_SIZE`, enforced by a byte counter whatever `Content-Length`
  says; a failure mid-transfer unlinks `dest`.
- Time: connect and idle timeouts on every request; `download` and `exists` also
  a 5-minute total; `download_to_file` none (big artifacts on slow links).
- Proxies: an `https` base honors the proxy environment; a loopback `http` base
  bypasses it.

## Who creates a local store

Parsing a location changes nothing, under either parser. They differ for a
local path that isn't there:

- `parse_existing_storage` — every command working on an existing store —
  refuses it, so a mistyped path is an error, not an empty store. It is the one
  parse `fuz_release` re-exports, so `fuz tool install` / `upgrade` and `fuz
  self upgrade` (with or without `--check`) refuse a missing local `--storage`
  (exit 1) and leave the filesystem alone; so do `cargo xtask prune`, the
  backfill, and the `FUZ_RELEASE_LOG_URL` origins.
- `parse_storage` — `cargo xtask publish` alone — accepts it, since a first
  publish targets a store that doesn't exist yet. **The first upload creates a
  local store; nothing else does.** A path held by a non-directory is still
  refused up front.

Producer commands refuse an unusable `--storage` before doing work:
`cargo xtask publish` resolves it before loading the signing key (refusing a
non-directory path and a read-only backend), and the `fuz_sign` publish flows
refuse a read-only store themselves; `prune` and the backfill refuse a missing
local path and fail on a read-only backend before listing.

## VPS as a release host

Publish with `--storage ssh://user@vps/var/www/releases`, let nginx serve the
tree over HTTPS, and read it with `--storage https://vps/releases`; `install.sh`
reads it via `FUZ_INSTALL_BASE_URL`. All implemented — the `ssh://` loop
validated against a real host, the `https://` path by local tests only. What
isn't live is a hosted public channel: there is no default storage. The other
self-hosted path is `forge://` (auth-gated).

## Concurrency

**Single publisher assumed.** There's no compare-and-swap, so concurrent
publishes of one target race on its `latest-<target>.json` (last writer wins
on `FileStorage`; a forge would need a conditional write, SSH a lock). Don't run publishes concurrently;
CI should serialize releases.
