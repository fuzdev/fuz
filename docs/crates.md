# Crates

The per-crate reference: what each crate is for, its boundary, the rules that
span crates, and the consumers a change must reach. ../CLAUDE.md § Crates is
the short map. Module-level invariants, gate orders, and error cases live in
each crate's rustdoc (`cargo doc -p <crate> --document-private-items`) — put
new ones there, and keep cross-crate rules here.

Enforced boundaries (`cargo xtask check-release`, via `fuz_audit`) are marked
**(audited)**.

## Binaries

### `fuz`

The CLI client: `self`, `tool`, `artifact`, and `workload observe`.

- **Consumer-only** — fetches and verifies, never signs or publishes; `fuz_sign`
  stays out of its graph **(audited)**.
- Never drives fuzd's lifecycle and doesn't link `fuz_daemon`. Only
  `workload observe` speaks the wire protocol (over `fuz_client` + `fuz_wire`,
  degrading with a hint when fuzd isn't running); `self status` and
  `tool install|upgrade fuzd` only test whether the socket accepts a connection
  (`src/fuzd.rs`), to report the daemon or print a `fuzd restart` note.
- Its `release_log` module is the edge of the release log check: it reads
  `FUZ_RELEASE_LOG_URL` / `FUZ_RELEASE_LOG` into a `ReleaseLogPolicy` before any
  request and before `--storage` is parsed, and renders the outcome; the exit
  mapping is `ReleaseCommandError::exit_code` / `CliError::exit_code`
  (./release_log_check.md).
- `self version` / `status` are diagnostics: an unresolvable fuz home is a
  warning there (exit 0), the daemon reported unknown.
- Text another process chose (observe output) is printed through
  `escape_untrusted` and cut to its column.

### `fuzd`

The daemon (binds `~/.fuz/run/socket`). Bare `fuzd` runs in the foreground;
`fuzd {start,stop,restart,status,logs}` manage a backgrounded one through
`fuz_daemon`. Links `fuz_sidecar` for the empty pool; the runtimes sit behind
the off-by-default `sidecar` feature.

### `xtask`

Dev + publisher automation, absent from the `fuz`/`fuzd` graph and
`dev_only`-exempt from `check-release`: `install`, `clean`, `check-release`
(adding this workspace's forbids: `fuz_sign` in production binaries, `fuz`/`fuzd`
reaching `fuzi`/`fuzi_core`), `key …`, `publish {self,tool}` (the bootstrap
signer; `--log-repo` records the release), `release-log {backfill,revoke}`, and
`prune` — the last two dry-run unless `--wetrun`.

### `fuzi`

The lockfile-driven npm installer: a verb-first CLI over `fuzi_core`; its
surface, inputs, and exit codes are ./fuzi.md. It renders the core's
`InstallReport` and errors, and owns the **interrupt drain** (`src/signal.rs`),
which exits `128 + signum` rather than dying by the signal, since re-raising
under the default disposition would need `unsafe`. `install` never sweeps at
startup, which would race a concurrent install; `clean` reaps what an exit that
can't unwind leaves. Unless `node_modules` is a real directory, `clean` keeps
every `.fuzi-old-*` tree (it may be the user's only copy) and reports a restore
command. `fuz`/`fuzd` must not depend on it **(audited)**.

### `testing_spine_stub`

**Test-only, never shipped** (the packaging filter, and `check_no_test_binaries`
at publish and at manifest read). A domain-free spine server — the auth /
account / admin / audit / role-grant-offer surface, the cell verbs, and
cell-gated fact serving — its own `run_app` over the `fuz_actions::server`
toolkit, with `fuz_testing`'s hasher, every
`_testing_*` spec, and an env-gated startup DB reset. Default port 1177; its
command line is the harness's `--port <port>` alone. Driven by fuz_app's
cross-backend suites (./testing.md § Cross-backend suite); like its TS twin it
schedules no auth cleanup and starts with its limiters off.

### `testing_fake_fgro`

**Test-only, never shipped**; a binary target of `fuz_eval`. Its stand-in for
`fgro eval` in the integration suites (§ `fuz_eval`).

## Foundation

### `fuz_sys`

Home-agnostic OS primitives — the leaf beneath `fuz_home`, so the HTTP spine
can depend on it without inheriting `~/.fuz` (`fuz_sys` ⊥ `{axum, fuz_http}`
**(audited)**). The default build is sync-only and tokio-free; features add
`logging`, `signal`, `periodic` (`spawn_periodic`, the loop every scheduled
upkeep task runs on), `capture`, `argh` (`cli::parse_env_args`), and `tls`
(outbound rustls clients only, keeping `aws-lc-sys` out).

The one home for values crates must agree on: the size ceilings in `limits`;
the escaping of text the program didn't write (`text::escape_untrusted`,
`quoted`, `truncate`, `escape_message`; § Error rendering); `home_dir`, the one
`$HOME` lookup; and the no-follow vocabulary the stores classify entries with
(`fs::probe_real_dir`, `secure_file::open_nofollow_regular`, …). `fs::sweep_stale_staging_dirs` is the
age-gated sweep of crash-leaked staging dirs.

### `fuz_home`

The `~/.fuz` layer over `fuz_sys` (`fuz_home` ⊥ `{axum, fuz_db, fuz_http}`
**(audited)**): directory and socket paths, the CLI-owned `daemon.json`, logs and
rotation, `verify_pid_is_fuzd`, and the lifecycle timing constants.
./fuz_home.md.

### `fuz_crypto`

The verify-only trust floor and the single hashing home; no workspace-crate
deps.

- Ed25519 verification against the embedded release keys (`PUBLIC_KEYS`).
  Signed bytes are domain-separated per document kind, so a manifest signature
  never verifies as a release log head (./signing.md § Signed Bytes).
- `ContentHash`, the digest type content is hashed and compared through
  (`fuz_auth` hashes credentials directly — a token hash is a lookup key, not
  content addressing). Hex is written lowercase and read lowercase only:
  `from_lower_hex`, the `blake3_hex` / `blake3_hex_map` adapters, and
  `parse_prefixed` all refuse uppercase and any other length; `from_hex` is
  the one lenient parse, for hex from outside fuz. A fact address goes through
  `parse_fact_hash` (or the `fact_hash` serde adapter): `blake3:` + 64
  lowercase hex, nothing else — `parse_prefixed` also takes `sha256:` /
  `sha512:`, and the default `Deserialize` the SRI form too. The adapters
  that write bare hex refuse a non-BLAKE3 digest. Every digest form fuz
  writes or reads: ./release_format.md § Digest formats.
- `unique_map`: every map in a signed document is read through it, so a
  repeated key refuses the document.
- The verify-only `sshsig` parser and the `witness` co-signer keys. **A witness
  key is never a release key**: `is_trusted_key` reads `PUBLIC_KEYS` alone, and
  the build refuses a key listed as both.

### `fuz_audit`

**Build tooling only — never in a production binary (audited,
self-protecting).** The `check-release` dep-graph audit over
`cargo metadata --all-features`: forbidden crates on a normal or build edge
outside `testing_*` / `dev_only`, `BUILTIN_CRATE_LAYERING`, and any local
`test_*` feature on a release edge. It prints the subjects it checked, so a
renamed crate shows up rather than passing silently. Each workspace's xtask
enters through `run_check_release_cli`, `xtask_main`, or
`run_check_release_cli_with_rules`; a package opts out with
`[package.metadata.fuz_audit] dev_only = true`.

## Distribution

### `fuz_artifact`

Content-addressed artifacts and tool installs (over `fuz_sys` + `fuz_home` +
`fuz_crypto`).

- `switch_to_artifact` — the locked verify → switch `current` → link `bin/` →
  record composition behind `fuz artifact build` / `use`, `fuz self upgrade`,
  and `cargo xtask install`; its `&FileLock` parameter witnesses the artifact
  lock.
- `store` — the one store-entry policy (./artifacts.md § Store Entries).
- `is_content_hash`, the one check of `v1-<64 lowercase hex>`, and
  `is_release_token`, the one rule for a release's name, version, target, and
  binary names — shared by manifest validation, the release log's row rules,
  the log writers, and both tool installs. A binary name that is a token holds
  no `:` or `\n`, which keeps `content_hash_from_binaries` unambiguous.
- `cargo_build_release` — the release build behind `fuz artifact build` and
  `cargo xtask install`, one package per cargo run (feature unification across
  packages changes the binaries): the binary's path comes from cargo's JSON
  messages, never a guessed `target/release/`; `check_built_for` holds it to
  the host's target (./artifacts.md § Build and verification).
- `tools` — the per-tool install model and the `FIRST_PARTY_TOOLS` allowlist;
  `install_local_tool` is the no-storage install `cargo xtask install` uses
  (the fetching one is `fuz_release::install_tool`).
- `platform` — the one reading of what a binary is for: `ReleaseTarget` (the
  closed set of supported triples), `inspect_binary` (a hand-rolled ELF /
  Mach-O header reader over a bounded prefix), and `check_binary_target` (the
  policy every producer and `fuz` apply). Its `test_stubs` (minimal
  executables per target) are behind the dev-dependency-only
  `test_binary_stubs` feature, for the suites that publish or install.

### `fuz_storage`

The `Storage` trait and its backends — local, `forge://`, `ssh://`, read-only
`https://` (./storage_backends.md). Dumb byte pipes: signing and verifying live
above, so trust is independent of transport.

- `parse_storage` (a publish) vs `parse_existing_storage` (everything else).
- `validate_forge_key` is the one on-store key contract, applied before a key
  becomes a path, URL, or remote command, and shared with the forge server.
- `forge_home` is the one resolver of the forge home, bearer token, and
  `FUZ_FORGE_BASE_URL`, shared with `fuzf`.
- `base_url` (`validate_base_url`, `BaseUrl`, `BaseUrlRefusal`) is public, and
  the crate-private `http_client` policy (proxies, `https_only`, redirects, no
  `Referer`) is reached through `forge_client_builder` and `Redirects` — so
  `fuzf` takes the base-URL and client policy from here, with
  `forge_base_url_refusal_message` for its wording, rather than mirroring it.

Consumers: `fuz_release`, `fuz_sign`, `xtask`; outside, `fuzf` and the forge
server.

### `fuz_archive`

Hardened streaming `.tar.gz` extraction (`safe_extract`: zip-slip, null byte,
path length, size and compression-ratio caps over the whole stream, a
header-window cap, setuid and symlink refusal; every gzip member decoded and
the tar end-of-archive marker required), parameterized by `Placement`,
`ExtractLimits`, and `SymlinkPolicy`. A manifest-free leaf with no forbidden
crates, so `fuz_release` and `fuzi_core` both use it.

- **The root is never created.** Each file's parents are made strictly below
  the extraction root (`create_dir_all_below`, also exported for `fuzi_core`'s
  staging mkdirs); a root removed mid-extraction fails it with `NotFound`
  rather than being put back.
- **One reading of the stream** — an archive node-tar would split differently
  is refused (the crate rustdoc § One reading of the stream).
- **Error classes.** `ArchiveError::is_security_violation` covers every guard
  and `Malformed` (bytes that don't parse — both callers check the digest
  first, so re-reading fails the same way); `Read` (an OS error from the
  reader, or any reader error past the gzip stream), `Io`, and `Empty` are not
  violations.

### `fuz_release`

Fetch / verify / install; publishing is `fuz_sign`.

- Manifests (`tool: None` = the self artifact), tarball extraction,
  `fetch_*` / `install_tool`, `ReleaseLayout` (the one source of storage-key
  naming), and pure prune retention.
- Re-exports `parse_existing_storage` as the one parse a consumer binary
  reaches.
- The release log reader (`log_check`, **fail-closed**, `Unconfirmed` the one
  soft failure) and `co_sign` (a beacon, not a gate). The check runs before the
  cache-hit branch, so a revoked installed release isn't reported current.
- `check_no_test_binaries`, run at publish and at manifest validation.
- Every installed binary is held to `current_release_target()` after its
  hashes verify and before the install lands (`MislabelledBinary`: exit 1,
  not a security violation).
- Each stream's version pointer is per target (`latest-<target>.json`); a
  client reads its own.
- Prints nothing and never reads the release log variables itself
  (`ReleaseLogPolicy::from_env_values` takes their values).

Consumers: `fuz`, `fuz_sign`, `xtask`, `fuzf`; a spine server only as a
dev-dependency.

### `fuz_sign`

Everything that holds the private key. **A crate, not a feature** (feature
unification could route signing into `fuz`), forbidden in every production
binary **(audited)**.

- `load_signing_key`, the one key resolver, shared by `xtask` and `fuzf`.
- `sign_manifest` / `sign_head` — no sign-any-bytes entry point.
- The `publish_*` flows, which label a release with `PublishOptions::target`
  (else the publisher's own) and hold every binary — the bytes they sign — to
  it before anything is logged, signed, or uploaded; and `prune`, which
  deletes only keys it derives from `ReleaseLayout` (never
  `fuz-latest-<target>`), keeps every version a `latest-<target>.json` names,
  and refuses a manifest whose unsigned fields don't match its key before any
  delete.
- The release log writers — the only writers of a head: publish's entry,
  `backfill`, and `revoke`, over one shared clone / commit / push / read-back
  path (./release_log.md).

Consumers: `xtask` and `fuzf`; a spine server only as a dev-dependency.

## Daemon

### `fuz_daemon`

fuzd lifecycle — spawn, signal, health-poll, stale pid, logs — behind
**`fuzd`'s own CLI only**. `DaemonState` uses the socket lock to tell an
unresponsive daemon from a gone one. ./daemon_lifecycle.md.

### `fuzd_server`

The UDS server (postcard codec, dispatch, a `flock`-exclusive bind, graceful
shutdown) and the **demand-driven workload registry** (refcount, idle grace,
sharing), with the `observer` (process / network / services) and `watcher`
(inotify) kinds behind the `ObserverSource` / `WatchSource` seams.

- **A collector never waits on a subscriber**: a full channel drops that
  subscriber's frames and owes it a fresh snapshot.
- Forwarded output is bounded: outside strings are cut, and every frame fits
  `MAX_FRAME` (oversize batches split; an oversize snapshot goes out as a
  prefix plus `continues` deltas that `fuz_client` reassembles).

### `fuz_wire` / `fuz_client`

`fuz_wire` is the UDS protocol — the postcard envelope and the daemon /
sidecar / workload DTOs; `PROTOCOL_VERSION`'s doc is the version history, and
any shape change bumps it. `fuz_client` is its async client (`check_health`,
`daemon_status`, `shutdown`, the subscribe streams); a subscription ended
before its first snapshot is an error, never an empty success. Outside this
workspace, one app server takes both (and `fuzd_server` as a dev-dep for
an isolated-fuzd test), so a wire or `fuzd_server` API change reaches it.

### `fuz_sidecar`, `fuz_deno`, `fuz_python`

The dormant sidecar workload: the controller framework and the runtime
definitions (`fuz_deno`, `fuz_python`) behind fuzd's `sidecar` feature. No
runtime consumer.
./sidecars.md.

## Libraries for other workspaces

### `fuz_eval`

**One-shot** config eval through `fgro eval`, Gro's runtime, which owns the
walls (its kernel box, determinism, timeout). `eval_module`:

- settles the config's trust root and the run-as user — never root: under
  euid 0 it drops to the project's owner (with `SUDO_GID` when that owner ran
  `sudo`) and refuses a root-owned project; a project that is or holds the
  run-as user's home is refused either way;
- verifies `fgro` against a blake3 pin (`fgro_verify`, optional stat-keyed hash
  cache) and execs it through the held descriptor in the trust root, with only
  `TZ=UTC` in its environment and its own process group;
- returns the value and module graph (`GraphDump`) from fgro's envelope, read
  fail-closed (`ProtocolViolation`), or fgro's failure kind (`EvalErrorKind`).

Rules and residuals are its rustdoc. `testing_fake_fgro` stands in for fgro in
the integration suites; the real-fgro suites are `#[ignore]` and take
`FUZ_EVAL_TEST_FGRO`, and `uid_drop` is `#[ignore]` and runs as root
(./testing.md). Sole consumer: Zap.

### `fuz_pty`

A safe PTY API over libc. **Linux-only** (kernel ≥ 4.13; `execvpe` is a GNU
extension). The one crate allowing `unsafe_code`; sole consumer `zzz_server`.

## Spine

The Rust twin of fuz_app's `db/`, `auth/`, `http/`, `realtime/`, `actions/`,
`server/`, cell and fact layers. Wire literals, close codes, DDL, and error
bodies match the TS twin; read it before settling a shape (../CLAUDE.md § Values and
policy).

### `fuz_db`

The base: the pool, the identity-tracked migration runner, query helpers,
schema readiness (`check_schema_drift`, behind `/ready`), and the `db-status`
CLI (`status::run_db_status_cli`). **Commit with `commit_checked`**: a bare
`COMMIT` silently rolls back a transaction an earlier error aborted;
`commit_checked` reports it (`DbError::TransactionAborted`).

`ActionDb` is a request's handle — a pooled client, or the request
transaction for a side-effecting action. `GenericClient` is sealed and not
dyn-safe, so the handle is this concrete enum, and `action_db_dispatch!` runs
a generic `query_*` over whichever client it holds. Being concrete, it rides
object-safe traits — the hooks that receive it are in § `fuz_cell` /
`fuz_cell_actions`.

### `fuz_http`

HTTP primitives: JSON-RPC envelopes and the `JsonrpcError` taxonomy, flat REST
error bodies, client-IP resolution (trusted proxies, right-to-left XFF that
stops at the first malformed entry; `rate_limit_ip_key` keys an IPv6 client by
its `/64` at limiter call sites only, so audit rows keep the full address), the
gates (the Origin-only allowlist with no Referer fallback, the opt-in `Host`
gate, the CORS simple-request gate), strict param / query / JSON-body
decoding that doesn't fingerprint the backend, and `/ready`.

- **`compose_stack` is the one composition root**: route groups, each with a
  body cap and an origin scope, behind one fixed layer order, so an over-cap
  body is 413 before 403 and unrouted paths pass the same gates. The stack
  mounts every gate; none is mounted by hand. It returns a `GatedRouter`, the
  only thing `serve_with_shutdown` serves, and logs how client IPs resolve
  (trusted proxies or the TCP peer), so no server repeats it.
- A request panic answers a generic `500` only under a `panic = "unwind"`
  release profile in the server's workspace.
- **`serve_with_shutdown`** — its own hyper accept loop, with a required
  `ShutdownCloser` that closes every WS / SSE connection at shutdown, and
  write-progress and header-read deadlines the TS twin lacks.
- A server with an `AuthGate` builds its options with `AuthGate::stack_options`,
  so both origin checks read one allowlist.
- **Action params** — `params` holds:
  - the hand-decode helpers a handler reads `params` with (field parsers,
    `reject_unknown_keys` / `reject_null_keys`, `serialize_result`);
  - the `InputShape` every `ActionSpec` declares, with its void rule
    (`require_void_params`);
  - the wire UUID grammar (`is_valid_uuid`, and the `deserialize_*wire_uuid*`
    serde adapters that put it in front of `Uuid`'s permissive parser);
  - the `deserialize_*wire_int` adapters, which read a typed integer as
    `z.number().int()` does (any integral spelling, within the safe-integer
    range);
  - `json_has_own_proto_key`, the walk behind the dispatcher's
    `params_proto_key` refusal.

  `strict_params` is the typed half (`parse_strict_params`). Field rules that
  name auth-owned fields (role names, text bounds, the paging reasons) stay in
  `fuz_auth`.
- **Logged causes** — `internal_error_with_source` and
  `db_unavailable_with_source`, and their flat-REST twins
  `internal_error_response_with_source` / `db_unavailable_response_with_source`,
  log at `error` the error's `format_error_chain` (plus a `sqlstate` field,
  `fuz_db::sqlstate_in_chain`, when a driver error carries one) and answer
  the opaque body. A
  `tokio_postgres::Error` or `fuz_db::DbError` prints only its kind, so a
  direct log of one uses `error = ?e`.
- **`BaseServerEnv`** — the env every spine server reads the same way, twin of
  fuz_app's `BaseServerEnv`; the vars and their rules are `fuz_http::server_env`'s
  rustdoc.
- **Wildcard origins are opt-in** — the boot, the boot-only branch included,
  refuses a wildcard allowlist entry (`:*`, a `*` label) before any database
  work unless
  `FUZ_ALLOW_ORIGIN_WILDCARDS=true`, and an admitted one warns on every boot;
  `fuz_http::origin_wildcard` owns the rules.

fuz_app's `RouteSpec` / `AppSurface` have no Rust twin (`axum::Router` covers
both).

### `fuz_auth`

The auth surface (twin of fuz_app's `auth/`): ingress validation (the zod
grammar twins for usernames, emails, token ids, role names, and fact hashes),
`AuthGate` (origin check, then credential resolution: daemon token → cookie
→ bearer), token scopes, global roles, capped sessions and tokens, Argon2id
passwords, rate limiting, the REST routes (`/status`, `/login`, `/logout`,
`/password`, `/bootstrap`, `/signup`), auth cleanup, and the audit registry.
The rules a change must keep:

- The non-cookie credential legs (daemon token, bearer) refuse browser callers.
- Every `AuthSpec` names a `CredentialGate`; gate order is credential → scope
  → role. A scope-narrowed token is RPC-only, and the surfaces that answer
  anonymous callers (`fuz_fact_serving`'s cell-scoped read, `/status`) answer it
  as anonymous.
- Builtin roles are global-only (refused with a scope, offered only by a
  global admin, never self-service); the dispatcher's role gate and every
  builtin-role check read the **global** grant. REST `?acting=` goes through
  `route_helpers::require_acting_actor`.
- On the REST routes a failed pool checkout answers `fuz_http`'s flat 503
  `service_unavailable` and any other internal failure its flat 500. The audit
  write stays fail-open, and a failed credential read ends the walk with
  `CredentialReadFault`'s answer — the 503 for a failed checkout, the
  plain-text 500 (the TS twin's Hono default) for a failed query — never a
  lower credential or anonymous.
- `create_capped_session` is the only production session minter
  (`fuz_testing`'s fixtures insert uncapped rows directly).
- Every rate-limited attempt reserves its slot before it runs, and an attempt
  abandoned after its Argon2 work started is still charged.
- `AuditEventType` is the spine-wide closed registry (auth and cell events);
  each `AUDIT_EVENT_SPECS` row fixes its wire literal, routing, and
  `RevocationScope`.
- The daemon token's consuming half is here; its producer is `fuz_testing`, so
  production assemblies leave it `None`.

Credential formats, byte-identical with fuz_app so a credential either spine
mints works on both:

- **Session token**: 32 random bytes, base64url without padding. Stored as
  `auth_session.id`, the BLAKE3 of the token as 64 lowercase hex
  (`hash_session_token`).
- **API token**: `secret_fuz_token_` + 32 random bytes in unpadded base64url;
  its public id is `tok_` + the first 12 body characters. Stored as
  `api_token.token_hash`, the BLAKE3 of the whole token as 64 lowercase hex
  (`hash_api_token`).
- **Session cookie**: `{token}:{expires_at}.{signature}`, with `expires_at` in
  Unix seconds as ASCII digits and the signature an HMAC-SHA256 in padded
  standard base64. Keys come from `SECRET_FUZ_COOKIE_KEYS`, split on `__`,
  each at least 32 UTF-16 code units; the first signs and every key verifies
  (`Keyring`'s rustdoc covers rotation).
- **Password**: an Argon2id PHC string (m=19456, t=2, p=1).

The bootstrap token is an operator-written file, not a minted credential: the
expected value is the file's bytes minus one optional trailing LF, compared in
constant time against the submitted token — no other trimming. A value under
`BOOTSTRAP_TOKEN_MIN_BYTES` (32) reads as an unreadable file, at boot and at
request time, with an error log.

Revocation: § Spine cross-crate rules.

### `fuz_realtime`

WS and SSE transport. **Boundary**: no `ActionSpec` knowledge — origin and auth
resolve in the consumer's upgrade handler, and per-message dispatch is the
callback `fuz_actions` supplies.

- `ConnectionRegistry` (WS) and `SseRegistry` (SSE): per-account / per-session
  caps (evict-oldest), **two-phase registration** (pending → re-check →
  admit), and a byte budget per connection. A send never waits; one that
  doesn't fit closes that connection.
- **Every WS write has a deadline**, so a client that stops reading holds its
  loop for one write deadline; connections close at the credential deadline.
- `audit_stream_router` (`GET /api/admin/audit/stream`) — the non-RPC gate
  pipeline over SSE.
- `RealtimeCloser` fans each close to both registries; it's the closer every
  consumer mounting the audit stream binds, and the closer it passes
  `serve_with_shutdown`.

### `fuz_actions`

The dispatch framework, top of the spine: `ActionSpec`, `ActionRegistry`,
`ActionContext`, and `perform_action` (one enforcement order on HTTP and WS;
a transaction iff `side_effects`, committed with `commit_checked`, post-commit
effects drained only after it), the `/rpc` router, the WS endpoint
(`register_action_ws`), the protocol actions, and the `run_app` seams.

`fuz_actions::server` is the spine-consumer server toolkit — the twin of
fuz_app's `server/app_backend.ts` + `server/app_server.ts`. Its module doc maps
the pieces; `create_app_backend`'s doc owns the boot order. What a change must
keep:

- A server keeps only its own domain state, action specs, and final `Router`;
  everything else is the toolkit's.
- `ActionRateLimits` is one budget across RPC, WS, and the auth set.
- `StartupError` carries the exit codes (configuration and a wrong transaction
  isolation → 2, else 1).
- A server refuses to boot unless Postgres's `default_transaction_isolation` is
  `read committed` (`REQUIRED_TRANSACTION_ISOLATION` has why).
- Every `ActionSpec` declares its `fuz_http::InputShape` (no default): `Void`
  for a method whose twin's input is `z.void()`, `Object` otherwise.
  `perform_action` holds a `Void` method to the no-arg call (absent, `null`,
  or `{}`) after the authority gates and before the handler, so a
  parameterless handler never checks `params` itself;
  `_testing_action_manifest` reports the shape as `input`, which the
  cross-backend manifest parity gate diffs.
- `GET /rpc` refuses a side-effecting method. Match the WS inbound message cap
  to the RPC body limit.
- `ConnectionRegistry::broadcast` applies no per-recipient filter, so the WS
  endpoint's role gate is a consumer's ACL over broadcasts unless it uses
  `broadcast_filtered`.
- WS upgrade admission: § Spine cross-crate rules.

### `fuz_cell` / `fuz_cell_actions`

The cell layer, split like the fact layer. `fuz_cell` is storage and authz:
DDL byte-identical with the TS twin, the query modules, and `cell_authz`.
`can_view_cell` / `can_edit_cell` = global admin ‖ owner ‖ scope-matched
grant, plus public reads (the public and grant arms only while `moderation` is
unset or `approved`); `can_manage_cell` = global admin ‖ owner (a scoped
`admin` row bypasses nothing); `cell_view_sql` is the one SQL form of
`can_view_cell`, and relation lists keep only edges whose far end the viewer
can see, before `LIMIT`. `can_steward_cell` is a separate moderator read arm,
composed only at the surfaces `cell_steward`'s rustdoc names. `fuz_cell` ⊥
`fuz_actions` **(audited)**, so a serving-only consumer composes
`can_view_cell` without the verbs.

`fuz_cell_actions` is the RPC verb set (`build_cell_spec_set`, its seams on
`CellSpecSetOptions`): the core, ACL, field, item, and audit verbs. Its error
mapping mirrors TS, every write emits its audit event in-tx, and
`CellCreateAuthorize` covers every cell `cell_clone` writes too. A root's
contribution `policy` is a manage-tier column, opaque to the spine: the create
authorizer reads it (`root_policy`) and accepts each write of it
(`validate_policy`, which refuses by default — and with no authorizer every
policy is refused `cell_policy_unsupported`); it is set at a root's
`cell_create` and changed only by `cell_policy_set`, never through `data`,
which an editor grant can write. A `CellGrantCreateAuthorize` narrows a
manager's `cell_grant_create` after the spine's own gates; a
`CellGrantRevokeAuthorize` widens `cell_grant_revoke` to a scope's steward,
asked only for a non-manager, non-grantee caller revoking a role-shaped grant
with a scope (a refusal keeps the 404 mask; an allowed revoke audits
`steward: true`, and its delete matches the level the hook saw). The authorize
hooks — `CellCreateAuthorize`, `CellGrantCreateAuthorize`,
`CellGrantRevokeAuthorize`, and `fuz_auth`'s `OfferCreateAuthorize` — get the
request's `ActionDb`, the request transaction, as each gated verb has side
effects, and must only read through it; nothing enforces that
(`CellDataValidator` is pure and takes none). **Fact refs are
possession-gated**: a non-admin write introducing a ref to a fact its acting
actor holds no `fact_holder` row for is 403 `cell_ref_not_held`, answered from
holder rows alone (no existence oracle), in SQL with no runtime `fuz_fact`
dependency.

### `fuz_fact` / `fuz_fact_serving`

`fuz_fact` is the content-addressed byte store: **un-authz'd, with no HTTP,
cell, or auth** (`fuz_fact` ⊥ `{axum, fuz_http, fuz_cell, fuz_auth,
fuz_actions}` **(audited)**), so bytes reach a client only through
`fuz_fact_serving`. Embedded `bytea` or disk CAS, verify-on-read, a
`fact_holder` row on every put. Its migrations run after `fuz_auth`'s
(`fact_holder` references `actor`). Every long-running disk-CAS consumer spawns
`spawn_orphan_temp_sweeper` beside its server and joins it on shutdown.

- **A fact id is `blake3:` + 64 lowercase hex**, the TS `FactHashSchema`
  grammar. Every ingress (a route segment, an RPC param, a cell field naming a
  fact) must read it through `ContentHash::parse_fact_hash`, or
  `fuz_auth::is_valid_fact_hash` where the string is kept (cell `refs`, a
  declared ref) — the same grammar, held equal by a test.
- A disk-backed row's `external_url` is `file:<shard>/<rest>` over the same
  lowercase hex, and a reader resolves it only when it is the address of the
  row's own hash (`ParsedFactUrl::addresses`), since the streaming read and
  the serving routes don't re-hash. A row that fails either check is a
  logged not-found on `get` and `open` alike (`Ok(None)`, as the TS `get`
  answers `null`), not an error.
- Fact refs are the ones a put declares; the store never scans content for
  addresses.

`fuz_fact_serving` is its **sole authz'd reader**: the cell-gated route
(authz on the `(cell, hash)` edge through `can_view_cell`) and the admin-only
bare route, byte-for-byte with the TS twin. `XAccelConfig` makes un-validated
X-Accel unconstructible: it parses the nginx config and refuses any facts
location that isn't a server-level `location ^~ … { internal; }` carrying the
fact security headers, and any `ssi` or headers-more that could undo them (the
`nginx` module's rustdoc).

### `fuz_db_admin`

The allowlist-gated table browser under `/api/db`: `browsable_tables` minus
the unoverridable `NON_BROWSABLE_TABLES` credential floor, a
`NON_DELETABLE_TABLES` floor, and audited deletes. The role is checked at
**account grain** (`?acting=` is resolved and discarded). Sole consumer:
`fuz_forge_server`.

### `fuz_testing`

**Test-only spine fixtures — never in a production binary (audited).** A crate,
not a `fuz_auth` feature, so unification can't route it into production.

- What production must be unable to reach: the test hasher, the daemon-token
  producer, and the daemon-token-gated `_testing_*` specs. A consumer's
  `testing_*` binary mounts `_testing_*` specs only together with their TS
  twins, since the cross-backend action-manifest diff is exact.
- The shared `#[ignore]` Postgres harness (./testing.md § Postgres suites),
  including `TestingTableLock` for driving races deterministically, and
  `assert_expected_schema_fixture`, a server's `/ready` fixture drift guard.
- A `testing_*` server's toolkit wiring: `testing_backend_options` (the test
  hasher, limiters off, `startup_reset_hook`, in-flight audit tracking),
  `require_daemon_token_from_env`, `testing_reset_specs` (`_testing_reset` +
  `_testing_drain_effects`, over the runtime's daemon-token state) over
  `truncate_reset_state` — the spine's `fuz_cell::CELL_DROP_TABLES` /
  `fuz_fact::FACT_DROP_TABLES` joined with the server's own tables — and
  `inert_app_backend` for router tests without a database. Each spine table
  const, `fuz_auth::AUTH_INTEGRATION_TRUNCATE_TABLES` (the auth tables the
  reset deletes from) among them, is held to its chain's DDL by
  `migration_created_tables`.
- A dev-dependency of the spine crates and consumer servers, and a normal
  dependency of `testing_spine_stub` (`fuz_audit` walks runtime edges only, so
  the dev cycles are allowed).

## npm bridge

### `fuzi_core`

The engine behind `fuzi`: lockfile read → classify → plan → fetch into the CAS
under `~/.fuz/cache/npm/` → extract via `fuz_archive` into a staging tree →
place sibling links, link `.bin` → completeness check → atomic swap. No spine,
fuzd, or signing deps; sole consumer `fuzi`.

- **No code path runs package code** (no lifecycle scripts, no compilation); a
  seccomp no-exec filter is deferred (./deferred_security.md).
- Only sibling `link: true` entries (depth 1, `resolved` exactly `../<dir>`)
  are linked, and a link target is never written to; other link shapes are
  refused. Every placed key passes `validate_nm_key`.
- `verify` is structural (presence, version, links, bins).
- `install --dry-run` writes nothing but gives the real run's verdict on the
  cache: it re-hashes every cached tarball, serially, so a warm dry run can
  take longer than the install. Online a corrupt entry is would-fetch and
  listed in `healed`; under `--offline` it is `offline_cache_corrupt` (65).
- `package-lock.json` and `package.json` are opened non-blocking and must be
  regular files (a symlink is followed, as npm does); each read is capped at
  `fuz_sys::limits::MAX_BUFFERED_SIZE` and a file over it is refused (`io`,
  74), never truncated. `verify`'s per-package `package.json` read is the same
  but no-follow.
- An extraction error names its package: a security-class `ArchiveError` is a
  bad package (exit 65 — the bytes matched the lockfile), the rest I/O (74).
- A staging tree another process cut into (a concurrent `fuzi clean` sweeps
  live `.fuzi-installing-*` trees too) is refused at publish when it is missing
  a placed package directory, shipped `package.json`, link, or `.bin` link, and
  a write that fails `NotFound` because its directory went is read the same way
  — `staging_incomplete`, exit 75, `node_modules` unchanged. It is a cheap
  check, not an exclusion: a sweep landing between it and the publish rename
  still gets through, and files within a package are not checked, so a sweep
  that stops part-way can publish a package missing files; the planned
  project-level install lock is the real exclusion.
- `node_modules` is replaced by renames, so one that can't be renamed is
  refused (exit 73): a mount point (`node_modules_mount_point` — the device
  check, or the move-aside's `EBUSY`), or a directory the filesystem won't
  rename in place (`node_modules_not_renameable` — the move-aside's `EXDEV`,
  e.g. an overlayfs lower layer).
- Fetch failures split transient / permanent / I/O, which `fuzi` maps to
  sysexits.
- Prints nothing; payload strings stay raw in the structs and are escaped in
  every human rendering.

## Spine cross-crate rules

### WebSocket close codes

Wire twins of fuz_app's (`fuz_realtime::ws_close_codes`):

| Code | Const | When |
| --- | --- | --- |
| 1001 | `WS_CLOSE_GOING_AWAY` | server shutdown, or a registration it closed or preceded |
| 1009 | `WS_CLOSE_MESSAGE_TOO_BIG` | inbound message over the cap |
| 1011 | `WS_CLOSE_INTERNAL_ERROR` | the admission re-check itself failed (fail closed) |
| 4001 | `WS_CLOSE_SESSION_REVOKED` | credential revoked, or expired (`WS_CLOSE_CREDENTIAL_EXPIRED_REASON`) |
| 4003 | `WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT` | client silent past the receive timeout |
| 4004 | `WS_CLOSE_CONNECTION_LIMIT` | superseded by the per-account cap (its credential is still good) |
| 4005 | `WS_CLOSE_OUTBOUND_OVERFLOW` | outbound queue over its byte budget |
| 4006 | `WS_CLOSE_PERMISSION_REVOKED` | a role the connection's endpoint required was revoked |

### Revocation

- In-transaction revocation handlers close sockets on the post-commit queue
  (`queue_connection_close`), never before the commit — a client rechecking on a
  4001 can't find the revoked row still there.
- REST `/logout` and `/password` close inline, **before** their fail-open audit
  write — the one close a failed audit INSERT can't suppress, and the reason the
  closer must reach SSE. `/password` closes only once its transaction commits,
  so a rollback closes nothing.
- A request dropped between a commit and its close leaves the write committed
  and the connections open — on `/password`, `/logout`, `/login`'s eviction
  close, and the dispatcher's post-commit drain alike.
- The revocation guard (WS and SSE alike) dispatches on `AUDIT_EVENT_SPECS`'
  `RevocationScope` and fires only on a written audit row. A global
  `role_grant_revoke` closes the account's connections gated on the role (WS
  with 4006).
- Cap evictions (`/login` past the session cap, `account_token_create` past the
  token cap) write no revoking audit row, so their handlers close the evicted
  credential's connections directly after the commit.
- Expiry: every WS and SSE connection closes at its credential's deadline in
  the process holding it; the session sweep closes each session it deletes
  again, for the connections the sweeping process holds. Expired API-token rows
  are not swept.

### WS upgrade admission

`fuz_actions::admit_upgrade` (public, for a consumer's own upgrade handler)
runs after the gates origin → 401 → token scope → acting actor (on every
endpoint, `?acting=` through `require_acting_actor`) → `required_roles` (the
resolved actor's active global grants, counted only while the actor and its
account are active, so an actor soft-deleted mid-upgrade is refused). Then:

1. register pending;
2. re-read the credential and roles;
3. admit, where the per-account cap evicts.

A revocation either preceded registration (the re-read sees it) or followed it
(and found the pending entry), so the socket is refused before any loop runs:
4001 for the credential, 4006 for a role, 1011 when the re-read failed, 1001
when shutdown closed or preceded registration. A refused request never closes
another socket. Per-message dispatch re-authorizes the actor, not the session
or token, so admission is where a revoked credential is caught.

### Non-RPC gate pipeline

The audit stream, `fuz_db_admin`, and `fuz_fact_serving`'s bare route run one
pipeline: origin → credential (session-only by default) → `?acting=` through
`require_acting_actor` → role. The audit stream reads the role from the
**resolved actor's** grants; `fuz_db_admin` at account grain.

## Error rendering

How errors reach the user:

- **Untrusted text** — text from outside the program (a storage key from an
  unsigned pointer, a manifest field read before its signature is checked, a
  response body, a remote command's stderr, a parser's message) is escaped where
  it is rendered, in the `Display` of the type that holds it
  (`fuz_sys::text::escape_untrusted` / `quoted`, over `truncate`). The struct
  keeps the value as given. A wrapper embeds an inner message as is; one needing
  a whole message on one bounded line uses `escape_message`, which leaves
  existing escapes alone. `fuz_crypto` (no workspace deps) renders its
  canonical-JSON error's string as bounded ASCII.
- **Source chains** — `fuz`, `fuzd`, `fuzf`, `xtask`, and the spine servers print the
  chain on their `error:` line via `format_error_chain` (`xtask` and a server's `main`
through `report_failure`, a server with `StartupError`'s hint and exit code): each
  cause `: `-joined, skipping one the text so far already ends with, each cut
  to a bounded length and escaped. A
  cause that must not be printed — a URL that can carry a credential, text its
  own message shows bounded — stays out of `source()`.
- **Hints** — `.hint()` exists only where some binary renders it (`fuz`,
  `fuzf`, `fuzd`, the `cargo xtask` commands, the spine servers'
  `StartupError`); `fuzi_core`'s
  `FetchError::is_permanent` drives retry classification.
- **Classification** — `is_security_violation` (`ArchiveError` →
  `TarballError` → `ReleaseError`, plus the release log and co-signature
  errors) stays complete at every wrapper level, even an uncalled one, so a
  future caller never inherits an incomplete fail-closed classification.
  `is_unconfirmed` (`ReleaseLogError` → `ReleaseError`) forwards the release log
  check's soft failure the same way; `fuz` maps it to exit 75.
