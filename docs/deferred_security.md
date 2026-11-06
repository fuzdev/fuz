# Deferred Security

Security work evaluated and deliberately deferred, each with a "revisit when"
trigger. Not a backlog — most may never be built; it records what the current
posture does *not* cover. What is built is ./security-model.md,
./release_log_check.md, and ./crates.md.

## Distribution and keys

### Release log: public log and default origin

Built: the publisher's writers (./release_log.md) and the opt-in client check,
co-signature verification included (./release_log_check.md). Deferred: a public
log repository and a built-in origin — so by default nothing is checked; any
co-signer or embedded witness key; caching or requiring a co-signature.
`install.sh` reads only the unsigned `latest/` pointer, from the first
reachable origin. Revocation reaches only clients with `FUZ_RELEASE_LOG_URL`
set and leaves storage untouched (./release_log.md § Revoking a Release).
**Lands when** the public release host (`releases.fuz.dev`) and a public log
repository exist — the log is the bootstrap edge's authenticity check, so it
ships with the host.

### Offline root key / release-key rotation

The trusted release keys are the list embedded in each binary; no key above them
signs or revokes a release key, so with one key embedded, a compromise means
every install re-bootstraps (./security-model.md § Key Compromise Response).
**Revisit when** public distribution has users who can't be asked to
re-bootstrap, or a second key or maintainer exists.

### Signing key encryption at rest

`0600` key files are adequate for one maintainer (a keylogger defeats a
passphrase; SSH keys are commonly unencrypted). When needed: a
`fuz-signing-key-v2` format (v1, unencrypted, is the only one today) with
Argon2id + XChaCha20-Poly1305, refusing non-interactive signing; new deps
`chacha20poly1305` and `rpassword`. **Revisit when** there are multiple
maintainers, a high-value deployment, or a user asks.

### mlock for the signing key

`fuz_sign` holds the publisher's signing key in memory while it signs
(zeroized on drop); `mlock()` would also keep it out of swap. A material
improvement that may justify `unsafe` (./platform_support.md § Rules).
**Revisit when** signing moves to a shared or long-running host.

### Binary-name collisions between tools

A tool manifest may not declare a self-artifact binary name (`fuz`, ASCII
case-folded) — refused at the manifest, the publish, and the link. Not refused:
a name a filesystem's Unicode folding or normalization would resolve to `fuz`,
and two tools claiming one name (the later install takes `bin/<name>`; nothing
records link ownership). Reaching either takes a signed first-party manifest.
**Revisit when** a second publisher or a third-party tool channel exists.

### Persistent downgrade protection

Built: no-downgrade against the **installed** version on `fuz self upgrade` and
`fuz tool install` / `upgrade` (`--allow-downgrade` overrides). Deferred: a
highest-seen version in `~/.fuz/state/` that survives an uninstall or a
`--force` reinstall. **Revisit when** a rollback attack induces a
reinstall-from-scratch.

### Signature expiry / freshness

`signed_at` sits outside the signed bytes and signatures never expire; staleness
is handled by no-downgrade and log revocation. Making a timestamp trustworthy
means moving it into the signed bytes, which breaks every signature. **Revisit when** a concrete time-boxed-validity use case
appears.

### Multi-source key publication

The key lives in the repo and the binary. Publishing it elsewhere (website,
social, DNS TXT) only helps users who compare. The opt-in release log pointer is
already a second-origin check at install. **Revisit when** a first-install
verification step needs an out-of-band key, or an incident questions the key's
authenticity.

### Generic hardening

| Item | Why not now | Revisit when |
| --- | --- | --- |
| Reproducible builds + rebuilder attestations | no reproducible builds yet; needs external verifiers | builds reproduce and verifiers volunteer |
| SLSA provenance (hermetic builds, attestations) | priority is signed distribution working | external pressure (enterprise, audit) |
| Vendored deps / cargo-vet | `Cargo.lock` pins; crates.io compromise is rare | high-security deployments, or a compromise touching our deps |
| HSM signing | protects exfiltration, not an attacker who can invoke signing | multiple maintainers, high-value targets |
| Threshold / MPC signing | one key, one maintainer; plain N-of-M multisig comes first | a second maintainer joins |
| Key ceremony, escrow, succession | theater without organizational backing | multiple maintainers, users depending on updates |
| Post-quantum / hybrid signatures | ed25519 not threatened; PQ libraries maturing (the envelope's `algorithm` / `format` fields leave room) | standards mature, or an ed25519 weakness |
| TLS / SPKI pinning | complicates rotation; TLS anchors only the first install | user demand, or a CA compromise |
| Tor / IPFS / BitTorrent distribution | tiny user base, infrastructure cost | adversarial networks or censorship |
| Canary releases, anomaly detection, storage monitoring | too few users and releases; a public log provides monitoring as a side effect | more users, an automated pipeline, or a public log |
| Mirror fallback | any mirror can be read with `--storage` (trust is the signature); one `--storage` source, no fallback | the primary host has availability problems |
| Integrity-monitoring daemon | a local attacker can disable it | enterprise deployment with central alerting |
| Formal verification, ZK build proofs | effort / research | the crypto path stabilizes, or research matures |
| Formal security policy (SLAs, backports, safe harbor) | pre-1.0, single maintainer | external users depend on it |
| Third-party security audit | cost; code changes fast | post-1.0, funding |
| Incident runbook beyond the key-compromise steps | one maintainer who knows the system | multiple maintainers, or an incident shows gaps |
| Background updates, passive update notices | users choose when to update; `--check` is the manual form | users ask |
| `fuz tool` rollback and prune | `fuz tool install --version X --allow-downgrade` covers rollback; leftovers are small | tool upgrades break often, or installs pile up |
| Delta transfer between versions | binaries are small | binaries grow |
| Export control, license audit, compliance trail | standard crypto libs, permissive deps, no regulatory need | commercial distribution or copyleft deps |

## Local runtime

### fuzi no-exec enforcement (seccomp)

fuzi runs no package code by construction (no lifecycle scripts, no
compilation; the static guards are clippy `disallowed_types` /
`disallowed_methods` in the fuzi crates' `clippy.toml` and the text scan in
`crates/fuzi_core/tests/exec_free.rs`). A
seccomp filter would make that hold even through a bug: a regression adding a
spawn, a compromised dependency, or a crafted tarball exploiting the parse path
— sha512 proves bytes match the lock, not that they're safe to parse. Design:
`KillProcess` on `execve`/`execveat`/`ptrace`/`fork`/`vfork`, with
`clone`/`clone3` allowed (glibc threads use `clone3`; a fork-shaped child
inherits the filter), installed at the top of `main()`; a full syscall
allowlist later. Linux-only; needs `seccompiler`. **First in line** once fuzi
installs lockfiles the user didn't write.

### fuzi tarball entry-count cap

`safe_extract` caps bytes but not entries, and an empty entry costs one 512 B
header, so about two million empty files fit under fuzi's 1 GiB total cap — an inode-exhaustion DoS
that cleans up on failure, not on success. Exploiting it needs a lockfile whose
`integrity` matches the crafted tarball. Fix: `ExtractLimits::max_entries`.
**Lands with** the seccomp filter.

### Daemon sandboxing

Dropping capabilities or seccomp/landlock for fuzd is hard while it spawns
subprocesses (`systemctl --user`, sidecars when enabled), and a compromised
same-user daemon already means the game is lost. **Revisit when** fuzd handles
untrusted input or runs with elevated privileges.

### Sidecar hardening (dormant)

If the sidecar workload is revived (./sidecars.md): sidecars run with the
daemon's privileges (containers / gVisor / Wasmtime would bound them); their
link is JSON-over-stdio; the Deno definition's npm imports are pinned but its
JSR import floats on a major range with no lockfile. **Revisit when** sidecars
run untrusted or user-specified code.

## Spine and network surfaces

What remains for the spine crates' network-facing surfaces. The built
mechanisms — connection and stream caps, two-phase admission, outbound byte
budgets, write deadlines, the request-head and write-progress deadlines,
credential-deadline closes — are ./crates.md (§ Spine cross-crate rules and the
`fuz_http` / `fuz_realtime` / `fuz_auth` entries).

### WebSocket and SSE

- **Per-IP and global connection caps** — the per-account cap does nothing for
  many accounts behind one address, and nothing caps the total.
- **Rate limiting failed-auth upgrades** — a refused upgrade costs a credential
  lookup and counts against no limiter.
- **TCP keepalive** — none on accepted sockets, so a quiet SSE stream whose peer
  vanished without a FIN is held until a write waits or the cap supersedes it
  (a WebSocket closes on its
  receive timeout; an idle HTTP connection at `HEADER_READ_TIMEOUT`).
- **Throughput floors** — the HTTP write-progress deadline restarts on any byte,
  and the WebSocket write deadline is per frame, so a client trickling just
  inside them holds its response or loop indefinitely.
- **A total outbound budget** — budgets are per connection; an account at its
  cap can hold cap × budget, and nothing bounds the sum.
- **Sparing a slow but honest reader** — over-budget or too-slow clients are
  disconnected (4005, or a dropped socket) and must reconnect; nothing replays
  fan-out frames a close discarded (a request's own response is never queued).
- **A deadline on a refused upgrade's close frame** outside shutdown.
- **A refuse-newest cap mode** — the caps only evict.
- **Cross-process enforcement** — caps and sweeps count one process.
- **A bound on pending registrations** — a connection awaiting admission is
  outside the cap for one credential re-read.
- **A role that ends without a revocation row** — a grant reaching `expires_at`,
  or a `role_grant` / `actor` row deleted outside the grant verbs, writes no row,
  so a socket admitted on it keeps receiving the endpoint's broadcasts.
- **An exact re-check for an any-of role gate** — losing any listed role closes
  the account's sockets there, even if it holds another.
- **Telling an evicted SSE stream why** — it ends with no frame, so a browser
  reconnects and a client past the cap ping-pongs; a `superseded` frame is a
  twin wire change.

**Revisit when** realtime fan-out grows, or before public / untrusted exposure.

### HTTP connections

- **A request-body deadline** — once the head is in, nothing times the body, so
  a client declaring a body and never sending it holds a connection and handler,
  unauthenticated on `/login`, `/signup`, `/bootstrap`. The fix belongs where the
  body is buffered, not on the socket.
- **A lingering close after an early response** — a response sent before the
  body was read (a 413) closes with the rest unread, which the kernel turns into
  a reset the client may see instead of the status (nginx's `lingering_close`).
- **A global or per-IP connection cap**, and **a request-rate or lifetime bound**
  on keep-alive connections.

**Revisit when** a spine server is exposed without a reverse proxy; behind nginx
the proxy's own timeouts and limits face the client.

### PostgreSQL

Queries are parameterized; the runtime-interpolated identifiers in
`fuz_db_admin` and `fuz_db::status` pass `is_valid_sql_identifier`. Deferred:

- **TLS to the database** — `create_pool` connects `NoTls`, assuming a
  co-located Postgres.
- **Audit log retention** — `query_audit_log_cleanup_before` exists and nothing
  calls it.
- **Credential rotation, backup encryption** — deployment-owned.
- **Row-level security** — skeptical: defense in depth, but it can mask missing
  application scoping; prototype one boundary first.

**Revisit when** a multi-tenant consumer ships, a database crosses an untrusted
network, or `audit_log` needs pruning.

### Browser sessions

- **Serializing concurrent session creators** — the cap's count / evict / insert
  runs in one transaction but under Read Committed two creators each evict
  against a stale count and both commit above the cap (same for the token cap;
  both queries document it). Needs one lock per `(account, credential kind)`;
  the oracle is a barrier-based Postgres test.
- **A login across a password change** — `/login` doesn't re-read the hash it
  verified before minting, so a verify overlapping a `/password` commit can mint
  a session on the old password. Needs the insert to re-check the hash in-tx.
- **A `__Host-` cookie prefix** — the default `fuz_session` name has none, so a
  sibling subdomain can plant one; the name is the consumer's to pass, and the
  default is a wire value both twins share.
- **The `Host` gate and simple-request layer are opt-in** per consumer.

**Revisit when** concurrent logins per account matter, a consumer serves sibling
subdomains it doesn't control, or a spine server is exposed beyond a trusted
network.
