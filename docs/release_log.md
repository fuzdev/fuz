# Release Log

Writing the release log: recording a release as it is published, creating a log
from releases already in storage, revoking a release, recovering a failed
write, and co-signing. The reader side is ./release_log_check.md; the file formats are
./release_format.md § Release Log Files; the publish this hooks into is
./release_workflow.md.

The release log is a git repository, separate from release storage, holding one
signed `head.json` (every release as a row, each target's digests under it) and
a `latest/` directory of one-line pointer files. Its writers are publisher-only
(`fuz_sign`, behind `cargo xtask` and `fuzf`); `fuz` only reads it.

## Recording a Release

Both xtask publish commands (and `fuzf tool publish`) take `--log-repo <path>`,
the root of a local clone of the log repository:

```bash
cargo xtask publish self --storage /path --log-repo /path/to/release-log
cargo xtask publish tool fuzd target/release/fuzd --version 0.3.0 --storage /path --log-repo /path/to/release-log
```

Without `--log-repo`, publish is the upload alone. With it, publish also:

1. **Checks the clone** — the root of a git work tree, on a branch with an
   upstream a plain `git push` updates (checked once the upstream exists), with
   no uncommitted change to `head.json` or `latest/`, no ignore rule covering
   them, and no symlink among them.
2. **Fast-forwards** to the upstream. A diverged clone is refused; nothing is
   merged or rebased.
3. **Verifies the existing head** against the keys embedded in the publishing
   binary; a head that doesn't parse or verify is never overwritten. A work tree
   without `head.json` counts as an empty log only when neither the upstream nor
   the last commit holds one.
4. **Extends the head** — a release's first target appends its row, later
   targets join it (several targets are several publishes, each its own head
   and commit). The signing key joins the head's key history if new; `seq`
   rises by one.
5. **Signs and checks** the new head against the previous one with the
   append-only rules, before writing anything.
6. **On a log with no head yet**, lists release storage (the self stream and
   every first-party tool stream) and refuses if it holds a manifest for any
   other release (**A first head is complete**, below).
7. **Writes and pushes** `head.json` and, for the self artifact,
   `latest/fuz-<target>.sha512`; commits what changed as
   `log: <name> <version> <target> seq <seq>` (`log: latest <name> …` when only
   the pointer moved) under your git identity; and pushes with a plain
   `git push`. Where that push goes — other branches under
   `push.default=matching`, a forcing `+` refspec — is the clone's git
   configuration, which publish doesn't override.
8. **Reads back** the commit the remote-tracking ref names after the push: its
   `head.json` must verify and record this release, and its `latest/` pointer
   must name it. Publish succeeds only then.

**The signing key must be trusted by the publishing binary** (its build's
`crates/fuz_crypto/src/public_keys.json`) — the existing, new, and read-back
heads are all verified against it, and an untrusted key is refused before any
upload, even when the release is already logged.

**Checked before anything is uploaded.** Steps 1–6 run first and write nothing
but the fast-forward, so a log that can't take the release — missing, dirty, or
diverged clone; a push configured to go elsewhere; an unverifiable head; the
version logged with different bytes; a revoked release; an untrusted key; no
head while storage holds other releases — leaves storage untouched. One gap: a
log with no pushed head has no remote-tracking ref to compare the push
configuration against, so a first push that goes elsewhere is caught only after
the upload. The checks run again when the release is recorded.

**Ordering.** The release is recorded after its tarball and manifest are
uploaded and confirmed present (an existence check), and before anything
advertises them. If recording fails at any step, the push included, publish
fails with the latest pointer and `fuz-latest-<target>` unmoved; the versioned files
stay in storage.

**A first head is complete.** A reader treats a release the head doesn't list as
a failure, so a log must list every release from its first head on. A publish
into a log with no head is therefore allowed only when storage holds nothing
but the release being published; otherwise it fails before uploading, names the
manifest keys it found, and points at the backfill:

```bash
cargo xtask release-log backfill --storage /path --log-repo /path/to/release-log --wetrun
```

So: **backfill, then the first `publish … --log-repo`**, whenever storage
already has releases. Into empty storage, the first publish creates the log, and
re-running it after a failed log write is fine — its own uploaded manifest
doesn't count against it. The check reads storage keys only (the backfill
verifies manifests), a failed listing is a refusal, and a log with a head is
never held to storage.

**A logged target never changes.** Publishing the same build again changes
nothing. Different bytes under a logged version and target fail before upload —
a different build is a new version. A revoked release takes no further targets.

`git` runs with no timeout (a push may wait on an ssh passphrase or hardware
key). Git's terminal credential prompt is off, so a remote that asks for a
username or password fails the push — use a credential helper or ssh. Ctrl-C is
recoverable at every step (§ Recovering a Log Write). The signing key never
enters the clone: only `head.json` and `latest/*.sha512` are written or staged.

## Creating a Log From Existing Releases

`release-log backfill` writes a log's complete first head from what storage
already holds:

```bash
cargo xtask release-log backfill --storage /path --log-repo /path/to/release-log            # review
cargo xtask release-log backfill --storage /path --log-repo /path/to/release-log --wetrun   # write, commit, push
```

`--key-file` and `-q` work as on `publish`. Storage is only read, and must
exist (a local `--storage` that isn't a directory is refused).

- **It only creates a log** — a clone whose upstream has a `head.json` is
  refused, verified or not. Later releases are recorded by
  `publish … --log-repo`.
- **Don't publish while it runs** — a release uploaded after its stream is read
  isn't in the first head.
- **Dry run by default** — without `--wetrun` it runs every read and check and
  prints each row with its `published_at` and targets, the `latest/` pointers,
  the `head.json` size against its limit, and the commit subject, writing
  nothing beyond the fast-forward. The real run reads storage again.

What it checks:

1. The clone, as a publish does (steps 1–2 above); a trusted signing key; and
   that the last commit tracks nothing under `latest/` but pointers the
   backfill itself writes.
2. Every manifest of the self stream and each first-party tool stream: within
   the size limit, parses, verifies against the trusted keys, is the manifest
   its storage key names, and has a `signed_at` that isn't in the future.
3. Each manifest's tarball, downloaded and held to its pinned BLAKE3.
4. For the self artifact, the flat binary `fuz-<version>-<target>` (its pinned
   BLAKE3) and any `.sha512` sidecar beside it (the line a publish writes). A
   sidecar with no binary is an error.
5. Each stream's `latest-<target>.json` pointers: each parses and names a
   version with a verified manifest for its target.
6. What the self stream advertises: for every target with a pointer, the
   version it names has a flat binary for the target, and
   `fuz-latest-<target>` is byte-for-byte that binary (by SHA-512), with an
   agreeing sidecar if any. A `fuz-latest-<target>` without a
   `latest-<target>.json` is an error — `install.sh` downloads it without
   knowing its version.

Any failure fails the whole backfill, listing every storage key at fault —
nothing is skipped, since a release storage serves but the log omits is the gap
the log exists to show. Fix or remove what's listed (`cargo xtask prune` for
releases past retention, by hand otherwise) and rerun. Empty storage is an
error too; that log is created by its first `publish … --log-repo`.

**A self release without its flat binary needs `--allow-missing-flat`**, which
logs it without a `sha512` — permanently, since a logged target never changes.
Without the flag the backfill (dry run included) fails listing the missing
binaries. The flag never covers a version a latest pointer names.

It writes one commit, `log: backfill <rows> releases seq 1`:

- `head.json` at `seq` 1 — one `ok` row per release with every target (the
  manifest's `content_hash` and `binaries`, plus the self flat binary's
  `sha512`), ordered by `published_at`, name, then version, so the same storage,
  key, and time give the same bytes. The key history holds the signing key.
- `latest/fuz-<target>.sha512` for each target checked in step 6.

Then it pushes and reads back, as a publish does.

**Review `published_at`** in the dry run. A row's date is the earliest
`signed_at` among its manifests — a field outside the manifest signature,
whatever the manifest's writer put there — and it never changes once pushed.

Only the named streams are read: a `tools/` directory that isn't a first-party
tool isn't walked, and a file in a walked stream no release accounts for is
listed, not logged. Storage keys print escaped, one per line.

**Recreating a log** (no head in its history is one this build can extend, e.g.
an unreadable signature format): republish or prune every release in storage,
commit and push the removal of `head.json` and `latest/`, run the backfill, then
revoke again each release the old log revoked — the backfill records every row
`ok`.

## Revoking a Release

A client checking the log refuses a revoked release, and no flag overrides it.

```bash
cargo xtask release-log revoke fuz 0.3.0 --log-repo /path/to/release-log            # review
cargo xtask release-log revoke fuz 0.3.0 --log-repo /path/to/release-log --wetrun   # write, commit, push
```

The name is the row's (`fuz`, or the tool name). `--key-file` and `-q` work as
on `publish`; there is no `--storage`. The dry run prints the release and its
targets, the `seq` it would sign, each `latest/` pointer before and after, and
the commit subject, writing nothing beyond the fast-forward.

What it does:

1. Checks the clone as a publish does and verifies the head. No head, or no row
   for the release, is an error; the key must be trusted.
2. Marks the whole row `revoked` (every target), adds the key to the history if
   new, raises `seq`, signs, and checks against the old head before writing.
   Revocation is permanent, and the head records no time or reason.
3. Settles `latest/`, reading only the release's own pointers
   (`latest/<name>-<target>.sha512` per target). Each must be a tracked plain
   file holding a pointer line (a symlink or executable is refused). A pointer
   naming the revoked version moves to the newest non-revoked release of that
   name with a `sha512` for the target — by semver, pre-releases included — or
   is removed when there is none. Other pointers are left alone.
4. Commits as `log: revoke <name> <version> seq <seq>`, pushes, and reads back:
   the row revoked, moved pointers as written, removed ones absent.

**Storage is untouched.** `latest-<target>.json` and `fuz-latest-<target>` keep naming
the revoked version. A client with the log check refuses it, and `install.sh`
with `FUZ_RELEASE_LOG_URL` follows the moved pointer (or refuses a removed one);
without the variable, neither sees the revocation. Publishing a fixed release
moves both. Revoke can't see storage, so it can't tell whether the release a
pointer moves to still has its flat binary (`cargo xtask prune` removes it):
check the dry run's before → after lines against storage first, or publish a
fixed release instead.

**Rerunning is safe.** An already-revoked release signs no new head; the run
still repairs a pointer naming it
(`log: latest revoke <name> <version> seq <seq>`), pushes a commit an earlier
run left unpushed, and reads back. With nothing to do it says so and exits 0.

## Recovering a Log Write

Publish, backfill, and revoke write the log the same way — commit, plain
`git push`, read back — and fail the same ways. Most failures leave the clone
ready for the same command again.

- **Commit fails** (no usable signing key for git, a refusing hook) — rolled
  back to the last commit; fix the cause and rerun.
- **Push fails** — the commit stays unpushed. Rerunning a publish or revoke
  signs nothing, pushes it, and reads back (a publish then moves its latest pointer);
  the push runs every time, so a remote with several push URLs gets completed.
  A backfill can't rerun (the log now has a head): `git push` by hand, or let
  the next `publish … --log-repo` push it.
- **Remote moved** — the next run reports the clone diverged:
  `git reset --hard @{upstream}` and rerun.
- **Dirty clone** (an interrupted run, or a rollback that couldn't finish) —
  inspect with `git status`, discard, rerun:

  ```bash
  git reset -q -- head.json latest     # unstage
  git checkout -- head.json            # restore tracked files; "did not match"
  git checkout -- latest               #   means the last commit has none
  git clean -fd -- head.json latest    # remove what the last commit lacks
  ```
- **Read-back couldn't read** the pushed commit — whether the log holds the
  change is unknown; rerun (a backfill then reports a log with a head; the next
  `publish … --log-repo` verifies it).
- **Read-back found something else** after a successful push — a hook rewrote a
  file, or the index was told to assume one unchanged; for a publish,
  the latest pointer hasn't moved. The commit is public: remove the cause and discard
  uncommitted changes. If the pushed `head.json` doesn't verify (and always
  after a backfill), restore it with `git revert --no-edit HEAD` — never rewrite
  pushed history — push, and rerun.
- **"No head.json in its work tree"** — a local unpushed commit removed it
  (`git reset --hard @{upstream}`), or it's only missing from the work tree
  (clear any assume-unchanged / skip-worktree flag, `git checkout -- head.json`).
- **"Not a latest pointer" / "not a plain file"** (revoke) — only the revoked
  release's own pointers, reported before anything is written. Restore the file
  to a pointer line or remove it, commit, push, and rerun.

## Co-signing

A **co-signer** fetches the release log head on a schedule and publishes, in a
fork of the log it serves as one more origin, which head it saw, signed with its
own ed25519 SSH key used for nothing else
(`ssh-keygen -Y sign -n fuz_release_log`). What `fuz`
checks: ./release_log_check.md § Co-signatures; the `witness` file format:
./release_format.md § Release Log Files. Its origin must:

- serve `witness` and the `head.json` it names from one commit;
- serve that `head.json` byte for byte as hashed (a `.gitattributes` with
  `* -text` keeps git from rewriting line endings);
- spell the statement line exactly as specified, the signature over that line,
  newline included;
- never sign a second document at a `seq` it already signed, or a lower `seq`.
