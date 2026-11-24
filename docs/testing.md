# Testing

How the workspace is tested: the CI jobs, the database tests on pglet and
PostgreSQL, the cross-backend suite, and the known flakes. CI's reasons per
job are the comments at the top of `.github/workflows/check.yml`.

## CI

`.github/workflows/check.yml` runs on pushes to `main`, pull requests against
any branch (a push to a feature branch with no PR open runs nothing), and
manual dispatch:

- `check` — the local gates, exactly:

  ```bash
  cargo fmt --all --check
  cargo clippy --locked --workspace --all-targets -- -D warnings
  cargo test --locked --workspace          # twice: runner umask, then umask 000
  cargo xtask check-release
  RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --all-features --document-private-items
  ```

  `--document-private-items` matters: rustdoc checks only the docs it renders,
  so without it private and `pub(crate)` doc comments go unchecked.
- `db-tests` — the PostgreSQL leg: every DB test again, the Postgres-only ones
  included, against a `postgres:18` service (§ Postgres suites).
- `fuzi-gate` — `FUZI_GATE_STRICT=1 scripts/fuzi-gate.sh --glibc-only` (set
  the strict flag locally to match CI); the musl leg is manual
  (`scripts/fuzi-gate/README.md`).
- `install-test` — `scripts/install-test.sh` and its mutation gate
  `scripts/install-test-mutants.sh` (`scripts/install-test/README.md`).

Every job that runs cargo checks this repo out into `fuz/` and fuzdev/pglet
beside it into `pglet/`: `fuz_testing` path-depends on pglet's server crate,
and Cargo loads it for any build in the workspace. `check.yml`'s `PGLET_REF`
is pglet's `main`, which `cross-contract.yml` repeats, so fuz and pglet move
together. `--locked` holds `Cargo.lock` to the pglet crates and their
dependencies, so a pglet change to either fails fuz's CI until fuz re-locks
(`cargo update -p pglet_server`): the accepted cost.
Locally, keep a `pglet` checkout beside this one.

`.github/workflows/cross-contract.yml` runs nightly and by manual dispatch,
never on a push: it checks out fuz_app's `main` beside this checkout, builds
`testing_spine_stub` with `--locked`, and runs fuz_app's
`test:cross:rust-spine-stub`, `test:cross:parity` and `test:cross:security`
against a `postgres:18` service (§ Cross-backend suite). A red run means fuz
or fuz_app `main` drifted from the other; a change spanning both repos lands
in fuz_app first.

`fuz_eval`'s `#[ignore]` real-fgro suites run in no CI job: they need an
`fgro` snapshot build, which CI has no way to get yet. Locally:
`FUZ_EVAL_TEST_FGRO=/abs/path/to/fgro cargo test -p fuz_eval --test real_fgro -- --ignored`
(with `--ignored` and no variable they fail). Its `uid_drop` suite, also
`#[ignore]`, checks the drop from root and runs as root, from a binary built as
yourself (the commands are in `crates/fuz_eval/tests/uid_drop.rs`); run
unprivileged, it fails. Its other suites run in `check` against
`testing_fake_fgro`.

The toolchain is pinned in `rust-toolchain.toml` (local `cargo` and CI both
read it), since `clippy::nursery` + `-D warnings` breaks on stable-channel
drift.

## Daemon tests

Tests that need a daemon spawn their own with an isolated `FUZ_HOME`,
independent of the developer's `~/.fuz/`.

## Postgres suites

Every DB test opens its database with `fuz_testing::fresh_test_db`, which
starts a pglet server of its own for the test, in-process on a loopback port,
runs the suite's migrations, and stops it when the returned `TestDb` drops. So
the DB tests run in plain `cargo test`, in parallel, with nothing to set up.

Set `FUZ_TEST_POSTGRES_URL` to a PostgreSQL server and a role with `CREATEDB`
and every DB test instead creates a database of its own there, named
`fuz_testing_<suite>_<pid>_<n>`, and drops it after. That's the PostgreSQL
leg, the `db-tests` job, and a local Postgres is the expected way to run it —
write and verify a change locally, don't defer to CI:

```bash
export FUZ_TEST_POSTGRES_URL=postgres://<user>@localhost:5432/postgres
cargo test -p fuz_db -p fuz_http -p fuz_auth -p fuz_cell -p fuz_fact -p fuz_fact_serving -p fuz_actions -p fuz_db_admin -p fuz_realtime -p fuz_cell_actions -p fuz_testing -- --include-ignored
```

A run killed before its tests' drops ran leaves their databases behind; drop
them by that name prefix.

**Postgres-only tests.** A test of what only PostgreSQL has (backends and
their cancellation, lock waits and `LOCK TABLE` stalls, triggers,
`ALTER DATABASE … SET`, a DST `SET TIME ZONE`) opens its database with
`TestEngine::Postgres` (`TestingDbOptions::postgres_only`) and carries
`#[ignore = "postgres-only: <why>"]`. One waiting on a pglet feature carries
`#[ignore = "pglet: <feature>"]` and the same engine, so it is found by
searching for the marker once pglet has the feature. Plain `cargo test`
reports them ignored; run with `--ignored` but without
`FUZ_TEST_POSTGRES_URL`, each fails naming the variable rather than passing
unrun.

**A crate that gains DB tests** joins both `-p` lists, the recipe above and
the `db-tests` job in `check.yml`. `xtask`'s `tests/db_suite_lists.rs`, in the
`check` job's `cargo test --workspace`, holds both lists to the tree in both
directions: a crate whose code names `fresh_test_db` (an aliased import
included), carries a marker, or lists `fuz_testing` under `[dev-dependencies]`
must be in each `-p` list and nothing else may be; each list sets
`FUZ_TEST_POSTGRES_URL` and no other connection variable; each `cargo test`
takes only `--locked` and `-p` before `--` and exactly `--include-ignored`
after it, with no shell comment or operator, as its step's whole `run:`; and
the job and its test step take no `if:`, `continue-on-error:`, or `shell:`. In
such a crate every `#[ignore` (and every `#[cfg_attr(…)]` holding an `ignore`)
is one of the two markers, and a crate with a marker names the Postgres engine
and the other way round. Its doc has the detection rule. `tests/pglet_pin.rs`
holds `cross-contract.yml`'s pglet checkout to `check.yml`'s `PGLET_REF`.

Each suite's purpose is in its file's `//!` doc. `fuz_auth`'s `tests/common/`
(seeding over `fuz_testing::seed`) and `tests/signup.rs` are the template for
a new per-handler suite.

`fuz_auth`'s `credential_mint_race` and `account_delete_races` play two
transactions against each other; only PostgreSQL shows a lock wait or a lock
order, so their racing tests are Postgres-only, and a change to a row lock, a
locking read or a `RETURNING` order runs the PostgreSQL leg.

## Cross-backend suite

**A change to a spine crate that `testing_spine_stub` links also runs fuz_app's
cross-backend suite** — `npm run test:cross:rust-spine-stub` in a `fuz_app`
checkout. Its setup runs
`cargo build -p testing_spine_stub --profile cross-test` (the root
`Cargo.toml`'s non-LTO test profile) in the workspace
`FUZ_RUST_SPINE_STUB_WORKSPACE_DIR` names (set it when this checkout is not at
the suite's default path), runs `createdb` against a local Postgres, then spawns
the binary and drives it over HTTP, WebSocket, and SSE.

It is the broad behavioral coverage of the cell verbs: `fuz_cell_actions`'s own
Postgres suite pins the authz gates (`tests/cell_authz.rs`'s `//!` lists them),
and its unit tests are pure — so `cargo test --workspace` and the Postgres
recipe can both be green with a cell handler broken.

`fuz_http`'s `request_header_conformance.json` and
`request_target_conformance.json`, `fuz_testing`'s
`credential_conformance.json`, and `fuz_fact_serving`'s
`tests/fixtures/x_accel_corpus.json` are byte-identical copies of fuz_app's
tables, run here by each module's unit test. `fuz_testing`'s `db_invariants.sql`
is a byte-identical copy too, generated in fuz_app and never edited here.
fuz_app's `conformance_table_copies` cross test, in the parity project, fails
when a copy differs, so a table row is edited in both repos; the nightly
`cross-contract` workflow runs it.

## Known flakes

- `fuz_pty`'s unit tests can fail under parallel workspace load (several read
  once after a fixed sleep) — rerun `cargo test -p fuz_pty` alone before
  believing one.
- `fuz_daemon`'s `await_lock_release_waits_for_the_holder_to_exit` and
  `fuzd_server`'s `run_with_deadline_*` wait on short deadlines and can miss
  them on a loaded machine. CI runs the workspace suite once per umask leg, so
  a run is exposed to each of these twice.
- Tests that create an artifact (`fuz`'s `self_cli` bootstrap tests among them)
  do so under the temp dir, so one with less free space than `fuz_artifact`'s
  `MIN_FREE_SPACE_BYTES` fails them with `not enough space to create artifact`.
- A `TMPDIR` long enough to overflow an `AF_UNIX` path fails
  `self_status_json_reports_fuzd_running_when_socket_listens`.

Not flakes, though they look timing-shaped:

- `fuz_archive`'s `a_pax_header_of_many_distinct_records_extracts` is a
  quadratic-regression canary: a pass is quick, and a run that takes minutes
  there has regressed, not flaked.
- `fuzi_core`'s FIFO tests (the `*_without_blocking` ones) pass in
  microseconds; their deadlines only bound how fast a regression (a
  blocking open) fails instead of hanging.

## The `umask 000` leg

`tempfile::tempdir()` honors the umask, so one leg alone would let the umask
decide whether the `~/.fuz` mode assertions mean anything. The `000` leg
guards:

- the `0700` pin on the test homes (the `fresh_home()` helpers) — without it a
  `tempdir()` home is refused as world-writable at `umask 000` and accepted at
  `022`;
- the ceiling half of `write_atomic_creates_with_mode`, since `umask 022`
  itself strips the group and other write bits a wrong mode would add.

A dropped mode is caught at both legs (that test's `SECURE_FILE_MODE` half and
the exact `0700` directory pins differ from an inherited mode at `022` and
`000` alike; they are vacuous only at `umask 077`). A new `~/.fuz`
subdirectory made with a bare `create_dir_all` fails at neither leg unless a
test pins its mode — `check_home_not_world_writable` inspects `~/.fuz` itself.
