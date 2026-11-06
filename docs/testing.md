# Testing

How the workspace is tested: the CI jobs, the real-Postgres suites, the
cross-backend suite, and the known flakes. CI's reasons per job are the
comments at the top of `.github/workflows/check.yml`.

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
- `db-tests` — the `#[ignore]` real-Postgres suites against a `postgres:18`
  service (§ Postgres suites).
- `fuzi-gate` — `FUZI_GATE_STRICT=1 scripts/fuzi-gate.sh --glibc-only` (set
  the strict flag locally to match CI); the musl leg is manual
  (`scripts/fuzi-gate/README.md`).
- `install-test` — `scripts/install-test.sh` and its mutation gate
  `scripts/install-test-mutants.sh` (`scripts/install-test/README.md`).

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

A local Postgres is the expected path for the `#[ignore]` suites — write and
verify them locally, don't defer to CI. Point each crate's `*_TEST_URL` at a
local server, `createdb` the databases once, then run with
`--ignored --test-threads=1` (required — each crate's suite shares one
database it resets per test, most by wiping its `public` schema through
`fuz_testing::fresh_test_db_pool`, and `fuz_db`'s snapshot test reads the
whole schema, so a suite's tests must not run concurrently):

```bash
export FUZ_DB_TEST_URL=postgres://<user>@localhost:5432/fuz_db_test
export FUZ_AUTH_TEST_URL=postgres://<user>@localhost:5432/fuz_auth_test
export FUZ_CELL_TEST_URL=postgres://<user>@localhost:5432/fuz_cell_test
export FUZ_FACT_TEST_URL=postgres://<user>@localhost:5432/fuz_fact_test
export FUZ_FACT_SERVING_TEST_URL=postgres://<user>@localhost:5432/fuz_fact_serving_test
export FUZ_ACTIONS_TEST_URL=postgres://<user>@localhost:5432/fuz_actions_test
export FUZ_DB_ADMIN_TEST_URL=postgres://<user>@localhost:5432/fuz_db_admin_test
export FUZ_REALTIME_TEST_URL=postgres://<user>@localhost:5432/fuz_realtime_test
export FUZ_CELL_ACTIONS_TEST_URL=postgres://<user>@localhost:5432/fuz_cell_actions_test
for db in fuz_db_test fuz_auth_test fuz_cell_test fuz_fact_test fuz_fact_serving_test fuz_actions_test fuz_db_admin_test fuz_realtime_test fuz_cell_actions_test; do createdb $db; done   # one-time
cargo test -p fuz_db -p fuz_http -p fuz_auth -p fuz_cell -p fuz_fact -p fuz_fact_serving -p fuz_actions -p fuz_db_admin -p fuz_realtime -p fuz_cell_actions -- --ignored --test-threads=1
```

**A crate that gains an `#[ignore]` Postgres suite** joins both the recipe
above and the `db-tests` job in `check.yml` — env var, database, and `-p`
entry in each. Nothing checks either list against the tree, and the `-p` entry
is the silent one: a crate missing from it leaves the job green while its suite
never runs. A missing database panics at the suite's first connect.

Each suite's purpose is in its file's `//!` doc. Schema handling:

- Most suites drop and recreate their schema through
  `fuz_testing::fresh_test_db_pool`: a new suite declares a `TestingDbOptions`
  const (env var, default DB, migration chains, optional scratch DDL) and
  delegates. `fuz_auth`'s `tests/common/` (seeding over `fuz_testing::seed`) and
  `tests/signup.rs` are the template for a new per-handler suite.
- `fuz_http`'s `ready` suite shares `FUZ_DB_TEST_URL` with `fuz_db`, so both
  scope themselves per table / per namespace and neither adopts
  `fresh_test_db_pool` — a `DROP SCHEMA` from either would destroy the other's
  rows mid-run.
- `fuz_db`'s status test needs a database with no `schema_version` tracker, so
  it creates and drops its own scratch database (`fuz_db_test_status_scratch`)
  — the test role needs `CREATEDB`, and a run that panics leaves that database
  for the next run to drop.

## Cross-backend suite

**A change to a spine crate that `testing_spine_stub` links also runs fuz_app's
cross-backend suite** — `npm run test:cross:rust-spine-stub` in a `fuz_app`
checkout. Its setup runs `cargo build -p testing_spine_stub --profile cross-test`
(the root `Cargo.toml`'s non-LTO test profile) in the
workspace `FUZ_RUST_SPINE_STUB_WORKSPACE_DIR` names (set it when this checkout
is not at the suite's default path), runs `createdb` against a local Postgres,
then spawns the binary and drives it over HTTP, WebSocket, and SSE.

It is the broad behavioral coverage of the cell verbs: `fuz_cell_actions`'s own
Postgres suite pins the authz gates (`tests/cell_authz.rs`'s `//!` lists them),
and its unit tests are pure — so `cargo test --workspace` and the Postgres
recipe can both be green with a cell handler broken.

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
