# fuzi empirical gate

The go/no-go acceptance gate for `fuzi` (the lockfile-driven npm installer).
It proves the load-bearing premise — **a script-skipped `fuzi install` produces
a working JS toolchain** — on real, committed lockfile fixtures, across both
libc flavors.

## Run

```sh
scripts/fuzi-gate.sh              # both libcs (glibc on host, musl in docker)
scripts/fuzi-gate.sh --glibc-only # host only — needs cargo + node + npm
scripts/fuzi-gate.sh --musl-only  # alpine container — needs docker only
```

The musl pass builds `fuzi` musl-natively via [`Dockerfile.musl`](Dockerfile.musl)
(a `rust:<version>-alpine` image at the `rust-toolchain.toml` pin), so the **host needs no
musl toolchain**. The build context is the repo root less the excludes in
[`Dockerfile.musl.dockerignore`](Dockerfile.musl.dockerignore), so any change
in it reruns the `cargo build` layer; BuildKit
cache mounts keep the crate registry + target across builds, which keeps that
rerun incremental. The gate logic + fixtures are mounted at run time, so the
container runs the checkout's own. Both passes run the identical logic in
[`inner.sh`](inner.sh), each with a fresh `FUZ_HOME` and npm cache under its
scratch dir: a run never touches `~/.fuz` or `~/.npm`, and fetches cold.

**CI**: the glibc leg runs on pushes to `main` and on pull requests as the
`fuzi-gate` job in
`.github/workflows/check.yml` (the runner's preinstalled node + npm suffice).
The musl leg stays manual — it needs docker plus a cold in-container cargo
build each CI run, so run `scripts/fuzi-gate.sh --musl-only` locally when
touching platform selection, extraction, or the fetch path.

**Without docker**: `inner.sh` runs on any Alpine host with node and npm.
Build `fuzi` there with a musl toolchain, copy this directory over, and run
`inner.sh` with `FUZI` set to the binary (plus `FUZI_GATE_STRICT=1`) and
`TMPDIR` on disk.

## What it asserts (per fixture, both libcs)

1. A real `fuzi install` succeeds with install scripts skipped.
2. `esbuild` is reported as a skipped install script.
3. `.bin/vite` and `.bin/esbuild` shims exist and are executable.
4. **The load-bearing test**: `esbuild.transform` works with its postinstall
   skipped (it resolves `@esbuild/<host>` at runtime) — see
   [`check-esbuild.mjs`](check-esbuild.mjs).
5. A real `vite build` succeeds (native **rollup** *and* **rolldown** bundlers).
6. `fuzi verify` passes (structural, cache-independent).
7. **A real SIGINT**: an `--offline` reinstall is interrupted mid-staging
   ([`check-sigint.mjs`](check-sigint.mjs), which spawns fuzi from node — a
   shell's `&` job starts with SIGINT ignored, and fuzi honors an inherited
   ignore). The checker duty-cycles fuzi under SIGSTOP / SIGCONT and sends the
   SIGINT only on a staging tree seen while every thread is stopped, so it
   arrives at most one quantum after staging began, however fast the box; it
   exits 130, leaves no `.fuzi-installing-*`,
   prints the drain's removal line (the evidence it caught the tree — an
   attempt without it lost the race and is retried), and the tree from step 1
   still verifies. Run human (no `error:` line after the drain) and `--json`
   (stdout empty or one complete document, never a cut one), each needing three
   such passes — a race-prone regression passes one attempt often.
8. **Superset cross-check**: a parallel `npm ci` from the same lockfile, then
   `fuzi`'s installed package set must be a SUPERSET of npm's host-pruned set —
   never a subset (a subset would mean a host-needed package was skipped) — the
   two trees must hold the same symlinks outside `.bin` (the package-set
   listing does not follow links, so this is what sees a link), and the same
   `.bin` entries with the same link texts.

The npm cross-checks (step 8 here, step 5 of the link fixture below) are skipped
with a note when `npm ci` itself fails — and fail the gate instead under
`FUZI_GATE_STRICT=1`, which CI sets.

And for the [`link-sibling/`](link-sibling) fixture (sibling `link: true`
packages):

1. `fuzi install` links both siblings, and an ESM import resolves through the
   link (`check-link.mjs`).
2. The linked package's `.bin` shim runs.
3. `fuzi verify` passes.
4. **Tamper**: `fuzi verify` exits 65 (its data-error class) on a tree edited
   after the install — a package link re-pointed, the linked package's `.bin`
   shim re-pointed, `node_modules` itself replaced by a symlink to the real
   tree. Each edit leaves the tree working (the new link resolves to the same
   file), so only verify can tell; each is undone before the next, the
   restored tree verifies again, and a reinstall over it succeeds.
5. Every symlink — package links and `.bin` — and its text match `npm ci
   --ignore-scripts`, with and without `--omit=dev` (the dev link drops; its
   flags live on the target entry), and fuzi ⊇ npm on packages.
6. The link targets' listing (path, mode, size, mtime, type) is unchanged
   across install, the tamper checks, reinstall, `fuzi clean`, and the
   `--omit dev` install — fuzi never writes into a link target.

The `.bin` parity in step 5 holds because the fixture's linked bin is an
executable regular file reached through real directories — the only kind fuzi
links (npm links any declared bin; fuzi skips the rest by design).

It also reports the longest extracted intra-package path. Real npm trees stay
well under tar's 100-char ustar name field, so GNU/pax long-name (`L`) framing
is exercised by a deterministic unit test instead (`fuz_archive`'s
`gnu_long_name_path_extracts`).

## Fixtures

Small committed vite projects, each pinning `esbuild` directly so the
load-bearing esbuild path is exercised regardless of the bundler, and a link
project:

- [`vite-rollup/`](vite-rollup) — vite 7 (rollup-based). Exercises the
  `@rollup/rollup-<platform>` + `@esbuild/<host>` prebuilt matrices.
- [`vite-rolldown/`](vite-rolldown) — vite 8 (rolldown-based). Exercises the
  `@rolldown/binding-<platform>` native `.node` addon (detect-libc selection).
- [`link-sibling/`](link-sibling) — `app/` depends on sibling directories
  through `file:../…` specs (npm records them as `link: true`): a prod link
  (`localpkg-a`, imported as ESM) and a dev link with an executable bin
  (`localpkg-b`), beside one small registry dep. Copied into the scratch dir
  with its layout intact, since a link's text is relative to it. Its lockfile
  lives at `link-sibling/app/package-lock.json`.

Each fixture's `package-lock.json` is committed (generated once with
`npm install --package-lock-only`); `fuzi` installs exactly from it. Regenerate
with npm — `fuzi` has no resolver.
