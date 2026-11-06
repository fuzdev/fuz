#!/bin/sh
# fuzi performance harness — repeatable, interleaved, A/B-capable.
#
# Times the phases of a real install on a real lockfile, and (given two
# binaries) interleaves them so a change can be scored against its baseline on
# a machine that is not perfectly idle.
#
# Method — why it looks like this:
#   - **Minimum of N**, not mean. Wall-clock noise is one-sided (contention only
#     ever makes a run slower), so the minimum is the best estimator of the work
#     actually done and is far more robust to background load than an average.
#   - **Interleaved** A/B. Running all of A then all of B scores a thermal or
#     load drift as a code change. Alternating within each round cancels it.
#   - **Real tree, real cache.** Defaults to gro's lockfile, a real-world tree
#     large enough that phase timings are stable.
#   - **Isolated FUZ_HOME and npm cache.** The cache is seeded once and reused
#     for every scenario, so runs never touch the developer's `~/.fuz` (or, with
#     `--npm`, `~/.npm`) and the warm-cache scenarios really are warm. A failed
#     seed stops the bench.
#   - **`TMPDIR` picks the filesystem measured.** The work dir (cache + tree) is
#     `mktemp -d`, so it lands under `$TMPDIR`, else `/tmp` — a tmpfs on many
#     hosts, which times RAM rather than a disk. Set `TMPDIR` to a directory on
#     the disk you mean to measure; the header prints the filesystem type.
#   - **Failures are not samples.** Any timed run that exits non-zero stops the
#     bench with its stderr — a fast failure would otherwise win the minimum.
#
# Usage:
#   scripts/fuzi-bench.sh                          # baseline only, default tree
#   scripts/fuzi-bench.sh --compare path/to/other-fuzi   # A/B against a second binary
#   scripts/fuzi-bench.sh --project path/to/project --runs 15
#   scripts/fuzi-bench.sh --npm                    # also time `npm ci` for scale
#
# Flags:
#   --project DIR   project supplying package.json + package-lock.json (default: ../gro beside this repo)
#   --fuzi PATH     binary under test (default: target/release/fuzi, built if absent)
#   --compare PATH  second binary; every scenario is run A/B interleaved
#   --runs N        rounds per scenario (default 10)
#   --npm           add an `npm ci` warm-cache comparison (needs npm)
#   --keep          keep the scratch dir (cache + tree) for a follow-up run
#
# Needs: cargo (unless --fuzi points at a prebuilt binary), network for the one
# cold seeding fetch. Everything after that is offline.
set -eu

REPO="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PROJECT="$(dirname -- "$REPO")/gro"
FUZI=""
COMPARE=""
RUNS=10
WITH_NPM=0
KEEP=0

while [ $# -gt 0 ]; do
	case "$1" in
		--project) PROJECT="$2"; shift 2 ;;
		--fuzi) FUZI="$2"; shift 2 ;;
		--compare) COMPARE="$2"; shift 2 ;;
		--runs) RUNS="$2"; shift 2 ;;
		--npm) WITH_NPM=1; shift ;;
		--keep) KEEP=1; shift ;;
		-h|--help) sed -n '2,/^[^#]/s/^# \{0,1\}//p' "$0"; exit 0 ;;
		*) echo "unknown flag: $1" >&2; exit 64 ;;
	esac
done

if [ -z "$FUZI" ]; then
	FUZI="$REPO/target/release/fuzi"
	[ -x "$FUZI" ] || cargo build --release --locked -p fuzi --manifest-path "$REPO/Cargo.toml"
fi
for bin in "$FUZI" ${COMPARE:+"$COMPARE"}; do
	[ -x "$bin" ] || { echo "not executable: $bin" >&2; exit 66; }
done
[ -f "$PROJECT/package-lock.json" ] || {
	echo "no package-lock.json in $PROJECT (pass --project)" >&2; exit 66; }

WORK="$(mktemp -d)"
[ "$KEEP" -eq 1 ] || trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/tree"
export FUZ_HOME="$WORK/fuzhome"
export npm_config_cache="$WORK/npm_cache"
mkdir -p "$TREE" "$FUZ_HOME"
cp "$PROJECT/package.json" "$PROJECT/package-lock.json" "$TREE/"

# Milliseconds of wall clock for one command run, output discarded. A run that
# exits non-zero is not a sample: it says so on stderr (with the tail of the
# command's own stderr) and returns 1 — a fast failure must never win a
# min-of-N.
time_ms() {
	_s=$(date +%s%N)
	_rc=0
	"$@" >/dev/null 2>"$WORK/last.err" || _rc=$?
	_e=$(date +%s%N)
	if [ "$_rc" -ne 0 ]; then
		printf 'FAILED (exit %s): %s\n' "$_rc" "$*" >&2
		tail -5 "$WORK/last.err" | sed 's/^/    /' >&2
		return 1
	fi
	echo $(( (_e - _s) / 1000000 ))
}

# Interleaved min-of-RUNS for one scenario: `bench <label> -- <argv...>`, where
# the argv's first word is the literal `FUZI` placeholder each binary substitutes.
bench() {
	_label="$1"; shift; shift  # drop the `--`
	_best_a=99999999
	_best_b=99999999
	_round=1
	while [ "$_round" -le "$RUNS" ]; do
		_ms=$(time_ms "$FUZI" "$@") || { echo "scenario failed: $_label" >&2; exit 1; }
		[ "$_ms" -lt "$_best_a" ] && _best_a=$_ms
		if [ -n "$COMPARE" ]; then
			_ms=$(time_ms "$COMPARE" "$@") || { echo "scenario failed (compare): $_label" >&2; exit 1; }
			[ "$_ms" -lt "$_best_b" ] && _best_b=$_ms
		fi
		_round=$((_round + 1))
	done
	if [ -n "$COMPARE" ]; then
		_delta=$(( _best_b - _best_a ))
		_pct=$(( _delta * 100 / _best_a ))
		printf '  %-34s %6s ms   compare %6s ms   %+d ms (%+d%%)\n' \
			"$_label" "$_best_a" "$_best_b" "$_delta" "$_pct"
	else
		printf '  %-34s %6s ms\n' "$_label" "$_best_a"
	fi
}

cd "$TREE"

printf '\n=== fuzi bench ===\n'
printf 'project : %s\n' "$PROJECT"
printf 'fuzi    : %s\n' "$FUZI"
[ -n "$COMPARE" ] && printf 'compare : %s\n' "$COMPARE"
printf 'runs    : %s (reporting the MINIMUM; interleaved when comparing)\n' "$RUNS"
printf 'load    : %s\n' "$(uptime | sed 's/.*load average/load average/')"
printf 'cores   : %s\n' "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"
printf 'work fs : %s (%s; TMPDIR picks it)\n' "$(stat -f -c %T "$WORK" 2>/dev/null || echo '?')" "$WORK"

# --- seed: one cold, networked install populates the isolated CAS ------------
printf '\nseeding the isolated cache (one cold networked install)...\n'
cold_ms=$(time_ms "$FUZI" install --quiet) || {
	echo "the cold seeding install failed; the warm scenarios would time an empty cache" >&2
	exit 1
}
tarballs=$(find "$FUZ_HOME/cache/npm" -name package.tgz 2>/dev/null | wc -l | tr -d ' ')
[ -d "$TREE/node_modules" ] || { echo "the seeding install left no node_modules" >&2; exit 1; }
cache_bytes=$(du -sb "$FUZ_HOME/cache/npm" 2>/dev/null | cut -f1)
tree_bytes=$(du -sb "$TREE/node_modules" 2>/dev/null | cut -f1)
printf '  cold install (network-bound, single sample)   %6s ms\n' "$cold_ms"
printf '  fetch set: %s tarballs, %s MiB compressed → %s MiB extracted\n' \
	"$tarballs" "$((cache_bytes / 1048576))" "$((tree_bytes / 1048576))"

# --- scenarios ---------------------------------------------------------------
# Each line adds phases to the plan; dry-run and verify each add a different
# one, so neither is reliably the cheaper of the two:
#   dry-run          = read + classify + plan + a serial re-hash of every cached tarball
#   verify           = plan + a structural walk of node_modules
#   warm install     = plan + fetch-phase re-verify + full materialize
printf '\nscenarios (min of %s):\n' "$RUNS"
bench "dry-run (plan + cache re-hash)" -- install --dry-run --quiet
bench "verify (structural walk)"       -- verify
bench "warm install (offline, full)"   -- install --offline --quiet
bench "clean (staging sweep)"          -- clean

if [ "$WITH_NPM" -eq 1 ] && command -v npm >/dev/null 2>&1; then
	printf '\nnpm ci (warm npm cache, same lockfile) — scale reference only:\n'
	npm ci --prefix "$TREE" >/dev/null 2>&1 || true   # warm npm's own cache first
	best=99999999
	i=1
	while [ "$i" -le 3 ]; do
		rm -rf "$TREE/node_modules"
		ms=$(time_ms npm ci --prefix "$TREE" --no-audit --no-fund) || {
			echo "scenario failed: npm ci" >&2; exit 1; }
		[ "$ms" -lt "$best" ] && best=$ms
		i=$((i + 1))
	done
	printf '  %-34s %6s ms\n' "npm ci" "$best"
	"$FUZI" install --offline --quiet >/dev/null 2>&1 || true  # restore a fuzi tree
fi

printf '\nnotes:\n'
printf '  - the minimum is reported: wall-clock noise is one-sided, so it is the\n'
printf '    most robust estimator of the work actually done under background load.\n'
printf '  - the cold number is ONE network-bound sample; do not rank on it.\n'
[ "$KEEP" -eq 1 ] && printf '  - scratch kept at %s\n' "$WORK"
printf '\n'
