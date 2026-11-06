#!/bin/sh
# fuzi empirical go/no-go gate.
#
# Builds a real `node_modules` from committed lockfile fixtures with a real
# (script-skipped) `fuzi install`, then asserts the load-bearing JS toolchain
# works (the assertions: scripts/fuzi-gate/README.md § What it asserts (per
# fixture, both libcs)). Runs the SAME logic (scripts/fuzi-gate/inner.sh) on
# the glibc host and inside an alpine (musl) container — libc selection is the
# riskiest axis, so both are gated.
#
# Usage:  scripts/fuzi-gate.sh [--glibc-only | --musl-only]
# Env:    FUZI_GATE_STRICT=1 — a skipped npm cross-check (npm ci failed) FAILS
#         the gate instead of printing a note (CI sets it).
# Needs:  glibc pass — cargo + node + npm on the host.
#         musl pass  — docker (builds fuzi musl-natively in
#                      rust:<pin>-alpine, kept equal to rust-toolchain.toml).
set -u

REPO="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
GATE_DIR="$REPO/scripts/fuzi-gate"
INNER="$GATE_DIR/inner.sh"
do_glibc=1
do_musl=1

for arg in "$@"; do
	case "$arg" in
		--glibc-only) do_musl=0 ;;
		--musl-only) do_glibc=0 ;;
		-h|--help) sed -n '2,/^[^#]/s/^# \{0,1\}//p' "$0"; exit 0 ;;
		*) echo "unknown flag: $arg" >&2; exit 64 ;;
	esac
done

glibc_rc=0
musl_rc=0

if [ "$do_glibc" -eq 1 ]; then
	echo "### glibc pass (host) — building fuzi..."
	cargo build --release --locked -p fuzi --manifest-path "$REPO/Cargo.toml" || exit 70
	FUZI="$REPO/target/release/fuzi" GATE_DIR="$GATE_DIR" LIBC=glibc sh "$INNER" || glibc_rc=$?
fi

if [ "$do_musl" -eq 1 ]; then
	echo
	echo "### musl pass — building the musl fuzi image (BuildKit-cached)..."
	# Dockerfile.musl builds a musl-native fuzi + node/npm; layer + cache-mount
	# caching make reruns incremental. The gate logic / fixtures are mounted at
	# run time, so editing them never rebuilds the image.
	if docker build -f "$GATE_DIR/Dockerfile.musl" -t fuzi-gate-musl:latest "$REPO"; then
		docker run --rm \
			-v "$GATE_DIR:/gate:ro" \
			-e FUZI=/usr/local/bin/fuzi \
			-e GATE_DIR=/gate \
			-e LIBC=musl \
			-e FUZI_GATE_STRICT="${FUZI_GATE_STRICT:-0}" \
			fuzi-gate-musl:latest \
			sh /gate/inner.sh || musl_rc=$?
	else
		musl_rc=$?
	fi
fi

echo
echo "================ fuzi gate summary ================"
[ "$do_glibc" -eq 1 ] && { [ "$glibc_rc" -eq 0 ] && echo "  glibc: PASS" || echo "  glibc: FAIL (rc=$glibc_rc)"; }
[ "$do_musl" -eq 1 ]  && { [ "$musl_rc" -eq 0 ]  && echo "  musl:  PASS" || echo "  musl:  FAIL (rc=$musl_rc)"; }
echo "======================================================"
[ "$glibc_rc" -eq 0 ] && [ "$musl_rc" -eq 0 ]
