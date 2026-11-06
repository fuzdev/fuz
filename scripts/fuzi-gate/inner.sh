#!/bin/sh
# fuzi empirical gate — libc-agnostic inner logic.
#
# Runs the same assertions on whatever host invokes it; the outer driver
# (scripts/fuzi-gate.sh) runs it once on the glibc host and once inside an
# alpine (musl) container, so the *identical* logic exercises both libcs.
#
# For each committed fixture, then the `link-sibling` fixture: the assertions
# listed in scripts/fuzi-gate/README.md § What it asserts (per fixture, both
# libcs).
# Fail-loud: any miss exits non-zero.
#
# Env in: FUZI (path to the fuzi binary), GATE_DIR (this dir), LIBC (label),
# FUZI_GATE_STRICT (optional; `1` turns a skipped npm cross-check into a FAIL).
set -eu

GATE_DIR="${GATE_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}"
FUZI="${FUZI:?set FUZI to the fuzi binary path}"
LIBC="${LIBC:-$(ls /lib/ld-musl-*.so.1 >/dev/null 2>&1 && echo musl || echo glibc)}"
FIXTURES="vite-rollup vite-rolldown"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# A fresh fuzi home and npm cache per run: the gate never reads or writes the
# developer's `~/.fuz` / `~/.npm`, and every run fetches cold, as in CI. The
# SIGINT step's `--offline` reinstalls read the cache step 1 seeded here.
export FUZ_HOME="$TMP/fuz_home"
export npm_config_cache="$TMP/npm_cache"
fails=0
note() { printf '    %s\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fails=$((fails + 1)); }
# A check that could not run (npm ci itself failed): a note by default, a FAIL
# under FUZI_GATE_STRICT=1 — CI sets it, so a broken npm can't pass the gate
# with its cross-checks silently skipped.
skip() {
	if [ "${FUZI_GATE_STRICT:-0}" = 1 ]; then fail "$* (FUZI_GATE_STRICT=1)"; else note "$*"; fi
}

# Set of placed package dirs (relative to a node_modules root), one per line, sorted.
package_set() {
	find "$1" -name package.json -type f 2>/dev/null |
		sed "s|^$1/||; s|/package.json\$||" |
		sort -u
}

# Symlinks under a node_modules root outside `.bin` (package links), relative to
# the root, one per line, sorted. `package_set` is blind to them (find without -L).
link_set() {
	find "$1" -type l ! -path '*/.bin/*' 2>/dev/null |
		sed "s|^$1/||" |
		sort
}

# Every `.bin` entry under a node_modules root (nested `.bin` dirs included)
# with its link text, relative to the root, sorted.
bin_texts() {
	find "$1" -path '*/.bin/*' -type l 2>/dev/null | sort | while IFS= read -r l; do
		printf '%s -> %s\n' "${l#"$1"/}" "$(readlink "$l")"
	done
}

# Every symlink under a node_modules root with its text (`.bin` included).
link_texts() {
	find "$1" -type l 2>/dev/null | sort | while IFS= read -r l; do
		printf '%s -> %s\n' "${l#"$1"/}" "$(readlink "$l")"
	done
}

# Listing of the link fixture's target dirs: path, mode, size, mtime, type. Must
# not change across install / reinstall / clean — fuzi never writes a link target.
target_listing() {
	( cd "$1" && find localpkg-a localpkg-b | sort | while IFS= read -r p; do
		stat -c '%n %a %s %Y %F' "$p"
	done )
}

# Longest intra-package file path (>100-char ones need GNU/pax tar framing).
longest_intra_path() {
	find "$1" -type f 2>/dev/null | awk '
		{ p = $0; sub(/^.*node_modules\//, "", p)
		  n = split(p, a, "/")
		  if (a[1] ~ /^@/) { s = 3 } else { s = 2 }
		  rel = ""; for (i = s; i <= n; i++) rel = rel (rel == "" ? "" : "/") a[i]
		  if (length(rel) > best) { best = length(rel); bestp = rel } }
		END { print best "\t" bestp }'
}

printf '\n=== fuzi gate · libc=%s · fuzi=%s ===\n' "$LIBC" "$FUZI"

for fx in $FIXTURES; do
	printf '\n--- fixture: %s ---\n' "$fx"
	src="$GATE_DIR/$fx"
	[ -f "$src/package-lock.json" ] || { fail "$fx: no committed package-lock.json"; continue; }

	work="$TMP/$fx"
	mkdir -p "$work"
	# copy only the committed inputs (never a stale node_modules)
	cp "$src/package.json" "$src/package-lock.json" "$work"/
	cp -r "$src/src" "$work"/src
	[ -f "$src/index.html" ] && cp "$src/index.html" "$work"/index.html
	cp "$GATE_DIR/check-esbuild.mjs" "$work"/check-esbuild.mjs
	cd "$work"

	# 1. real install (scripts skipped by construction)
	if out="$("$FUZI" install --json 2>install.err)"; then
		placed=$(printf '%s' "$out" | sed -n 's/.*"placed": *\([0-9]*\).*/\1/p')
		pass "$fx: fuzi install OK (${placed:-?} placed)"
	else
		fail "$fx: fuzi install failed (exit $?)"; cat install.err; continue
	fi
	# 2. skipped-script report names esbuild (from the install JSON above)
	if printf '%s' "$out" | grep -q '"esbuild"'; then
		pass "$fx: esbuild reported as a skipped install script"
	else
		fail "$fx: esbuild not reported in skipped scripts"
	fi
	# 3. .bin shims exist and resolve to an executable target
	for cmd in vite esbuild; do
		if [ -L "node_modules/.bin/$cmd" ] && [ -x "node_modules/.bin/$cmd" ]; then
			pass "$fx: .bin/$cmd present and executable"
		else
			fail "$fx: .bin/$cmd missing or not executable"
		fi
	done
	# 4. the load-bearing esbuild test (postinstall skipped, @esbuild/<host> placed)
	if node check-esbuild.mjs; then
		pass "$fx: esbuild.transform works with postinstall skipped"
	else
		fail "$fx: esbuild.transform FAILED"
	fi
	# 5. a real vite build (native rollup/rolldown bundler + .bin + esbuild transform)
	if node_modules/.bin/vite build >vite.log 2>&1 && ls dist/assets/*.js >/dev/null 2>&1; then
		pass "$fx: vite build OK ($(node_modules/.bin/vite --version 2>/dev/null | head -1))"
	else
		fail "$fx: vite build FAILED"; tail -15 vite.log
	fi
	# 6. fuzi verify (structural, cache-independent)
	if "$FUZI" verify >/dev/null 2>&1; then
		pass "$fx: fuzi verify OK"
	else
		fail "$fx: fuzi verify FAILED"
	fi
	# 7. a real SIGINT mid-materialization, human and --json: exit 130, the
	# drain's removal line, no staging tree left, no cut output, and the tree
	# from step 1 untouched (it still verifies)
	if node "$GATE_DIR/check-sigint.mjs" "$FUZI"; then
		pass "$fx: SIGINT mid-install exits 130, drained, no staging left"
	else
		fail "$fx: SIGINT mid-install"
	fi
	if "$FUZI" verify >/dev/null 2>&1; then
		pass "$fx: fuzi verify OK after the interrupted install"
	else
		fail "$fx: fuzi verify FAILED after the interrupted install"; "$FUZI" verify 2>&1 | tail -5
	fi
	# longest extracted intra-package path (long-name framing observability)
	lp="$(longest_intra_path node_modules)"
	note "$fx: longest intra-package path = $(printf '%s' "$lp" | cut -f1) chars ($(printf '%s' "$lp" | cut -f2))"

	# 8. superset cross-check: npm ci into a scratch tree, fuzi MUST be a superset
	npmdir="$TMP/$fx.npm"
	mkdir -p "$npmdir"
	cp package.json package-lock.json "$npmdir"/
	if ( cd "$npmdir" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 ); then
		package_set node_modules >fuzi.set
		package_set "$npmdir/node_modules" >npm.set
		missing="$(comm -23 npm.set fuzi.set)"
		nf=$(wc -l <fuzi.set); nn=$(wc -l <npm.set)
		if [ -z "$missing" ]; then
			pass "$fx: fuzi ⊇ npm (fuzi $nf ⊇ npm $nn packages, no subset gap)"
		else
			fail "$fx: fuzi MISSING packages npm placed:"; printf '%s\n' "$missing" | sed 's/^/        /'
		fi
		link_set node_modules >fuzi.links
		link_set "$npmdir/node_modules" >npm.links
		if cmp -s fuzi.links npm.links; then
			pass "$fx: package symlinks match npm ($(wc -l <fuzi.links) outside .bin)"
		else
			fail "$fx: package symlinks differ from npm:"; diff npm.links fuzi.links | sed 's/^/        /'
		fi
		bin_texts node_modules >fuzi.bins
		bin_texts "$npmdir/node_modules" >npm.bins
		if cmp -s fuzi.bins npm.bins; then
			pass "$fx: .bin names + link texts match npm ($(wc -l <fuzi.bins) entries)"
		else
			fail "$fx: .bin entries differ from npm:"; diff npm.bins fuzi.bins | sed 's/^/        /'
		fi
	else
		skip "$fx: npm ci unavailable/failed — skipping superset cross-check"
	fi
	cd "$GATE_DIR"
done

# --- the link-sibling fixture --------------------------------------------------
# Laid out as committed — `app/` beside its `localpkg-*` siblings — once for fuzi
# and once for npm, since a link's text is relative to that layout.
fx=link-sibling
printf '\n--- fixture: %s ---\n' "$fx"
src="$GATE_DIR/$fx"
fz="$TMP/$fx.fuzi"
np="$TMP/$fx.npm"
for root in "$fz" "$np"; do
	mkdir -p "$root/app"
	cp -Rp "$src/localpkg-a" "$src/localpkg-b" "$root"/
	cp "$src/app/package.json" "$src/app/package-lock.json" "$src/app/check-link.mjs" "$root/app"/
done
target_listing "$fz" >"$TMP/targets.before"
targets_unchanged() {
	target_listing "$fz" >"$TMP/targets.now"
	if cmp -s "$TMP/targets.before" "$TMP/targets.now"; then
		pass "$fx: link targets unchanged after $1"
	else
		fail "$fx: link targets CHANGED after $1:"; diff "$TMP/targets.before" "$TMP/targets.now" | sed 's/^/        /'
	fi
}

cd "$fz/app"
if out="$("$FUZI" install --json 2>install.err)"; then
	linked=$(printf '%s' "$out" | sed -n 's/.*"linked": *\([0-9]*\).*/\1/p')
	if [ "${linked:-0}" -eq 2 ]; then
		pass "$fx: fuzi install OK (2 linked)"
	else
		fail "$fx: fuzi install linked ${linked:-?}, expected 2"
	fi
else
	fail "$fx: fuzi install failed (exit $?)"; cat install.err
fi
targets_unchanged "install"
if node check-link.mjs >/dev/null 2>&1; then
	pass "$fx: ESM import resolves through the link"
else
	fail "$fx: import through the link FAILED"; node check-link.mjs 2>&1 | tail -5
fi
if [ "$(node_modules/.bin/localpkg-b 2>/dev/null)" = "localpkg-b ok" ]; then
	pass "$fx: linked package's .bin shim runs"
else
	fail "$fx: .bin/localpkg-b missing or did not run"
fi
if "$FUZI" verify >/dev/null 2>&1; then
	pass "$fx: fuzi verify OK"
else
	fail "$fx: fuzi verify FAILED"; "$FUZI" verify 2>&1 | tail -5
fi
# Tamper: a tree someone edited after the install must fail `fuzi verify` with
# its data-error exit (65). Each edit keeps the tree *working* — the swapped
# link still resolves to the same package — so only verify can tell; each is
# undone before the next, and the restored tree must verify again.
verify_catches() {
	"$FUZI" verify >/dev/null 2>&1 && rc=0 || rc=$?
	if [ "$rc" -eq 65 ]; then
		pass "$fx: fuzi verify catches $1 (exit 65)"
	else
		fail "$fx: fuzi verify exited $rc on $1, expected 65"
	fi
}
# A package link re-pointed (an absolute path to the very same directory).
text="$(readlink node_modules/localpkg-a)"
rm node_modules/localpkg-a && ln -s "$fz/localpkg-a" node_modules/localpkg-a
verify_catches "a swapped package link"
rm node_modules/localpkg-a && ln -s "$text" node_modules/localpkg-a
# The linked package's `.bin` shim re-pointed (again to the same file).
text="$(readlink node_modules/.bin/localpkg-b)"
rm node_modules/.bin/localpkg-b && ln -s "$fz/localpkg-b/bin/cli.js" node_modules/.bin/localpkg-b
verify_catches "a swapped linked-package .bin shim"
rm node_modules/.bin/localpkg-b && ln -s "$text" node_modules/.bin/localpkg-b
# `node_modules` itself turned into a symlink to the real tree.
mv node_modules nm-real && ln -s nm-real node_modules
verify_catches "a symlinked node_modules"
rm node_modules && mv nm-real node_modules
if "$FUZI" verify >/dev/null 2>&1; then
	pass "$fx: fuzi verify OK again once the tree is restored"
else
	fail "$fx: fuzi verify FAILED on the restored tree"; "$FUZI" verify 2>&1 | tail -5
fi
targets_unchanged "the verify tamper checks"
if "$FUZI" install >/dev/null 2>install.err; then
	pass "$fx: reinstall over the linked tree OK"
else
	fail "$fx: reinstall failed"; cat install.err
fi
targets_unchanged "reinstall"
"$FUZI" clean >/dev/null 2>&1 || fail "$fx: fuzi clean failed"
targets_unchanged "clean"

# npm parity: the same links with the same text, package links and .bin alike.
link_parity() {
	label="$1"; shift
	if ( cd "$np/app" && npm ci --ignore-scripts --no-audit --no-fund "$@" >/dev/null 2>&1 ); then
		link_texts node_modules >"$TMP/fuzi.links"
		link_texts "$np/app/node_modules" >"$TMP/npm.links"
		if cmp -s "$TMP/fuzi.links" "$TMP/npm.links"; then
			pass "$fx: symlinks + texts match npm ci$label ($(wc -l <"$TMP/fuzi.links") links)"
		else
			fail "$fx: symlinks differ from npm ci$label:"; diff "$TMP/npm.links" "$TMP/fuzi.links" | sed 's/^/        /'
		fi
		package_set node_modules >"$TMP/fuzi.set"
		package_set "$np/app/node_modules" >"$TMP/npm.set"
		if [ -z "$(comm -23 "$TMP/npm.set" "$TMP/fuzi.set")" ]; then
			pass "$fx: fuzi ⊇ npm$label (packages)"
		else
			fail "$fx: fuzi MISSING packages npm ci$label placed"
		fi
	else
		skip "$fx: npm ci$label unavailable/failed — skipping npm parity"
	fi
}
link_parity ""

# --omit dev drops the dev-flagged link (its flags live on the target entry).
if "$FUZI" install --omit dev >/dev/null 2>install.err; then
	if [ -L node_modules/localpkg-a ] && [ ! -e node_modules/localpkg-b ] && [ ! -L node_modules/localpkg-b ]; then
		pass "$fx: --omit dev keeps the prod link, drops the dev link"
	else
		fail "$fx: --omit dev placed the wrong links"
	fi
	if "$FUZI" verify --omit dev >/dev/null 2>&1; then
		pass "$fx: fuzi verify --omit dev OK"
	else
		fail "$fx: fuzi verify --omit dev FAILED"
	fi
else
	fail "$fx: fuzi install --omit dev failed"; cat install.err
fi
link_parity " --omit=dev" --omit=dev
targets_unchanged "--omit dev install"
cd "$GATE_DIR"

printf '\n=== libc=%s: ' "$LIBC"
if [ "$fails" -eq 0 ]; then printf '\033[32mALL CHECKS PASSED\033[0m ===\n'; else printf '\033[31m%d CHECK(S) FAILED\033[0m ===\n' "$fails"; fi
[ "$fails" -eq 0 ]
