#!/bin/sh
# End-to-end tests for scripts/install.sh against a local HTTPS server.
#
# install.sh forces `--proto '=https' --tlsv1.2`, so the server must speak TLS:
# a throwaway self-signed localhost cert is generated and trusted for the run
# via CURL_CA_BUNDLE. The "fuz binary" is a stub shell script — install.sh only
# chmod+x's it and runs `<it> self bootstrap`, so no build is needed (real
# bootstrap behavior is covered by the Rust self_cli suite). One Node server
# (scripts/install-test/serve.ts) path-routes the scenarios; this script varies
# FUZ_INSTALL_BASE_URL — and, for the release log cases, FUZ_RELEASE_LOG_URL /
# FUZ_RELEASE_LOG — per case and asserts exit code + output.
#
# Usage:  scripts/install-test.sh
# Needs:  node + openssl + curl (skips cleanly if one is absent); node must run
#         TypeScript by type stripping (fails loudly if it doesn't).
# Env:    INSTALL_SH_SHELL (shell under test), INSTALL_SH_PATH (script under test)
set -u

# The suite decides what install.sh sees of the release log: an exported
# FUZ_RELEASE_LOG_URL in the caller's environment must not turn the cases that
# test the unconfigured path into release log cases. run_case sets the pair
# per case, from CASE_LOG_URL / CASE_LOG.
unset FUZ_RELEASE_LOG_URL FUZ_RELEASE_LOG

REPO="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# The script under test. Overridable so scripts/install-test-mutants.sh can aim
# the whole suite at a deliberately-broken copy of install.sh; unset, this is
# the real thing.
INSTALL="${INSTALL_SH_PATH:-$REPO/scripts/install.sh}"
SERVE="$REPO/scripts/install-test/serve.ts"

# The shell install.sh runs under. `curl … | sh` inherits whoever's /bin/sh is —
# dash on Debian/Ubuntu, busybox ash on Alpine, bash elsewhere — so the script's
# portability is a real property, not a formality (the forge fleet deploys to
# both glibc/Debian and musl/Alpine). Unset = bare `sh`. Word-split on purpose so
# `INSTALL_SH_SHELL='busybox sh'` works.
SH_UNDER_TEST="${INSTALL_SH_SHELL:-sh}"

case "${1:-}" in
	-h | --help) sed -n '2,/^[^#]/s/^# \{0,1\}//p' "$0"; exit 0 ;;
	"") ;;
	*) echo "unknown flag: $1" >&2; exit 64 ;;
esac

command -v node >/dev/null 2>&1 || { echo "SKIP: node not found"; exit 0; }
# serve.ts is TypeScript, which node runs only with type stripping on. A node
# without it is present but unusable: a failure to report, not a reason to skip.
node -e 'process.exit(process.features.typescript ? 0 : 1)' 2>/dev/null ||
	{ echo "FAIL: node $(node --version) does not strip TypeScript types (an older Node, or one run with --no-strip-types)"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not found"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "SKIP: curl not found"; exit 0; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# --- stub "fuz binary": install.sh runs `<it> self bootstrap "$@"` ----------
STUB="$WORK/stub"
cat >"$STUB" <<'STUBEOF'
#!/bin/sh
if [ "$1" = "self" ] && [ "$2" = "bootstrap" ]; then
	[ -n "${FUZ_STUB_MARKER:-}" ] && printf 'ok' >"$FUZ_STUB_MARKER"
	echo "stub bootstrap ok"
	# What bootstrap would read: install.sh must hand both variables through.
	echo "stub env: url=[${FUZ_RELEASE_LOG_URL-<unset>}] switch=[${FUZ_RELEASE_LOG-<unset>}]"
	exit 0
fi
echo "stub: unexpected args: $*" >&2
exit 3
STUBEOF

# --- self-signed localhost cert (trusted for the run via CURL_CA_BUNDLE) ----
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
	-days 1 -nodes -subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 ||
	{ echo "FAIL: could not generate a test cert"; exit 1; }

# --- start the HTTPS server, wait for it to report its port -----------------
PORT=0 CERT="$WORK/cert.pem" KEY="$WORK/key.pem" STUB_PATH="$STUB" \
	node "$SERVE" \
	>"$WORK/server.out" 2>"$WORK/server.err" &
SERVER_PID=$!

port=""
i=0
while [ "$i" -lt 100 ]; do
	port=$(sed -n 's/^PORT=//p' "$WORK/server.out" 2>/dev/null)
	[ -n "$port" ] && break
	kill -0 "$SERVER_PID" 2>/dev/null ||
		{ echo "FAIL: server exited early"; cat "$WORK/server.err"; exit 1; }
	sleep 0.1
	i=$((i + 1))
done
[ -n "$port" ] ||
	{ echo "FAIL: server never reported a port"; cat "$WORK/server.err"; exit 1; }

BASE="https://localhost:$port"
silent_port=$(sed -n 's/^SILENT_PORT=//p' "$WORK/server.out")
http_port=$(sed -n 's/^HTTP_PORT=//p' "$WORK/server.out")
export CURL_CA_BUNDLE="$WORK/cert.pem" # curl trusts our self-signed cert
export SSL_CERT_FILE="$WORK/cert.pem"  # wget fallback (install.sh prefers curl)

pass=0
fail=0
UNSET="<unset>"
CASE_PATH=""
CASE_TMPDIR=""
CASE_LOG_URL="$UNSET"
CASE_LOG="$UNSET"
CASE_HOME="$UNSET"
WANT_ABSENT=""
WANT_ALSO=""
WANT_NO_REQUEST=""

# --- PATH that hides sha512sum, to force install.sh's `shasum -a 512` fallback
# Every macOS install takes that branch (macOS ships `shasum`, not `sha512sum`),
# but on Linux `command -v sha512sum` always wins, so the fallback would
# otherwise never execute in this suite — a typo in it would ship undetected and
# break first-install on macOS only. Symlinking the tools install.sh actually
# calls (minus sha512sum) into one dir is the cheapest way to reach it here.
SHIM="$WORK/no-sha512sum"
mkdir -p "$SHIM"
# (`ldd` and `getconf` too: they are how install.sh tells glibc from musl, and
# without them it falls back to looking for a musl loader, which a glibc host
# with Debian's `musl` package installed has.)
for t in sh uname tr curl wget mktemp df awk cut rm chmod shasum ldd getconf; do
	p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$SHIM/$t"
done
# The shell under test has to be reachable on the restricted PATH too — the
# PATH assignment fronts the command that invokes it, so a shim missing e.g.
# `dash` fails the case with "not found" rather than exercising the fallback.
sh_bin=${SH_UNDER_TEST%% *}
p=$(command -v "$sh_bin" 2>/dev/null) && ln -sf "$p" "$SHIM/$sh_bin"

# temp_left DIR — true when install.sh's temp directory (`fuz.XXXXXX`) is still
# in DIR.
temp_left() {
	for left in "$1"/fuz.*; do
		[ -e "$left" ] && return 0
	done
	return 1
}

# run_case NAME SCENARIO WANT_RC WANT_SUBSTR [marker|nomarker]
# The 5th argument pins whether the stub ran: `marker` asserts install.sh got
# as far as `<binary> self bootstrap`, `nomarker` asserts it never did — the
# difference between a refusal and a refusal *after* the bytes were executed.
# Set CASE_PATH to run install.sh under a restricted PATH (see the digest-tool
# fallback case below); it resets after each case. Set WANT_ABSENT to pin that a
# substring does NOT appear — used where a rejection must land at a specific
# guard and not fall through to a later one; it resets after each case too.
# WANT_ALSO pins a second substring that must appear (matched literally).
# WANT_NO_REQUEST=1 pins that the server saw no request under SCENARIO — so a
# case using it needs a scenario of its own.
#
# SCENARIO is the release host's. The release log is a second axis: set
# CASE_LOG_URL to give install.sh a FUZ_RELEASE_LOG_URL and CASE_LOG a
# FUZ_RELEASE_LOG. Both reset after each case to "$UNSET", which leaves the
# variable unset — distinct from setting it empty, which a case can also do.
# CASE_HOME replaces the case's own home directory as HOME (FUZ_HOME stays the
# case's directory); it resets to "$UNSET" too.
run_case() {
	name=$1
	scenario=$2
	want_rc=$3
	want_sub=$4
	want_marker=${5:-}
	want_absent="$WANT_ABSENT"
	want_also="$WANT_ALSO"
	want_no_request="$WANT_NO_REQUEST"

	home="$WORK/home-$name"
	marker="$WORK/marker-$name"
	out="$WORK/out-$name"
	mkdir -p "$home"
	rm -f "$marker"

	tmp="${CASE_TMPDIR:-$home}"
	mkdir -p "$tmp"
	case_home="$home"
	[ "$CASE_HOME" = "$UNSET" ] || case_home="$CASE_HOME"

	(
		[ "$CASE_LOG_URL" = "$UNSET" ] || export FUZ_RELEASE_LOG_URL="$CASE_LOG_URL"
		[ "$CASE_LOG" = "$UNSET" ] || export FUZ_RELEASE_LOG="$CASE_LOG"
		FUZ_INSTALL_BASE_URL="$BASE/$scenario" HOME="$case_home" FUZ_HOME="$home" \
			TMPDIR="$tmp" FUZ_STUB_MARKER="$marker" \
			PATH="${CASE_PATH:-$PATH}" \
			$SH_UNDER_TEST "$INSTALL" --no-modify-path
	) >"$out" 2>&1
	rc=$?
	CASE_PATH=""
	CASE_TMPDIR=""
	CASE_LOG_URL="$UNSET"
	CASE_LOG="$UNSET"
	CASE_HOME="$UNSET"
	WANT_ABSENT=""
	WANT_ALSO=""
	WANT_NO_REQUEST=""

	ok=1
	[ "$rc" -eq "$want_rc" ] || { ok=0; echo "  rc: got $rc, want $want_rc"; }
	grep -q "$want_sub" "$out" || { ok=0; echo "  missing expected output: $want_sub"; }
	# A forbidden substring pins that the rejection happened at the intended
	# guard and did not fall through to a later one (the malformed/length guards
	# must reject *before* the digest compare, never surface as "checksum
	# mismatch"). Empty WANT_ABSENT (the default) skips this check.
	[ -n "$want_absent" ] && grep -q "$want_absent" "$out" &&
		{ ok=0; echo "  forbidden output present (rejected too late?): $want_absent"; }
	[ -n "$want_also" ] && ! grep -qF -- "$want_also" "$out" &&
		{ ok=0; echo "  missing expected output: $want_also"; }
	[ -n "$want_no_request" ] && grep -q "^REQ /$scenario/" "$WORK/server.out" &&
		{ ok=0; echo "  the server saw a request under /$scenario/, and should have seen none"; }
	# Whatever the outcome, install.sh takes its temp directory with it.
	temp_left "$tmp" && { ok=0; echo "  temp files left behind in $tmp"; }
	# An empty marker arg means "don't assert"; a non-empty, unrecognized value
	# is a typo that would silently disable the check, so reject it loudly.
	case "$want_marker" in
		marker)
			[ -f "$marker" ] || { ok=0; echo "  stub was not invoked (no marker)"; } ;;
		nomarker)
			[ -f "$marker" ] && { ok=0; echo "  stub was invoked (marker present) but should not have been"; } ;;
		"") ;;
		*) echo "run_case: unrecognized marker arg '$want_marker' (want: marker | nomarker | empty)" >&2; exit 64 ;;
	esac

	if [ "$ok" -eq 1 ]; then
		echo "PASS: $name"
		pass=$((pass + 1))
	else
		echo "FAIL: $name"
		sed 's/^/    /' "$out"
		fail=$((fail + 1))
	fi
}

run_case ok        ok        0 "verified — running bootstrap" marker
run_case notfound  notfound  1 "failed to download" nomarker
run_case nosidecar nosidecar 1 "checksum sidecar is missing" nomarker
# A mismatch may be a compromised release host: the refusal points at the
# private reporting channel, never at the public tracker.
PRIVATE_REPORT="report privately: https://github.com/fuzdev/fuz/security/policy"
WANT_ALSO="$PRIVATE_REPORT"
WANT_ABSENT="fuzdev/fuz/issues"
run_case badsum    badsum    65 "checksum mismatch" nomarker
# A non-hex sidecar: rejected by the malformed-digest guard, which must be
# *terminal* — WANT_ABSENT pins that execution never reaches the digest compare
# (a neutralized guard `exit` would leak a "checksum mismatch" here instead).
WANT_ABSENT="checksum mismatch"
run_case malformed malformed 1 "sidecar is malformed" nomarker
run_case upper     upper     0 "verified — running bootstrap" marker
run_case flaky     flaky     0 "verified — running bootstrap" marker

# A sidecar whose digest field is built to drive the terminal (an erase-line
# sequence, a carriage return, a direction override): the refusal shows it as
# printable ASCII, one `?` per byte that is not, and no escape byte reaches the
# output.
WANT_ABSENT="$(printf '\033')"
WANT_ALSO="got 'x?[2K????y'"
run_case hostile hostile 1 "sidecar is malformed" nomarker

# A digest field of any length is cut to the bound before it is shown: the
# first 512 characters, and not the 513th.
WANT_ABSENT="$(printf '%0513d' 0 | tr 0 z)"
WANT_ALSO="got '$(printf '%0512d' 0 | tr 0 z)'"
run_case longfield longfield 1 "sidecar is malformed" nomarker

# A 64-hex (sha256-length) sidecar: lowercase, all hex, so the charset check
# passes it through. Only the "exactly 128" length test stands between a
# downgraded digest and a compare against a truncated value, so this is the
# case that fails if that test is weakened. WANT_ABSENT pins that the length
# guard is terminal — the rejection must not fall through to the digest compare.
WANT_ABSENT="checksum mismatch"
run_case sha256len sha256len 1 "sidecar is malformed" nomarker

# TLS downgrade on redirect: the server 301s to a *fully valid* plain-HTTP copy
# of the `ok` scenario, so the install would otherwise sail through — the only
# thing stopping it is curl's `--proto '=https'` refusing https→http. rc +
# "failed to download" + nomarker is the whole pin; curl's own protocol-refusal
# wording varies by version, so matching it would make this case brittle.
run_case redirect  redirect  1 "failed to download" nomarker

# The fallback must agree with sha512sum on the same bytes, or the digest
# compare fails — so a passing `ok` scenario here proves cross-tool agreement,
# not just that the branch ran.
if [ -e "$SHIM/shasum" ] && ! PATH="$SHIM" command -v sha512sum >/dev/null 2>&1; then
	CASE_PATH="$SHIM"
	run_case shasum_fallback ok 0 "verified — running bootstrap" marker
else
	echo "SKIP: shasum_fallback (no shasum, or sha512sum still on the shim PATH)"
fi

# TMPDIR with a backslash: GNU coreutils escapes such filenames and marks the
# line by prefixing the *hash* with a backslash, so computing the digest by
# path would yield a corrupt value and report a bogus "checksum mismatch —
# ... tampered with". install.sh reads via stdin to sidestep it. TMPDIR is
# user-supplied (the disk-space hint tells you to set it), so this is reachable.
CASE_TMPDIR="$WORK/back\\slash-tmp"
run_case backslash_tmpdir ok 0 "verified — running bootstrap" marker

# A relative HOME is refused before anything is requested, as the binary would
# refuse it — but only after the download. The `relhome` scenario serves like
# `ok` and is this case's alone, so WANT_NO_REQUEST pins the refusal's timing.
CASE_HOME="h"
WANT_NO_REQUEST=1
run_case relhome relhome 1 "HOME is not an absolute path" nomarker

# A musl host (Alpine): fuz has no musl build, so install.sh refuses before it
# requests anything. A fake `ldd` that answers `--version` the way musl's does
# (on stderr, exit 1) fronts the PATH, so this glibc host reads as musl; the
# glibc side is every other case. The `musl` scenario serves like `ok`, so with
# the refusal gone the install would succeed — and it is this case's alone, so
# WANT_NO_REQUEST can pin that nothing was downloaded.
if [ "$(uname -s)" = Linux ]; then
	FAKE_MUSL="$WORK/fake-musl"
	mkdir -p "$FAKE_MUSL"
	cat >"$FAKE_MUSL/ldd" <<'LDDEOF'
#!/bin/sh
printf 'musl libc (x86_64)\nVersion 1.2.5\nDynamic Program Path\n' >&2
exit 1
LDDEOF
	chmod +x "$FAKE_MUSL/ldd"
	CASE_PATH="$FAKE_MUSL:$PATH"
	WANT_ALSO="nothing was downloaded"
	WANT_NO_REQUEST=1
	run_case musl musl 1 "this host's libc is musl" nomarker

	# Undetermined reads as glibc: an `ldd` that names neither libc (Gentoo's
	# prints its own banner) and a `getconf` that fails, on a host with no musl
	# loader, must install, not refuse. Skipped where the loader exists, since
	# it would then decide the case.
	if [ -e "/lib/ld-musl-$(uname -m).so.1" ]; then
		echo "SKIP: libc_undetermined (this host has a musl loader)"
	else
		FAKE_UNDETERMINED="$WORK/fake-undetermined"
		mkdir -p "$FAKE_UNDETERMINED"
		cat >"$FAKE_UNDETERMINED/ldd" <<'LDDEOF'
#!/bin/sh
printf 'ldd (Gentoo 2.39-r9 p6) 2.39\n'
LDDEOF
		cat >"$FAKE_UNDETERMINED/getconf" <<'GETCONFEOF'
#!/bin/sh
exit 1
GETCONFEOF
		chmod +x "$FAKE_UNDETERMINED/ldd" "$FAKE_UNDETERMINED/getconf"
		CASE_PATH="$FAKE_UNDETERMINED:$PATH"
		run_case libc_undetermined ok 0 "verified — running bootstrap" marker
	fi
else
	echo "SKIP: musl, libc_undetermined (musl detection runs on Linux only)"
fi

# --- release log --------------------------------------------------------------
# With FUZ_RELEASE_LOG_URL set, the digest and the version come from a release
# log origin (`w*` scenarios) and the release host supplies bytes only. Most
# cases run against `vonly`, a release host with no `fuz-latest-*` and no
# sidecar at all: an install that succeeds there read neither.

LOG="$BASE"
VERIFIED="verified fuz 0.9.9 against the release log"
MALFORMED="release log pointer is malformed"
# A token that must never reach the output: an origin is named by position
# only, since a URL can carry a secret.
SECRET="tok-SECRET"
# Port 1 (tcpmux) is the closed port: nothing listens there, and unlike a port
# the OS handed out and took back, no concurrent run can come to own it.
DOWN="https://localhost:1/$SECRET"

# Local-directory origins. The suite doesn't know the host's target, so each
# directory holds a pointer for every target install.sh can detect.
TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin"
if command -v sha512sum >/dev/null 2>&1; then
	stub_sum=$(sha512sum <"$STUB" | cut -d' ' -f1)
else
	stub_sum=$(shasum -a 512 <"$STUB" | cut -d' ' -f1)
fi
DIR_OK="$WORK/log-ok"         # the correct pointer
DIR_EMPTY="$WORK/log-empty"   # an existing directory with no pointer
DIR_BLOCKED="$WORK/log-blocked" # the pointer's path exists and is not a file
mkdir -p "$DIR_OK/latest" "$DIR_EMPTY" "$DIR_BLOCKED/latest"
for t in $TARGETS; do
	printf '%s  fuz-0.9.9-%s\n' "$stub_sum" "$t" >"$DIR_OK/latest/fuz-$t.sha512"
	mkdir -p "$DIR_BLOCKED/latest/fuz-$t.sha512"
done
DIR_SPACED="$WORK/log with space" # an entry is never word-split
cp -R "$DIR_OK" "$DIR_SPACED"

# The pointer is the only source of the digest and the name: the release host
# has no sidecar and no `fuz-latest-*` to fall back on.
CASE_LOG_URL="$LOG/wok"
WANT_ALSO="stub env: url=[$LOG/wok] switch=[<unset>]"
run_case witness_ok vonly 0 "$VERIFIED" marker
# A release host whose sidecar is wrong: not consulted, so not a failure.
CASE_LOG_URL="$LOG/wok"
run_case witness_ignores_sidecar badsum 0 "$VERIFIED" marker
CASE_LOG_URL="$LOG/wok/"
run_case witness_trailing_slash vonly 0 "$VERIFIED" marker
CASE_LOG_URL="$LOG/wupper"
run_case witness_upper vonly 0 "$VERIFIED" marker

# The bytes are not the logged release. A contradiction between two origins,
# not the corrupted download the sidecar path reports.
CASE_LOG_URL="$LOG/wmismatch"
WANT_ABSENT="checksum mismatch"
WANT_ALSO="$PRIVATE_REPORT"
run_case witness_mismatch vonly 65 "not the release the release log records" nomarker

# The release host has no such versioned binary.
CASE_LOG_URL="$LOG/wok"
run_case witness_binary_missing notfound 1 "failed to download" nomarker

# Absent: the origin answered and has no pointer. A refusal, never "retry".
CASE_LOG_URL="$LOG/wabsent"
run_case witness_absent vonly 65 "release log has no release for" nomarker
CASE_LOG_URL="$LOG/wgone"
run_case witness_gone vonly 65 "release log has no release for" nomarker

# Unreachable: the only soft failure, and the only thing that moves on to the
# next origin. Exit 75, and the origin's URL stays out of the output.
CASE_LOG_URL="$DOWN"
WANT_ABSENT="$SECRET"
WANT_ALSO="not a refusal"
run_case witness_down vonly 75 "no release log origin could be reached" nomarker
CASE_LOG_URL="$LOG/w403,$DIR_BLOCKED"
WANT_ALSO="origin 2 is unreachable"
run_case witness_unreachable vonly 75 "no release log origin could be reached" nomarker
# A 5xx that outlasts the retries, a 403, and an unreadable local pointer are
# each passed over for the next origin.
CASE_LOG_URL="$LOG/w503/base/path,$LOG/w403,$DIR_BLOCKED,$LOG/wok"
WANT_ALSO="origin 1 is unreachable (HTTP 503)"
run_case witness_fallback vonly 0 "$VERIFIED" marker

# A transient 503 is retried, as it is for the binary.
CASE_LOG_URL="$LOG/wflaky"
run_case witness_flaky vonly 0 "$VERIFIED" marker
# TLS downgrade on redirect: the origin 301s to a fully valid plain-HTTP copy of
# the pointer, which only curl's `--proto '=https'` refuses. A refused redirect
# is an origin that did not answer.
CASE_LOG_URL="$LOG/wredirect"
run_case witness_redirect vonly 75 "no release log origin could be reached" nomarker
# A failed TLS handshake (here against the plain-HTTP listener) is an origin
# that did not answer: passed over for the next one.
CASE_LOG_URL="https://localhost:$http_port,$LOG/wok"
WANT_ALSO="origin 1 is unreachable (no response)"
run_case witness_tls_failure vonly 0 "$VERIFIED" marker
# A curl failure that is not the network's (here a port curl cannot use) says
# nothing about the origin: a refusal, not "retry later", and no moving on.
CASE_LOG_URL="https://localhost:99999,$LOG/wok"
run_case witness_bad_port vonly 1 "origin 1 could not be read" nomarker

# No shopping: an origin that answers is final, however good the next one is.
CASE_LOG_URL="$LOG/wabsent,$LOG/wok"
run_case witness_no_shopping_absent vonly 65 "release log has no release for" nomarker
CASE_LOG_URL="$LOG/wmultiline,$LOG/wok"
run_case witness_no_shopping_malformed vonly 1 "$MALFORMED" nomarker
CASE_LOG_URL="$LOG/wmismatch,$LOG/wok"
run_case witness_no_shopping_mismatch vonly 65 "not the release the release log records" nomarker

# Pointer shape. Every one of these pointers is otherwise valid — right digest,
# a name the release host serves — so the install succeeds if its guard is gone.
for w in 304 empty nonl crlf multiline partial extra onespace tab threespace lead big badname badchar plus dotdot noversion latest othertarget notfuz; do
	CASE_LOG_URL="$LOG/w$w"
	run_case "witness_$w" ok 1 "$MALFORMED" nomarker
done
# The digest guard is terminal here too: a short digest never reaches the compare.
CASE_LOG_URL="$LOG/wsha256len"
WANT_ABSENT="not the release the release log records"
run_case witness_sha256len ok 1 "$MALFORMED" nomarker

# Local-directory origins.
CASE_LOG_URL="$DIR_OK"
run_case witness_dir vonly 0 "$VERIFIED" marker
CASE_LOG_URL="file://$DIR_SPACED"
run_case witness_dir_file_uri vonly 0 "$VERIFIED" marker
# `~/` is the home directory, as it is for the binary.
mkdir -p "$WORK/home-witness_dir_tilde"
cp -R "$DIR_OK" "$WORK/home-witness_dir_tilde/log"
CASE_LOG_URL="~/log"
run_case witness_dir_tilde vonly 0 "$VERIFIED" marker
CASE_LOG_URL="$DIR_EMPTY"
run_case witness_dir_absent vonly 65 "release log has no release for" nomarker
# A pointer that exists and cannot be read is unreachable, not absent: the next
# origin is read.
DIR_DANGLING="$WORK/log-dangling"
DIR_UNREADABLE="$WORK/log-unreadable"
mkdir -p "$DIR_DANGLING/latest"
cp -R "$DIR_OK" "$DIR_UNREADABLE"
for t in $TARGETS; do
	ln -s "$WORK/no-such-file" "$DIR_DANGLING/latest/fuz-$t.sha512"
	chmod 000 "$DIR_UNREADABLE/latest/fuz-$t.sha512"
done
CASE_LOG_URL="$DIR_DANGLING,$DIR_OK"
WANT_ALSO="origin 1 is unreachable"
run_case witness_dir_dangling vonly 0 "$VERIFIED" marker
if [ "$(id -u)" -ne 0 ]; then
	CASE_LOG_URL="$DIR_UNREADABLE,$DIR_OK"
	WANT_ALSO="origin 1 is unreachable"
	run_case witness_dir_unreadable vonly 0 "$VERIFIED" marker
else
	echo "SKIP: witness_dir_unreadable (root reads any file)"
fi

# Configuration errors: exit 2 before any request, the entry named by position
# and never shown.
config_case() {
	CASE_LOG_URL=$2
	WANT_ABSENT="$SECRET"
	run_case "config_$1" ok 2 "FUZ_RELEASE_LOG_URL entry 1 is not usable" nomarker
}
config_case http "http://localhost:1/$SECRET"
config_case forge "forge://$SECRET"
config_case ssh "ssh://$SECRET@host/x"
config_case scheme "gopher://$SECRET"
config_case userinfo "https://user:$SECRET@localhost:1/x"
config_case query "https://localhost:1/x?$SECRET"
config_case no_host "https://"
# (The `localhost:1` keeps this quick when the guard is mutated away: curl
# reads it as the host, where a bare token would be a slow DNS lookup.)
config_case empty_host "https:///localhost:1/$SECRET"
config_case missing_dir "$WORK/$SECRET-missing"
[ ! -e "$WORK/$SECRET-missing" ] ||
	{ echo "FAIL: a missing local origin was created"; fail=$((fail + 1)); }
# The whole list is validated before the first request: a usable first origin
# does not get the install past a bad second one. Empty entries are skipped and
# not counted.
CASE_LOG_URL="$LOG/wok, ,forge://$SECRET"
WANT_ABSENT="$SECRET"
run_case config_validated_first vonly 2 "FUZ_RELEASE_LOG_URL entry 2 is not usable" nomarker
CASE_LOG_URL=" , $LOG/wok ,"
run_case config_empty_entries vonly 0 "$VERIFIED" marker

# The switch. `off` with an origin configured: the unconfigured path, and a
# warning. It has to work when the list itself is what is broken.
CASE_LOG_URL="$LOG/wabsent"
CASE_LOG=off
WANT_ALSO="release log check is off"
run_case switch_off ok 0 "verified — running bootstrap" marker
CASE_LOG_URL="forge://$SECRET"
CASE_LOG=off
WANT_ALSO="stub env: url=[forge://$SECRET] switch=[off]"
run_case switch_off_broken_list ok 0 "verified — running bootstrap" marker
# Anything but `off` is an error, never read as on or as off — whatever the
# origin list holds.
CASE_LOG_URL="$LOG/wok"
CASE_LOG=OFF
run_case switch_invalid vonly 2 "FUZ_RELEASE_LOG is set to something other than" nomarker
CASE_LOG=0
run_case switch_invalid_unconfigured ok 2 "FUZ_RELEASE_LOG is set to something other than" nomarker
# No origin configured — unset, empty, or only separators: the release log is
# not read and nothing says so, with or without the switch.
CASE_LOG=off
WANT_ABSENT="release log"
run_case switch_off_unconfigured ok 0 "verified — running bootstrap" marker
CASE_LOG_URL=""
WANT_ABSENT="release log"
run_case unconfigured_empty ok 0 "verified — running bootstrap" marker
CASE_LOG_URL=" , "
WANT_ABSENT="release log"
run_case unconfigured_separators ok 0 "verified — running bootstrap" marker

# --- a signal ends the install -----------------------------------------------
# install.sh is signalled while its pointer fetch is waiting on an origin that
# accepts the connection and never answers, with a good second origin listed. It must stop there — not clean up and carry on to
# the next origin — and leave nothing behind. The signal goes to the whole
# process group, as a terminal's would, so curl gets it too; `setsid` gives the
# run a group of its own.
# interrupt_case NAME SIGNAL WANT_RC
interrupt_case() {
	name=$1
	home="$WORK/home-$name"
	marker="$WORK/marker-$name"
	out="$WORK/out-$name"
	mkdir -p "$home"
	(
		export FUZ_RELEASE_LOG_URL="https://localhost:$silent_port,$LOG/wok"
		FUZ_INSTALL_BASE_URL="$BASE/vonly" HOME="$home" FUZ_HOME="$home" \
			TMPDIR="$home" FUZ_STUB_MARKER="$marker" \
			exec setsid $SH_UNDER_TEST "$INSTALL" --no-modify-path
	) >"$out" 2>&1 &
	pid=$!
	# The temp directory appears just before the fetch starts.
	i=0
	while [ "$i" -lt 50 ] && ! temp_left "$home"; do
		sleep 0.1
		i=$((i + 1))
	done
	sleep 0.3
	kill -s "$2" -- "-$pid" 2>/dev/null
	wait "$pid"
	rc=$?

	ok=1
	[ "$rc" -eq "$3" ] || { ok=0; echo "  rc: got $rc, want $3"; }
	[ -f "$marker" ] && { ok=0; echo "  stub was invoked (marker present) but should not have been"; }
	temp_left "$home" && { ok=0; echo "  temp files left behind in $home"; }
	if [ "$ok" -eq 1 ]; then
		echo "PASS: $name"
		pass=$((pass + 1))
	else
		echo "FAIL: $name"
		sed 's/^/    /' "$out"
		fail=$((fail + 1))
	fi
}
if command -v setsid >/dev/null 2>&1; then
	interrupt_case witness_interrupt TERM 143
else
	echo "SKIP: witness_interrupt (no setsid)"
fi

# --- without curl -------------------------------------------------------------
# install.sh prefers curl, so its wget branch only runs where curl is absent: a
# PATH without curl reaches it, and wget trusts the test cert through a wgetrc.
NOCURL="$WORK/no-curl"
mkdir -p "$NOCURL"
for t in sh uname tr wget mktemp df awk cut rm chmod wc sha512sum shasum ldd getconf; do
	p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$NOCURL/$t"
done
p=$(command -v "$sh_bin" 2>/dev/null) && ln -sf "$p" "$NOCURL/$sh_bin"
printf 'ca_certificate = %s\n' "$WORK/cert.pem" >"$WORK/wgetrc"
export WGETRC="$WORK/wgetrc"
if PATH="$NOCURL" command -v curl >/dev/null 2>&1; then
	echo "SKIP: the no-curl cases (curl still on the shim PATH)"
else
	# The release log read is curl-only: refused before anything is requested,
	# and never attempted with wget.
	CASE_PATH="$NOCURL"
	CASE_LOG_URL="$LOG/wok"
	WANT_ABSENT="release log for"
	run_case witness_needs_curl vonly 1 "reading the release log needs curl" nomarker
	if PATH="$NOCURL" wget --https-only -qO /dev/null "$BASE/ok/fuz-probe" 2>/dev/null; then
		CASE_PATH="$NOCURL"
		run_case wget_success ok 0 "verified — running bootstrap" marker
		CASE_PATH="$NOCURL"
		run_case wget_notfound notfound 1 "failed to download" nomarker
		# A redirect to a valid plain-HTTP copy: only --max-redirect=0 refuses it.
		CASE_PATH="$NOCURL"
		run_case wget_redirect redirect 1 "failed to download" nomarker
	else
		echo "SKIP: the wget cases (no usable wget)"
	fi
fi

echo
echo "install.sh e2e [$SH_UNDER_TEST]: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
