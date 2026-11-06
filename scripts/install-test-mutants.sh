#!/bin/sh
# Mutation gate for scripts/install.sh — the e2e suite's own test.
#
# scripts/install-test.sh asserts install.sh does the right thing. This asserts
# the suite would *notice* if it stopped: each row below is a (mutation → the
# case that must catch it) pin. A row breaks one security- or correctness-
# critical behavior with a minimal sed edit, runs the whole e2e suite against
# the mutated copy, and requires the named case to fail. A mutation that fails
# nothing is not a passing test — it is the name of an untested property, and
# this harness is how that gets surfaced instead of assumed.
#
# Drift guard: a row whose sed no longer changes anything (install.sh was
# refactored out from under it) FAILS loudly rather than silently pinning
# nothing. Fix the expression or retire the row.
#
# Usage:  scripts/install-test-mutants.sh
# Needs:  the same deno + openssl + curl as install-test.sh (skips if absent).
#         Mutants run under the default `sh` only — shell portability is the
#         e2e suite's job (INSTALL_SH_SHELL), not this one's.
# Env:    INSTALL_MUTANT_JOBS — how many mutants run at once (default: the CPU
#         count, at most 8; 4 where `nproc` is absent). Each run is its own
#         server on its own port, and is mostly waiting on curl.
set -u

case "${1:-}" in
	-h | --help) sed -n '2,/^[^#]/s/^# \{0,1\}//p' "$0"; exit 0 ;;
	"") ;;
	*) echo "unknown flag: $1" >&2; exit 64 ;;
esac

REPO="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
INSTALL="$REPO/scripts/install.sh"
SUITE="$REPO/scripts/install-test.sh"

command -v deno >/dev/null 2>&1 || { echo "SKIP: deno not found"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not found"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "SKIP: curl not found"; exit 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

# --- baseline: the unmutated suite must be fully green ----------------------
# A red or skipped baseline makes every row below meaningless — "the suite
# failed under mutation" says nothing when the suite fails without one.
echo "baseline: running the unmutated suite..."
# Pin the shell (INSTALL_SH_SHELL=sh) and the script (INSTALL_SH_PATH=$INSTALL,
# the unmutated original the rows mutate copies of): an exported override in the
# caller's environment would otherwise make the baseline attest to a different
# shell or file than the rows exercise, defeating its purpose.
INSTALL_SH_SHELL=sh INSTALL_SH_PATH="$INSTALL" sh "$SUITE" >"$WORK/baseline.out" 2>&1
baseline_rc=$?
if [ "$baseline_rc" -ne 0 ] || ! grep -q ' 0 failed' "$WORK/baseline.out"; then
	echo "FAIL: baseline suite is not green — fix install.sh or the suite first"
	sed 's/^/    /' "$WORK/baseline.out"
	exit 1
fi
sed -n 's/^install\.sh e2e/  baseline: install.sh e2e/p' "$WORK/baseline.out"
echo

pass=0
fail=0
skipped=0
default_jobs=$(nproc 2>/dev/null) || default_jobs=4
case "$default_jobs" in "" | *[!0-9]* | 0) default_jobs=4 ;; esac
[ "$default_jobs" -le 8 ] || default_jobs=8
JOBS="${INSTALL_MUTANT_JOBS:-$default_jobs}"
case "$JOBS" in
	"" | *[!0-9]* | 0) echo "INSTALL_MUTANT_JOBS must be a positive integer" >&2; exit 64 ;;
esac

# NAME~SED_EXPR~EXPECTED_FAILING_CASES
# `~` separates the fields because sed expressions freely contain `|` and `/`.
# The third field is one case or several, separated by spaces; every one of
# them must fail. A behavior both install paths share (the digest guards, the
# downloader's flags) names a case from each, so a refactor that quietly stops
# one path from going through the shared code shows up as a miss.
cat >"$WORK/rows" <<'ROWS'
# TLS downgrade on redirect — the headline row: without --proto '=https' curl
# follows the 301 to plain HTTP and installs happily.
proto_https~s/--proto '=https' //~redirect witness_redirect
# Without -f, curl exits 0 on a 404 and writes the error page to disk — which
# for a release log origin turns "absent" into a pointer that fails to parse.
curl_fail~s/curl -fsSL/curl -sSL/~notfound witness_absent
# Neutralize the 128-length guard (still rejects an empty digest, so the other
# malformed case survives) — a sha256-length digest then reaches the compare.
digest_length~s/-eq 128/-ge 1/~sha256len witness_sha256len
# Without case folding, an uppercase-hex digest reads as a tampered download.
case_fold~s/ | tr 'A-F' 'a-f'//~upper witness_upper
# Invert the mismatch test: a wrong digest passes, a right one is rejected.
digest_compare~s/"\$expected" != "\$actual"/"$expected" = "$actual"/~badsum witness_mismatch
# A digest mismatch, which may be a compromised release host, sent to the
# public issue tracker instead of the private reporting channel.
private_report~s,report privately: https://github.com/fuzdev/fuz/security/policy,report at https://github.com/fuzdev/fuz/issues,~badsum witness_mismatch
# Hash by path instead of stdin: GNU coreutils escapes a backslash in the
# filename and marks it by prefixing the hash, corrupting the digest.
digest_stdin~s/sha512sum </sha512sum /;s/shasum -a 512 </shasum -a 512 /~backslash_tmpdir
# A relative HOME accepted: the install downloads and runs bootstrap, which
# only then refuses it.
relative_home~s,/\*) ;;,/* | [!/]*) ;;,~relhome
# No musl refusal: a musl host downloads the glibc binary, which cannot run
# there.
musl_refusal~s/if is_musl "\$arch"; then/if false; then/~musl
# The musl answer from `ldd --version` is not recognized: detection falls
# through to `getconf GNU_LIBC_VERSION`, which reads the host as glibc.
musl_ldd~s/\*musl\*) return 0 ;;/*musl-never*) return 0 ;;/~musl
# Undetermined reads as musl: a glibc host whose ldd names neither libc is
# refused.
musl_default~s|\[ -e "/lib/ld-musl-\$1.so.1" \]|true|~libc_undetermined
# Without --retry, a transient 503 aborts the one-liner.
curl_retry~s/--retry 3 //~flaky witness_flaky
# Print what a server sent as it is, instead of as printable ASCII: a sidecar's
# escape sequence then reaches the terminal with the refusal.
printable_filter~s/LC_ALL=C tr -c ' -.' '?'/cat/~hostile
# Without the cut, a field of any length reaches the terminal whole.
printable_cut~s/ | LC_ALL=C cut -c1-512//~longfield
# Neutralize the malformed/length guard's terminal `exit 1` (keeping the guard's
# detection + message): execution then falls through to the digest compare,
# which exits 65 with "checksum mismatch" while "sidecar is malformed" still
# prints. The rc (1 wanted) and the malformed case's WANT_ABSENT ("checksum
# mismatch" must be absent) both distinguish "rejected by the guard" from
# "rejected by the later compare".
digest_guard_exit~/wait a minute and retry/{n;s/exit 1/:/;}~malformed
# The same for the release log pointer: with its `exit` gone, a short digest
# goes on to the compare and is reported as a contradiction instead.
pointer_guard_exit~/a retry is unlikely to help/{n;s/exit 1/:/;}~witness_sha256len
#
# --- release log: which origin answers, and what an answer means ---
# 404 read as "unreachable": a missing pointer becomes a soft failure, and —
# the no-shopping rule — the install moves on to the next origin for a better
# answer.
absent_is_hard~s/404 | 410) pointer_absent/40x) pointer_absent/~witness_absent witness_no_shopping_absent
# 410 dropped from the absent class.
absent_gone~s/404 | 410) pointer_absent/404) pointer_absent/~witness_gone
# "Cannot confirm yet" reported with the refusal's exit code.
unconfirmed_exit~s/exit 75/exit 1/~witness_down
# A curl failure that is not the network's (exit 3, a URL it cannot use) read
# as "unreachable": the install moves on to the next origin.
curl_class~s/5 | 6 | 7 | 28/3 | 5 | 6 | 7 | 28/~witness_bad_port
# A failed TLS handshake dropped from the unreachable class: a refusal instead
# of moving on to the next origin.
curl_class_tls~s/ | 35 | 52/ | 52/~witness_tls_failure
# The wget branch follows redirects again: a 301 to plain HTTP installs.
wget_redirect~s/ --max-redirect=0//~wget_redirect
# The release log read attempted without curl — through wget, which cannot
# report the HTTP status the read needs.
needs_curl~s/if ! command -v curl >\/dev\/null 2>&1; then/if false; then/~witness_needs_curl
# A local pointer that is not readable, or is a dangling symlink, is no longer
# "unreachable".
dir_unreadable~s/if \[ -f "\$pointer" \] && \[ -r "\$pointer" \]; then/if [ -f "$pointer" ]; then/~witness_dir_unreadable
dir_dangling~s/if \[ -e "\$pointer" \] || \[ -L "\$pointer" \]; then/if [ -e "$pointer" ]; then/~witness_dir_dangling
# A trailing slash on an origin is no longer stripped.
trailing_slash~s|\*/) _rest=\${_rest%/} ;;|*//) _rest=${_rest%/} ;;|~witness_trailing_slash
#
# --- temp files and signals ---
# The temp directory is left behind.
cleanup~s/rm -rf "\$temp_dir"/:/~ok witness_ok
# A signal cleans up and lets the script carry on (the exit code gives it away:
# the interrupted fetch then fails closed on its own).
trap_no_exit~s/trap 'exit 143' TERM/trap cleanup TERM/~witness_interrupt
# No handler: the signal kills the shell before it can clean up.
trap_removed~/trap 'exit 143' TERM/d~witness_interrupt
#
# --- release log: the pointer's shape ---
# A second line is never looked for.
pointer_second_line~s/if IFS= read -r extra ||/if false \&\& IFS= read -r extra ||/~witness_multiline
# An unterminated fragment after the line is not noticed.
pointer_partial_line~s/ || \[ -n "\$extra" \]; then shape_ok=0/; then shape_ok=0/~witness_partial
# A line with no trailing newline is accepted.
pointer_newline~s/IFS= read -r line || shape_ok=0/IFS= read -r line || :/~witness_nonl
# The line split on any run of whitespace, as `read` splits fields: one space,
# a tab, three spaces, and a leading space are each accepted as the separator.
pointer_separator~s/IFS= read -r line || shape_ok=0/read -r expected fname || shape_ok=0/;/^\texpected=\${line%%/d;/^\tfname=\${line#/d~witness_onespace witness_tab witness_threespace witness_lead
# A response that wrote no file is not noticed.
pointer_no_file~s/\[ -f "\$pointer" \] || pointer_malformed/:/~witness_304
# No bound on the pointer's size.
pointer_size~s/-le "\$POINTER_MAX_BYTES" \] || pointer_malformed/-le "$POINTER_MAX_BYTES" ] || :/~witness_big
# The name need not end in this target.
name_target~s/"fuz-"\*"-\$target") ;;/"fuz-"*) ;;/~witness_othertarget
# The name need not be a `fuz-` binary.
name_prefix~s/"fuz-"\*"-\$target") ;;/*"-$target") ;;/~witness_notfuz
# The version may be empty.
name_version~s/\[ -n "\$version" \] || pointer_malformed/:/~witness_noversion
# The moving `latest` name is accepted as a version.
name_latest~s/\[ "\$version" = latest \] && pointer_malformed/:/~witness_latest
# `/` admitted to the name charset.
name_slash~s|\*\[!A-Za-z0-9._-\]\*) pointer_malformed|*[!A-Za-z0-9._/-]*) pointer_malformed|~witness_badname
# `+` admitted to the name charset: a version with build metadata, which no
# publish produces and no head records.
name_plus~s|\*\[!A-Za-z0-9._-\]\*) pointer_malformed|*[!A-Za-z0-9._+-]*) pointer_malformed|~witness_plus
# No charset check on the name at all.
name_charset~s/case "\$fname" in \*\[!A-Za-z0-9._-\]\*) pointer_malformed ;; esac/:/~witness_badchar
# `..` allowed in the name.
name_dotdot~s/case "\$fname" in \*\.\.\*) pointer_malformed ;; esac/:/~witness_dotdot
#
# --- release log: configuration ---
# The switch accepts anything: `OFF` is no longer an error.
switch_validation~s/"" | off) ;;/*) ;;/~switch_invalid switch_invalid_unconfigured
# The opt-out is not honored.
switch_off~s/if \[ "\$LOG_SWITCH" = off \]; then/if false; then/~switch_off switch_off_broken_list
# The list is not validated before the first request.
validate_first~s/for_each_origin check_origin || :/:/~config_validated_first config_forge
# An https origin may carry credentials or a query, or have no host. (The `.`
# after `._` stands for the charset's `~`, which is this table's field
# separator.)
origin_charset~s/"" | \/\* | \*\[!A-Za-z0-9._.:\/%+=-\]\*) return 1/"") return 1/~config_userinfo config_query config_empty_host
# The refused entry is shown.
origin_echo~s/entry \$1 is not usable/entry $1 [$2] is not usable/~config_http config_missing_dir
ROWS

# launch_mutant NAME SED_EXPR — start the suite against the mutated copy in the
# background; its output and exit code land in $WORK for check_mutant.
launch_mutant() {
	name=$1
	expr=$2

	mutant="$WORK/install-$name.sh"
	if ! sed "$expr" "$INSTALL" >"$mutant"; then
		echo "sed failed: $expr" >"$WORK/broken-$name"
		return
	fi
	if cmp -s "$mutant" "$INSTALL"; then
		echo "mutation did not apply; install.sh no longer matches: $expr" >"$WORK/broken-$name"
		return
	fi

	# INSTALL_SH_SHELL=sh keeps the "mutants run under the default sh only"
	# invariant true even if the caller exported a different shell.
	(
		INSTALL_SH_SHELL=sh INSTALL_SH_PATH="$mutant" sh "$SUITE" >"$WORK/out-$name" 2>&1
		echo "$?" >"$WORK/rc-$name"
	) &
	running=$((running + 1))
	if [ "$running" -ge "$JOBS" ]; then
		wait
		running=0
	fi
}

# check_mutant NAME EXPECTED_FAILING_CASES
check_mutant() {
	name=$1
	want_cases=$2

	if [ -f "$WORK/broken-$name" ]; then
		echo "FAIL: $name — $(cat "$WORK/broken-$name")"
		fail=$((fail + 1))
		return
	fi

	# A row can only be judged by cases that ran. The wget cases skip where
	# there is no usable wget; the baseline says whether they did.
	for want_case in $want_cases; do
		grep -q "^PASS: $want_case\$" "$WORK/baseline.out" && continue
		echo "SKIP: $name (its case $want_case did not run in the baseline)"
		skipped=$((skipped + 1))
		return
	done

	out="$WORK/out-$name"
	rc=$(cat "$WORK/rc-$name" 2>/dev/null || echo missing)

	ok=1
	# Other cases failing too is fine and expected — a mutation rarely breaks
	# exactly one behavior. What matters is that the named cases are among them.
	[ "$rc" != 0 ] ||
		{ ok=0; echo "  suite stayed green under the mutation — nothing pins this"; }
	for want_case in $want_cases; do
		grep -q "^FAIL: $want_case\$" "$out" ||
			{ ok=0; echo "  expected case '$want_case' to fail, but it did not"; }
	done

	if [ "$ok" -eq 1 ]; then
		echo "PASS: $name (caught by $want_cases)"
		pass=$((pass + 1))
	else
		echo "FAIL: $name (expected catch: $want_cases)"
		grep -E '^(PASS|FAIL|SKIP)' "$out" | sed 's/^/    /'
		fail=$((fail + 1))
	fi
}

# Read with a redirect (not a pipe) so the counters live in this shell.
running=0
while IFS='~' read -r m_name m_expr m_cases; do
	[ -n "$m_name" ] || continue
	case "$m_name" in \#*) continue ;; esac
	launch_mutant "$m_name" "$m_expr"
done <"$WORK/rows"
wait

while IFS='~' read -r m_name m_expr m_cases; do
	[ -n "$m_name" ] || continue
	case "$m_name" in \#*) continue ;; esac
	check_mutant "$m_name" "$m_cases"
done <"$WORK/rows"

echo
if [ "$skipped" -eq 0 ]; then
	echo "install.sh mutants: $pass caught, $fail missed"
else
	echo "install.sh mutants: $pass caught, $fail missed, $skipped skipped"
fi
[ "$fail" -eq 0 ]
