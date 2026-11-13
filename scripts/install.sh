#!/bin/sh
# fuz install script
#
# Intended one-liner (not hosted yet): curl -sSf https://www.fuz.dev/install.sh | sh
#
# Downloads the fuz binary for this platform, verifies its SHA512 digest, then
# hands off to `fuz self bootstrap` for the actual installation (artifact
# creation, symlinks, PATH setup).
#
# Trust model: HTTPS for first install; subsequent `fuz self upgrade` uses
# ed25519 signature verification against the public key embedded in fuz. The
# one-liner fetches this script from www.fuz.dev, not the release host, so with
# FUZ_RELEASE_LOG_URL set the check below catches a release host that tampers
# with the bytes. Nothing here holds against whoever can rewrite this script
# (docs/security-model.md § First Binary Bootstrap).
#
# Where the digest comes from decides what the first install is checked against:
#
# - By default it is the `.sha512` sidecar beside the binary, on the same host.
#   That catches a corrupted download. It says nothing about a compromised
#   host, which would replace the binary and its sidecar together.
# - With FUZ_RELEASE_LOG_URL set, it is the release log instead: a second
#   origin (a "witness") serves `latest/fuz-<target>.sha512`, one line naming
#   the release's versioned binary and its digest. The release host then
#   supplies only bytes, so it cannot alone substitute a binary or serve an
#   older release. The pointer is not signed — this is agreement between two
#   origins, not a signature check; `fuz self bootstrap`, which reads the same
#   variable, holds the binary to the log's signed head next.
#
# The release log read is active only when FUZ_RELEASE_LOG_URL is set: this
# script has no built-in origin, and no public release log exists. It needs
# curl; the default path also works with wget.
#
# Environment:
#   FUZ_INSTALL_BASE_URL  the release host (where the bytes come from)
#   FUZ_RELEASE_LOG_URL   release log origins, comma-separated, each an
#                         https:// URL or an existing local directory. The
#                         first one that can be reached is read; unset or
#                         empty, the release log is not read
#   FUZ_RELEASE_LOG       `off` skips the release log read (with a warning);
#                         any other value is an error
#
# Exit codes: 0 installed; 1 failed; 2 an unset, empty, or relative HOME, an
# unusable FUZ_RELEASE_LOG_URL / FUZ_RELEASE_LOG, or an argument `fuz self
# bootstrap` does not accept; 65 refused on integrity grounds (a checksum
# mismatch, the release log contradicting the download or recording no
# release) — fuz's code for bytes not to trust; 75 no release log origin
# could be reached (not a refusal — retry); 130 / 143 interrupted. Past the
# download, `fuz self bootstrap`'s own exit code passes through.

set -eu

BASE_URL="${FUZ_INSTALL_BASE_URL:-https://releases.fuz.dev}"
LOG_URLS="${FUZ_RELEASE_LOG_URL:-}"
LOG_SWITCH="${FUZ_RELEASE_LOG:-}"
MIN_KB=51200 # 50 MB
POINTER_MAX_BYTES=1024 # a pointer is one short line

# --- output helpers --------------------------------------------------------

info() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; }

# printable TEXT — TEXT as one line of printable ASCII, cut to 512 characters:
# every other byte (a control character, a newline, each byte of a non-ASCII
# character) becomes `?`. For text a server or a downloader chose, on its way
# into a message: nothing in it can drive the terminal or add a line.
#
# The set is the range space through `~`, not `[:print:]`: busybox `tr` has no
# such class and reads its letters as a list, so nearly every byte became `?`.
printable() {
	printf '%s' "$1" | LC_ALL=C tr -c ' -~' '?' | LC_ALL=C cut -c1-512
}

# --- platform detection ----------------------------------------------------

is_musl() {
	# is_musl ARCH — true on a Linux host whose libc is musl (Alpine and
	# similar), where the glibc binary this script would download cannot run.
	#
	# `ldd --version` names the libc on both: musl's ldd is its own loader and
	# says "musl libc", glibc's says "GNU libc" / "GLIBC". It answers first,
	# either way, because it is the libc speaking. Without an ldd that says
	# which (a busybox-only image can drop musl-utils), glibc's
	# `getconf GNU_LIBC_VERSION` is the other positive glibc signal, and the
	# musl loader at /lib/ld-musl-ARCH.so.1 is the musl one: it is the libc
	# itself, so no musl system lacks it. It is checked last because a glibc
	# host can carry it too (Debian's `musl` package installs it), and such a
	# host always has a glibc ldd that answers before it.
	#
	# Undetermined reads as glibc: a wrong refusal would block a host fuz
	# supports, with no way past it, while a wrong pass only gets as far as a
	# digest-verified binary that fails to start at `self bootstrap`.
	if command -v ldd >/dev/null 2>&1; then
		_ldd=$(ldd --version 2>&1) || : # musl's ldd exits 1 on --version
		case "$_ldd" in
			*musl*) return 0 ;;
			*GLIBC* | *"GNU libc"* | *glibc*) return 1 ;;
		esac
	fi
	getconf GNU_LIBC_VERSION >/dev/null 2>&1 && return 1
	[ -e "/lib/ld-musl-$1.so.1" ]
}

detect_target() {
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	arch=$(uname -m)
	case "$arch" in
		arm64) arch="aarch64" ;;
		amd64) arch="x86_64" ;;
	esac

	case "$os" in
		linux)
			case "$arch" in
				x86_64 | aarch64) ;;
				*) return 1 ;;
			esac
			# Refused here, before anything is downloaded: the glibc binary
			# would verify and then fail at `self bootstrap` with a loader error.
			if is_musl "$arch"; then
				err "this host's libc is musl (Alpine or similar), and fuz has no musl build yet"
				err "the $arch-unknown-linux-gnu binary needs glibc and cannot run here; nothing was downloaded"
				err "use fuz on a glibc host or container (Debian, Ubuntu, Fedora, ...), or build from source: https://github.com/fuzdev/fuz"
				err "platform status: docs/platform_support.md in that repository"
				return 2
			fi
			echo "$arch-unknown-linux-gnu"
			;;
		darwin)
			case "$arch" in
				x86_64)  echo "x86_64-apple-darwin" ;;
				aarch64) echo "aarch64-apple-darwin" ;;
				*) return 1 ;;
			esac
			;;
		mingw*|msys*|cygwin*)
			err "Windows is not supported. Use WSL: https://learn.microsoft.com/windows/wsl/"
			return 2
			;;
		*)
			return 1
			;;
	esac
}

# --- download --------------------------------------------------------------

download() {
	# download URL OUTPUT ERR_FILE
	# Captures the downloader's stderr to ERR_FILE so callers can print
	# the underlying network/tool error when the download fails — much
	# better than the generic "check your network" fallback alone.
	#
	# Retries a few times on *transient* failures (connection refused,
	# timeouts, 429/5xx) so a flaky network doesn't abort the one-liner. A
	# genuine 404 is not retried — curl only retries transient HTTP codes,
	# and wget stops on 4xx — so a missing binary still fails fast.
	#
	# With curl, `http_code` is left holding the final HTTP status (`000` when
	# there was none): `curl -f` exits 22 for a 404 and a 503 alike, and the
	# release log read has to tell them apart.
	_url=$1
	_out=$2
	_err=$3
	if command -v curl >/dev/null 2>&1; then
		http_code=$(curl -fsSL --proto '=https' --tlsv1.2 \
			--retry 3 --retry-connrefused --retry-delay 1 \
			-w '%{http_code}' -o "$_out" "$_url" 2>"$_err")
	elif command -v wget >/dev/null 2>&1; then
		# --https-only governs only recursive retrieval; --max-redirect=0 is what
		# keeps a release-host redirect (to http, or anywhere) from being followed.
		wget --https-only --max-redirect=0 --tries=3 --waitretry=1 -qO "$_out" "$_url" 2>"$_err"
	else
		err "neither curl nor wget is available; install one of them and re-run"
		exit 1
	fi
}

show_download_error() {
	# Indent the downloader's own message; usually has a useful HTTP code or DNS
	# error. It can repeat what the server sent (a status line, a redirect
	# target), so each line is printed as printable ASCII.
	if [ -s "$temp_err" ]; then
		while IFS= read -r line; do err "  $(printable "$line")"; done <"$temp_err"
	fi
}

# --- checksum --------------------------------------------------------------

compute_sha512() {
	# compute_sha512 FILE
	#
	# Read via stdin rather than passing the path: GNU coreutils escapes a
	# filename containing a backslash or newline and marks the line by
	# prefixing the *hash* with a backslash, so `cut -f1` would yield a
	# corrupt digest and the compare below would report a bogus "tampered
	# with". TMPDIR is user-supplied (the disk-space hint even tells you to set
	# it), so that path is reachable. Reading stdin prints "<hash>  -" — no
	# filename, nothing to escape.
	if command -v sha512sum >/dev/null 2>&1; then
		sha512sum <"$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 512 <"$1" | cut -d' ' -f1
	else
		err "no SHA512 tool found (need sha512sum or shasum)"
		exit 1
	fi
}

is_sha512_hex() {
	# is_sha512_hex DIGEST
	#
	# The digest must be exactly 128 hexadecimal characters. Validating the
	# charset (not just the length) means a corrupt-but-128-char digest fails
	# here as "malformed" instead of as a confusing mismatch against the real
	# digest later. The case glob matches when any byte is outside
	# [0-9a-fA-F]; an empty string matches no glob char, so it's the length
	# test that rejects that.
	case "$1" in
		*[!0-9a-fA-F]*) return 1 ;;
	esac
	[ "${#1}" -eq 128 ]
}

# --- disk space ------------------------------------------------------------

check_disk_space() {
	tmpdir=${TMPDIR:-/tmp}
	# POSIX-compliant df -P: column 4 is "Available 1024-blocks"
	free=$(df -P "$tmpdir" 2>/dev/null | awk 'NR==2 {print $4}')
	if [ -z "$free" ]; then
		# Couldn't determine; skip the check (df is not available everywhere)
		return 0
	fi
	if [ "$free" -lt "$MIN_KB" ]; then
		err "not enough space in $tmpdir (need ${MIN_KB} KB, have ${free} KB)"
		err "re-run with TMPDIR set to a directory with more free space"
		exit 1
	fi
}

# --- release log -----------------------------------------------------------
#
# The two variables are read as the `fuz` binary reads them, so the script and
# the `fuz self bootstrap` it hands off to agree on whether a release log is
# configured. The binary verifies the signed head from every origin; this
# reads one origin's unsigned pointer.

for_each_origin() {
	# for_each_origin FN — calls `FN POSITION ENTRY` for each entry of
	# FUZ_RELEASE_LOG_URL in order until one returns 0; returns 1 when none
	# did. Entries are trimmed and empty ones skipped, so POSITION counts the
	# non-empty entries. Split by parameter expansion, never by word-splitting:
	# an entry may hold spaces or glob characters.
	origins_left=$LOG_URLS
	origin_pos=0
	while [ -n "$origins_left" ]; do
		origin=${origins_left%%,*}
		case "$origins_left" in
			*,*) origins_left=${origins_left#*,} ;;
			*) origins_left= ;;
		esac
		while :; do
			case "$origin" in
				[[:space:]]*) origin=${origin#?} ;;
				*[[:space:]]) origin=${origin%?} ;;
				*) break ;;
			esac
		done
		[ -n "$origin" ] || continue
		origin_pos=$((origin_pos + 1))
		"$1" "$origin_pos" "$origin" && return 0
	done
	return 1
}

parse_origin() {
	# parse_origin ENTRY — sets `origin_kind` (https | dir) and `origin_loc`
	# (the URL without trailing slashes, or the directory); returns 1 when the
	# entry is not an origin this script can read.
	origin_loc=$1
	case "$origin_loc" in
		https://*)
			origin_kind=https
			_rest=${origin_loc#https://}
			while :; do
				case "$_rest" in
					*/) _rest=${_rest%/} ;;
					*) break ;;
				esac
			done
			origin_loc="https://$_rest"
			# A host, and no credentials, query, or fragment — nor anything
			# curl would read as a glob, which rules out an IPv6 literal.
			case "$_rest" in
				"" | /* | *[!A-Za-z0-9._~:/%+=-]*) return 1 ;;
			esac
			;;
		file://*)
			origin_kind=dir
			origin_loc=${origin_loc#file://}
			;;
		# http:// (loopback too: every request here is https), forge://,
		# ssh://, and anything else with a scheme.
		*://*) return 1 ;;
		*) origin_kind=dir ;;
	esac
	if [ "$origin_kind" = dir ]; then
		case "$origin_loc" in
			"~") origin_loc=$HOME ;;
			"~/"*) origin_loc=$HOME/${origin_loc#"~/"} ;;
		esac
		# Must already exist: a mistyped path is a configuration error, not an
		# origin that happens to be unreachable. Nothing is created.
		[ -d "$origin_loc" ] || return 1
	fi
}

# shellcheck disable=SC2317  # invoked indirectly via for_each_origin
check_origin() {
	# check_origin POSITION ENTRY — exits 2 unless ENTRY is a usable origin.
	# The entry is never shown: a URL can carry a secret.
	parse_origin "$2" && return 1
	err "FUZ_RELEASE_LOG_URL entry $1 is not usable (counting non-empty entries; not shown, since a URL can carry a secret)"
	err "a release log origin is an https:// URL or an existing local directory"
	err "fix the entry, or set FUZ_RELEASE_LOG=off to install without the release log"
	exit 2
}

resolve_log_mode() {
	# Sets `log_mode`: inactive (no origin configured), off (opted out), or
	# witness. Makes no request. The switch is a closed set — unset, empty, or
	# exactly `off` — whatever the origin list holds, so a typo never reads as
	# on or as off. Under `off` the list is not parsed: the opt-out has to work
	# when the list itself is what is broken.
	case "$LOG_SWITCH" in
		"" | off) ;;
		*)
			err "FUZ_RELEASE_LOG is set to something other than 'off', its only value"
			err "unset it to keep the release log check, or set it to exactly 'off' to skip it"
			exit 2
			;;
	esac
	log_mode=inactive
	case "$LOG_URLS" in
		*[!,[:space:]]*) ;;
		*) return 0 ;; # nothing but separators
	esac
	if [ "$LOG_SWITCH" = off ]; then
		warn "FUZ_RELEASE_LOG=off: the release log check is off; verifying against the release host's own checksum only"
		log_mode=off
		return 0
	fi
	# Every entry is validated before the first request.
	for_each_origin check_origin || :
	# wget cannot do this read: it has no way to report the HTTP status.
	if ! command -v curl >/dev/null 2>&1; then
		err "reading the release log needs curl, which is not available"
		err "install curl, or set FUZ_RELEASE_LOG=off to install without the release log"
		exit 1
	fi
	log_mode=witness
}

pointer_absent() {
	# pointer_absent POSITION — the origin answered, and has no pointer.
	err "the release log has no release for $target (origin $1 answered, and has no pointer for this platform)"
	err "the release host may be serving a release its publisher never logged; nothing was installed"
	exit 65
}

pointer_malformed() {
	err "release log pointer is malformed (origin $origin_pos did not serve one '<sha512>  fuz-<version>-$target' line)"
	err "nothing was installed; a retry is unlikely to help — report at https://github.com/fuzdev/fuz/issues"
	exit 1
}

# shellcheck disable=SC2317  # invoked indirectly via for_each_origin
read_origin() {
	# read_origin POSITION ENTRY — returns 0 with `pointer` naming the file
	# that holds the origin's answer, or 1 when the origin is unreachable, the
	# only outcome that moves on to the next origin. An origin that answers is
	# final: the script never shops for a better answer.
	#
	# Unreachable is the `fuz` binary's class — no HTTP answer, any HTTP status
	# that is not success, a local file that cannot be read — except that
	# 404 / 410 (or no such local file) is a refusal here. The downloader's own
	# message is never shown, since it can repeat the URL.
	if ! parse_origin "$2"; then
		# Validated before the first request: a directory removed since.
		warn "release log origin $1 is unreachable (no longer a directory)"
		return 1
	fi
	_name="latest/fuz-$target.sha512"
	if [ "$origin_kind" = dir ]; then
		pointer="$origin_loc/$_name"
		if [ -f "$pointer" ] && [ -r "$pointer" ]; then
			return 0
		fi
		if [ -e "$pointer" ] || [ -L "$pointer" ]; then
			warn "release log origin $1 is unreachable (its pointer is not a readable file)"
			return 1
		fi
		pointer_absent "$1"
	fi
	pointer=$temp_ptr
	# No earlier origin's partial answer can be read as this one's.
	rm -f "$pointer"
	download "$origin_loc/$_name" "$pointer" "$temp_err" && return 0
	_rc=$?
	case "$http_code" in
		404 | 410) pointer_absent "$1" ;;
		[1345][0-9][0-9])
			warn "release log origin $1 is unreachable (HTTP $http_code)"
			return 1
			;;
	esac
	# No error status. Unreachable only when curl's exit code says the network
	# failed: 5 / 6 name resolution, 7 connect, 28 timeout, 35 / 60 TLS,
	# 52 / 55 / 56 the connection dropped. Anything else — a URL curl cannot
	# use, a local write error, a signal — says nothing about the origin, so
	# it must not read as "retry later".
	case "$_rc" in
		5 | 6 | 7 | 28 | 35 | 52 | 55 | 56 | 60)
			warn "release log origin $1 is unreachable (no response)"
			return 1
			;;
	esac
	err "release log origin $1 could not be read (curl exit $_rc); nothing was installed"
	exit 1
}

read_release_log() {
	# Sets `expected` (lowercase digest), `fname` (the versioned binary's name
	# on the release host), and `version`, from the first reachable origin.
	#
	# The pointer is untrusted until checked: read with `read -r`, only ever
	# expanded quoted, and printed only after validation.
	info "reading the release log for $target..."
	if ! for_each_origin read_origin; then
		err "no release log origin could be reached, so this release cannot be confirmed yet"
		err "this is not a refusal, and nothing was installed: check your network and retry"
		exit 75
	fi

	# A response with no body (a 304) leaves no file at all.
	[ -f "$pointer" ] || pointer_malformed
	[ "$(($(wc -c <"$pointer")))" -le "$POINTER_MAX_BYTES" ] || pointer_malformed

	# Exactly one newline-terminated line, the shape the publisher writes.
	# `read` returns nonzero at end of input, so the first read fails on an
	# empty file or an unterminated line, and the second must find nothing —
	# neither another line nor the start of one. The line is read whole
	# (`IFS=`), then split at its first two spaces: `<digest>  <name>`, the
	# sidecar format. Any other separator — one space, a tab, a third space,
	# leading or trailing whitespace — leaves a space or tab in the digest or
	# the name, which the checks below refuse.
	line=
	extra=
	shape_ok=1
	{
		IFS= read -r line || shape_ok=0
		if IFS= read -r extra || [ -n "$extra" ]; then shape_ok=0; fi
	} <"$pointer"
	[ "$shape_ok" -eq 1 ] || pointer_malformed
	expected=${line%%"  "*}
	fname=${line#*"  "}
	is_sha512_hex "$expected" || pointer_malformed

	# The name becomes part of a URL and of what is printed, so it must be the
	# versioned binary for this target and nothing else: `fuz-<version>-<target>`
	# with a version that is not the moving `latest`, in the release-token
	# charset (no `/`, `+`, whitespace, or control character — a CRLF pointer's
	# CR fails here), and no `..`.
	case "$fname" in
		"fuz-"*"-$target") ;;
		*) pointer_malformed ;;
	esac
	version=${fname#fuz-}
	version=${version%"-$target"}
	[ -n "$version" ] || pointer_malformed
	[ "$version" = latest ] && pointer_malformed
	case "$fname" in *[!A-Za-z0-9._-]*) pointer_malformed ;; esac
	case "$fname" in *..*) pointer_malformed ;; esac

	expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
}

# --- main ------------------------------------------------------------------

main() {
	# fuz bootstrap installs into ~/.fuz/; fail fast if HOME isn't usable (the
	# binary refuses an empty or relative HOME too, but only after the download).
	case "${HOME:-}" in
		/*) ;;
		'')
			err "\$HOME is not set; fuz needs it to install into ~/.fuz/"
			exit 2
			;;
		*)
			err "\$HOME is not an absolute path; fuz needs one to install into ~/.fuz/"
			exit 2
			;;
	esac

	check_disk_space

	target=$(detect_target) || {
		case "$?" in
			2) exit 1 ;; # Windows / musl message already printed
			*)
				err "unsupported platform: $(uname -s) $(uname -m)"
				err "fuz is published for:"
				err "  linux  x86_64, aarch64 (glibc)"
				err "planned, not yet published:"
				err "  darwin x86_64, aarch64"
				err "to use fuz on another platform, build from source: https://github.com/fuzdev/fuz"
				exit 1
				;;
		esac
	}

	resolve_log_mode

	# One private directory for everything downloaded: no file in it has a
	# name another local user could create first.
	temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/fuz.XXXXXX") || {
		err "failed to create temp file in ${TMPDIR:-/tmp}"
		exit 1
	}
	temp_bin="$temp_dir/fuz"
	temp_sha="$temp_dir/sidecar"
	temp_ptr="$temp_dir/pointer"
	temp_err="$temp_dir/err"

	# shellcheck disable=SC2317  # invoked indirectly via trap
	cleanup() {
		rm -rf "$temp_dir"
	}
	# A signal ends the install: cleanup alone would let the script carry on
	# past the download the signal interrupted.
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	if [ "$log_mode" = witness ]; then
		# The release log names the versioned binary and its digest; the
		# release host supplies bytes only — neither its `fuz-latest-*` nor
		# its sidecar is read.
		read_release_log
		bin_url="$BASE_URL/$fname"
		info "downloading fuz $version for $target..."
	else
		bin_url="$BASE_URL/fuz-latest-$target"
		sha_url="$bin_url.sha512"
		info "downloading fuz for $target..."
	fi

	download "$bin_url" "$temp_bin" "$temp_err" || {
		err "failed to download $bin_url"
		show_download_error
		err "check your network connection and that $BASE_URL is reachable"
		exit 1
	}

	if [ "$log_mode" != witness ]; then
		download "$sha_url" "$temp_sha" "$temp_err" || {
			err "failed to download $sha_url"
			show_download_error
			# The binary itself downloaded fine (above), so this is not a missing or
			# unsupported target — the checksum sidecar beside it is absent.
			err "the checksum sidecar is missing, so the download can't be verified"
			err "the release may be mid-publish, or the host may serve an older layout"
			err "if you host these bytes yourself, republish so each binary has a .sha512 beside it"
			exit 1
		}

		# sidecar format: "<hash>  <filename>\n" — first whitespace field is the hash.
		# Lowercased because hex case carries no information but the compare below is
		# a string match: an uppercase digest passes the well-formed check and would
		# then be reported as "tampered with" despite being the same value. The
		# byte-source is pluggable, so a self-hoster's sidecar needn't match our
		# producer's casing. (`tr` is already required by detect_target.)
		expected=$(cut -d' ' -f1 <"$temp_sha" | tr 'A-F' 'a-f')

		if ! is_sha512_hex "$expected"; then
			# The sidecar is whatever the release host served.
			err "sha512 sidecar is malformed: expected 128 hex chars, got '$(printable "$expected")'"
			err "the release may be mid-publish; wait a minute and retry"
			exit 1
		fi
	fi

	actual=$(compute_sha512 "$temp_bin")

	if [ "$expected" != "$actual" ]; then
		if [ "$log_mode" = witness ]; then
			# Two origins disagree. Not a corrupted download to retry: either
			# the release host is serving bytes the publisher never logged, or
			# the log is wrong.
			err "REFUSED: the downloaded binary is not the release the release log records"
			err "  release log, fuz $version for $target: $expected"
			err "  $bin_url: $actual"
			err "the release host and the release log contradict each other; nothing was installed"
			err "do not work around this — report privately: https://github.com/fuzdev/fuz/security/policy"
			exit 65
		fi
		err "checksum mismatch — download may be corrupted or tampered with"
		err "  expected: $expected"
		err "  actual:   $actual"
		# The binary and its sidecar are two uploads, so a publish in progress
		# can serve a new binary beside the old digest for a moment.
		err "the release may be mid-publish: retry the install in a minute"
		err "if the mismatch persists, report privately: https://github.com/fuzdev/fuz/security/policy"
		exit 65
	fi

	chmod +x "$temp_bin"

	if [ "$log_mode" = witness ]; then
		info "verified fuz $version against the release log — running bootstrap..."
	else
		info "verified — running bootstrap..."
	fi
	# Hand off to fuz self bootstrap, which creates the artifact directory,
	# sets up symlinks, and modifies the user's shell rc file. The
	# downloaded binary stays in $temp_bin until cleanup; bootstrap
	# atomically creates ~/.fuz/artifacts/v1-<hash>/ from its own bytes,
	# so a previous fuz install (if any) is unaffected by a bootstrap failure.
	# The environment passes through untouched, so bootstrap's own release log
	# check sees the same FUZ_RELEASE_LOG_URL / FUZ_RELEASE_LOG.
	# Pass through any args the user (or pipe-to-sh wrapper) provided.
	"$temp_bin" self bootstrap "$@"
}

main "$@"
