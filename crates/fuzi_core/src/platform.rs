//! Platform axes (`os` / `cpu` / `libc`) and host detection.
//!
//! npm constrains a package to platforms via per-entry `os`/`cpu`/`libc`
//! arrays. fuzi maps both the npm tokens and the Rust host constants into the
//! same enums, then matches per-axis. Host detection (`Platform::current`)
//! runs once — the libc probe (`/usr/bin/ldd`, else the loader) is the only
//! filesystem IO in plan building besides the lockfile and manifest reads.

use crate::entry::RegistryEntry;

/// An operating-system axis token (npm `os` values + host translation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Os {
    /// `linux`.
    Linux,
    /// `darwin` (macOS).
    Darwin,
    /// `win32` (Windows).
    Win32,
    /// `freebsd`.
    Freebsd,
    /// `openbsd`.
    Openbsd,
    /// `netbsd`.
    Netbsd,
    /// `dragonfly`.
    Dragonfly,
    /// `sunos` (Solaris / illumos).
    Sunos,
    /// `android`.
    Android,
    /// `aix`.
    Aix,
    /// An unrecognized token, kept verbatim — only ever matches the host on
    /// exact equality.
    Other(String),
}

impl Os {
    /// Parse an npm `os` array token.
    #[must_use]
    pub fn from_npm(token: &str) -> Self {
        match token {
            "linux" => Self::Linux,
            "darwin" => Self::Darwin,
            "win32" => Self::Win32,
            "freebsd" => Self::Freebsd,
            "openbsd" => Self::Openbsd,
            "netbsd" => Self::Netbsd,
            "dragonfly" => Self::Dragonfly,
            "sunos" => Self::Sunos,
            "android" => Self::Android,
            "aix" => Self::Aix,
            other => Self::Other(other.to_string()),
        }
    }

    /// Translate a Rust `std::env::consts::OS` value into the npm-token enum.
    #[must_use]
    pub fn from_rust(rust_os: &str) -> Self {
        match rust_os {
            "linux" => Self::Linux,
            "macos" => Self::Darwin,
            "windows" => Self::Win32,
            "freebsd" => Self::Freebsd,
            "openbsd" => Self::Openbsd,
            "netbsd" => Self::Netbsd,
            "dragonfly" => Self::Dragonfly,
            "solaris" | "illumos" => Self::Sunos,
            "android" => Self::Android,
            "aix" => Self::Aix,
            other => Self::Other(other.to_string()),
        }
    }
}

/// A CPU-architecture axis token (npm `cpu` values + host translation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cpu {
    /// `x64`.
    X64,
    /// `arm64`.
    Arm64,
    /// `ia32`.
    Ia32,
    /// `arm`.
    Arm,
    /// `ppc64`.
    Ppc64,
    /// `s390x`.
    S390x,
    /// `riscv64`.
    Riscv64,
    /// `mips`.
    Mips,
    /// `mips64`.
    Mips64,
    /// `loong64`.
    Loong64,
    /// An unrecognized token, kept verbatim — only matches on exact equality.
    Other(String),
}

impl Cpu {
    /// Parse an npm `cpu` array token.
    #[must_use]
    pub fn from_npm(token: &str) -> Self {
        match token {
            "x64" => Self::X64,
            "arm64" => Self::Arm64,
            "ia32" => Self::Ia32,
            "arm" => Self::Arm,
            "ppc64" => Self::Ppc64,
            "s390x" => Self::S390x,
            "riscv64" => Self::Riscv64,
            "mips" => Self::Mips,
            "mips64" => Self::Mips64,
            "loong64" => Self::Loong64,
            other => Self::Other(other.to_string()),
        }
    }

    /// Translate a Rust `std::env::consts::ARCH` value into the npm-token enum.
    #[must_use]
    pub fn from_rust(rust_arch: &str) -> Self {
        match rust_arch {
            "x86_64" => Self::X64,
            "aarch64" => Self::Arm64,
            "x86" => Self::Ia32,
            "arm" => Self::Arm,
            "powerpc64" => Self::Ppc64,
            "s390x" => Self::S390x,
            "riscv64" => Self::Riscv64,
            "mips" => Self::Mips,
            "mips64" => Self::Mips64,
            "loongarch64" => Self::Loong64,
            other => Self::Other(other.to_string()),
        }
    }
}

/// A C-library axis token.
///
/// `Unrecognized` is a never-match sentinel for a declared libc token that is
/// neither `glibc` nor `musl` (the fuz projects' own lockfiles only ever carry
/// those two). The host (`Platform::current`) never produces `Unrecognized`, so
/// a declared `Unrecognized` positive can never equal the host — the safe
/// never-match outcome, never coerced to glibc/musl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Libc {
    /// `glibc`.
    Glibc,
    /// `musl`.
    Musl,
    /// A declared token other than `glibc`/`musl` — never matches the host.
    Unrecognized,
}

impl Libc {
    /// Parse an npm `libc` array token. Returns `None` for any token other
    /// than `glibc`/`musl`; the caller models that as a never-match axis token
    /// (`Libc::Unrecognized`), never coerced to glibc/musl.
    #[must_use]
    pub fn from_npm(token: &str) -> Option<Self> {
        match token {
            "glibc" => Some(Self::Glibc),
            "musl" => Some(Self::Musl),
            _ => None,
        }
    }
}

/// The detected host platform. `libc` is `None` on non-Linux hosts and on
/// Linux hosts whose libc evidence was unclear or mixed — in both cases that
/// means "no libc filter," NOT "matches nothing".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    /// Host operating system.
    pub os: Os,
    /// Host CPU architecture.
    pub cpu: Cpu,
    /// Host C library (Linux only; `None` = no filter).
    pub libc: Option<Libc>,
}

impl Platform {
    /// Detect the current host. Translates the Rust target constants into npm
    /// tokens, then probes the libc once (Linux only: `ldd`, else the dynamic
    /// loader). The libc detection warning, if any, is discarded — use [`detect`](Self::detect)
    /// to capture it for the report.
    #[must_use]
    pub fn current() -> Self {
        Self::detect().0
    }

    /// Like [`current`](Self::current) but also returns the libc-probe warning
    /// (Linux, unclear or mixed evidence), so the caller can surface it on the
    /// [`InstallReport`](crate::InstallReport) — the library itself prints nothing.
    #[must_use]
    pub fn detect() -> (Self, Option<String>) {
        let (libc, warning) = probe_libc();
        (
            Self {
                os: Os::from_rust(std::env::consts::OS),
                cpu: Cpu::from_rust(std::env::consts::ARCH),
                libc,
            },
            warning,
        )
    }

    /// True iff the host satisfies every declared axis of `entry`.
    ///
    /// An axis the entry does not declare imposes no filter.
    #[must_use]
    pub fn matches(&self, entry: &RegistryEntry) -> bool {
        self.matches_axes(&entry.os, &entry.cpu, &entry.libc)
    }

    /// The axis-by-axis core of [`matches`](Self::matches), taking already-parsed
    /// token slices rather than a whole [`RegistryEntry`].
    ///
    /// A registry entry reaches it through [`matches`](Self::matches); a link
    /// target, which never becomes a `RegistryEntry`, through `classify`'s link
    /// arm with its parsed `os`/`cpu`/`libc` tokens; and the `prune`
    /// reachability walk through [`accepts_raw`](Self::accepts_raw), which
    /// parses an entry's raw tokens first. So the shared predicate lives here
    /// as the single source of axis-match truth.
    #[must_use]
    pub fn matches_axes(
        &self,
        os: &[PlatformToken<Os>],
        cpu: &[PlatformToken<Cpu>],
        libc: &[PlatformToken<Libc>],
    ) -> bool {
        axis_ok(&self.os, os) && axis_ok(&self.cpu, cpu) && libc_ok(self.libc, libc)
    }

    /// Os+cpu match only, ignoring libc — "does this host *expect* a binary of
    /// this shape?" Used by `fuzi verify` to tell a genuinely off-host optional
    /// (e.g. darwin-only `fsevents` on Linux — no os/cpu match, correctly
    /// absent) apart from a wrong-libc lock (os+cpu match but the libc-matching
    /// variant is missing — a real failure). The full [`matches`](Self::matches)
    /// still gates *installation*; this only scopes the verify assertion.
    #[must_use]
    pub fn matches_os_cpu(&self, os: &[PlatformToken<Os>], cpu: &[PlatformToken<Cpu>]) -> bool {
        axis_ok(&self.os, os) && axis_ok(&self.cpu, cpu)
    }

    /// The raw-axis front door to [`matches_axes`](Self::matches_axes): parse an
    /// entry's raw `os`/`cpu`/`libc` token arrays, then match the host against
    /// all three.
    ///
    /// A token that fails to parse (empty / double-`!` / `!any` — malformed, and
    /// refused loudly upstream by `classify`) makes the whole entry read as **not
    /// a match** (`false`), the conservative not-installable arm: a malformed
    /// token must never be silently taken as a match. Callers that already hold
    /// parsed [`PlatformToken`] slices use [`matches_axes`](Self::matches_axes)
    /// directly.
    #[must_use]
    pub fn accepts_raw(&self, os: &[String], cpu: &[String], libc: &[String]) -> bool {
        let (Ok(os), Ok(cpu), Ok(libc)) = (
            parse_os_axis(os),
            parse_cpu_axis(cpu),
            parse_libc_axis(libc),
        ) else {
            return false;
        };
        self.matches_axes(&os, &cpu, &libc)
    }

    /// The os+cpu-only raw-axis front door to
    /// [`matches_os_cpu`](Self::matches_os_cpu): parse an entry's raw `os`/`cpu`
    /// token arrays (libc deliberately *not* consulted) to answer "does this host
    /// *expect* a binary of this shape?".
    ///
    /// Like [`accepts_raw`](Self::accepts_raw), a malformed token yields `false`
    /// (the conservative arm — never silently a match). Used by `fuzi verify` to
    /// scope its platform assertion to host-expected variants; installation stays
    /// gated by the full [`accepts_raw`](Self::accepts_raw).
    #[must_use]
    pub fn expects_os_cpu_raw(&self, os: &[String], cpu: &[String]) -> bool {
        let (Ok(os), Ok(cpu)) = (parse_os_axis(os), parse_cpu_axis(cpu)) else {
            return false;
        };
        self.matches_os_cpu(&os, &cpu)
    }
}

/// One parsed platform-axis token.
///
/// `x` requires the host to equal `x`; `!x` excludes the host `x`. npm's `any`
/// is not a token: it is special only as an axis's **sole** entry (`["any"]`),
/// which the axis parsers read as no filter at all — an empty axis. In a list
/// with other tokens `any` is a literal name no host has, exactly as
/// `npm-install-checks`' `checkList` treats it. The combinations a raw token
/// could spell but that are meaningless — `!any`, an empty token, a
/// double-leading-`!` (`!!x`) — are refuse-loud parse errors
/// (`RefuseReason::MalformedPlatformToken`), never a guess, so they are
/// unrepresentable here rather than excluded by a runtime guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformToken<T> {
    /// A positive token `x` — matches iff the host equals `x`.
    Is(T),
    /// A negated token `!x` — excludes the host `x`.
    Not(T),
}

/// Parse one raw axis token into a `PlatformToken` via `map`.
/// Returns `Err(())` for an empty, double-`!` (`!!x`), or `!any` token
/// (refuse-loud — never silently no-op). A bare `any` maps like any other
/// name; the sole-`any` axis never reaches here (see [`parse_axis`]).
fn parse_token<T>(raw: &str, map: impl FnOnce(&str) -> T) -> Result<PlatformToken<T>, ()> {
    if raw.is_empty() {
        return Err(());
    }
    let (negated, rest) = raw.strip_prefix('!').map_or((false, raw), |r| (true, r));
    if rest.is_empty() || rest.starts_with('!') {
        return Err(()); // empty after `!`, or double-`!`
    }
    if negated && rest == "any" {
        // npm reads `!any` as excluding a platform named "any" — a no-op that
        // only a confused lockfile writes. Refuse rather than silently no-op.
        return Err(());
    }
    let token = map(rest);
    Ok(if negated {
        PlatformToken::Not(token)
    } else {
        PlatformToken::Is(token)
    })
}

/// Parse a raw axis with `map`: a sole `any` is no filter (an empty axis);
/// otherwise every token is parsed, `any` among them as a plain name.
fn parse_axis<T>(raw: &[String], map: impl Fn(&str) -> T) -> Result<Vec<PlatformToken<T>>, String> {
    if let [only] = raw
        && only == "any"
    {
        return Ok(Vec::new());
    }
    raw.iter()
        .map(|t| parse_token(t, &map).map_err(|()| t.clone()))
        .collect()
}

/// Parse an npm `os` array into platform tokens, or `Err` on a malformed
/// token (the offending raw string).
///
/// # Errors
///
/// Returns the offending raw token string if any token is empty,
/// double-negated, or `!any`.
pub fn parse_os_axis(raw: &[String]) -> Result<Vec<PlatformToken<Os>>, String> {
    parse_axis(raw, Os::from_npm)
}

/// Parse an npm `cpu` array into platform tokens.
///
/// # Errors
///
/// Returns the offending raw token string on a malformed token.
pub fn parse_cpu_axis(raw: &[String]) -> Result<Vec<PlatformToken<Cpu>>, String> {
    parse_axis(raw, Cpu::from_npm)
}

/// Parse an npm `libc` array into platform tokens.
///
/// Shares the generic grammar (negation / sole `any` / refuse-loud on
/// malformed); the only libc-specific part is the value mapping — a recognized
/// token maps directly, and an unrecognized one (not `glibc`/`musl`, a
/// non-sole `any` included) becomes the never-match `Libc::Unrecognized`
/// sentinel, a positive the host can never equal, never coerced to a real
/// libc.
///
/// # Errors
///
/// Returns the offending raw token string on an empty, double-negated, or
/// `!any` token.
pub fn parse_libc_axis(raw: &[String]) -> Result<Vec<PlatformToken<Libc>>, String> {
    parse_axis(raw, |s| Libc::from_npm(s).unwrap_or(Libc::Unrecognized))
}

/// One axis. Empty `declared` means no filter (matches everything).
///
/// npm-exact semantics: `(no positives OR host ∈ positives) AND host ∉ negatives`.
fn axis_ok<T: PartialEq>(host: &T, declared: &[PlatformToken<T>]) -> bool {
    if declared.is_empty() {
        return true;
    }
    let in_neg = declared
        .iter()
        .any(|t| matches!(t, PlatformToken::Not(x) if x == host));
    let has_positive = declared.iter().any(|t| matches!(t, PlatformToken::Is(_)));
    let host_in_positive = declared
        .iter()
        .any(|t| matches!(t, PlatformToken::Is(x) if x == host));
    let pos_ok = !has_positive || host_in_positive;
    pos_ok && !in_neg
}

/// libc axis. A host `None` (non-Linux or undetected) imposes no filter and
/// matches any libc-declared package — the deliberate superset arm, NOT
/// match-nothing.
fn libc_ok(host: Option<Libc>, declared: &[PlatformToken<Libc>]) -> bool {
    if declared.is_empty() {
        return true;
    }
    host.is_none_or(|h| axis_ok(&h, declared))
}

/// glibc dynamic-loader basenames across supported architectures.
#[cfg(target_os = "linux")]
const GLIBC_LOADERS: &[&str] = &[
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
    "ld-linux.so.2",
    "ld-linux-armhf.so.3",
    "ld-linux-riscv64-lp64d.so.1",
    "ld64.so.2", // ppc64le
    "ld64.so.1", // s390x
];

/// Bare loader directories (non-multiarch layouts), **root-relative** so
/// `root.join(dir)` nests under the probe root (see [`probe_libc_at`] for why
/// the leading `/` must stay off).
#[cfg(target_os = "linux")]
const BARE_DIRS: &[&str] = &["lib64", "lib", "usr/lib"];

/// Parents of Debian/Ubuntu multiarch loader directories (`<arch>-linux-gnu`),
/// root-relative (see [`probe_libc_at`]).
#[cfg(target_os = "linux")]
const MULTIARCH_PARENTS: &[&str] = &["lib", "usr/lib"];

/// Directories scanned for the musl loader (`ld-musl-<arch>.so.1`),
/// root-relative (see [`probe_libc_at`]).
#[cfg(target_os = "linux")]
const MUSL_DIRS: &[&str] = &["lib", "usr/lib"];

/// The `ldd` script npm reads first, root-relative (see [`probe_libc_at`]).
#[cfg(target_os = "linux")]
const LDD_PATH: &str = "usr/bin/ldd";

/// How much of `ldd` is read. glibc's and musl's are a few KiB of shell; the
/// cap bounds the read of an oversized regular file. A non-regular file (a
/// FIFO, a device) is never read at all — see [`read_ldd`].
#[cfg(target_os = "linux")]
const LDD_READ_CAP: u64 = 64 * 1024;

/// Detect the host libc, returning the detected libc (`None` = no filter) and
/// an optional detection warning for the caller to surface on the
/// [`InstallReport`](crate::InstallReport).
///
/// Thin wrapper over [`probe_libc_at`] rooted at the real filesystem root; the
/// detection rules and rationale live there.
#[cfg(target_os = "linux")]
fn probe_libc() -> (Option<Libc>, Option<String>) {
    probe_libc_at(std::path::Path::new("/"))
}

/// [`probe_libc`]'s core, with every lookup rooted under `root`. The real
/// probe passes `/`; tests pass a tempdir holding a fake layout — the crate's
/// only libc-detection seam.
///
/// The order is npm's (`npm-install-checks`' `libc()`), so the same evidence
/// is consulted first. fuzi parts from npm only where the evidence is
/// unclear: npm reads an `ldd` naming both as musl, and a readable `ldd`
/// naming neither as no libc.
///
/// 1. **`/usr/bin/ldd`'s contents**, when the file can be read: naming `musl`
///    means musl, naming `GNU C Library` means glibc. A glibc host with the
///    Debian `musl` package installed carries a stray `ld-musl-*` loader but a
///    glibc `ldd`, so reading `ldd` first gets it right.
/// 2. **The dynamic loader**, only when there is no readable `ldd` (a minimal
///    or distroless image): an `ld-musl-<arch>.so.1` means musl, a glibc
///    loader or a multiarch `libc.so.6` means glibc. npm asks node's process
///    report here instead (which libc the running node loaded). fuzi has no
///    node, so it reads the loaders on disk, weaker evidence that can show
///    both.
///
/// **Unclear or mixed evidence never picks a side.** An `ldd` naming neither
/// libc or both, both loaders present (a gcompat shim beside musl, or a stray
/// musl beside glibc), or nothing found (a static or scratch image) all yield
/// `None` — no libc filter, which installs the superset (both `-gnu` and
/// `-musl`) — plus a warning. The superset always holds the host's real
/// variant and the wrong one sits unloaded, so it never under-installs; a
/// guess could. (npm instead refuses every libc-declaring package when it
/// cannot tell — the deliberate arm fuzi does not share.) Nothing downstream
/// re-checks a confident answer: `fuzi verify` probes with this same
/// detector, so a wrong confident answer would pass verify too — which is why
/// only unambiguous evidence gives one.
///
/// **Join gotcha:** `BARE_DIRS` / `MULTIARCH_PARENTS` / `MUSL_DIRS` /
/// `LDD_PATH` are root-relative (`"lib"`, not `"/lib"`) on purpose —
/// `Path::join` REPLACES the base when handed an absolute argument, so
/// `root.join("/lib")` would yield `/lib` and silently probe the real
/// filesystem, defeating the seam. Keep the leading slash off so
/// `root.join(dir)` stays under `root`.
#[cfg(target_os = "linux")]
fn probe_libc_at(root: &std::path::Path) -> (Option<Libc>, Option<String>) {
    let (musl, glibc, source) = read_ldd(&root.join(LDD_PATH)).map_or_else(
        || {
            (
                has_musl_loader(root),
                has_glibc_loader(root),
                "no /usr/bin/ldd, and the loaders found are",
            )
        },
        |ldd| {
            (
                contains_bytes(&ldd, b"musl"),
                contains_bytes(&ldd, b"GNU C Library"),
                "/usr/bin/ldd names",
            )
        },
    );
    let unclear = |evidence: &str| {
        Some(format!(
            "could not detect libc ({source} {evidence}); treating libc as unconstrained — install may be a superset"
        ))
    };
    match (musl, glibc) {
        (true, false) => (Some(Libc::Musl), None),
        (false, true) => (Some(Libc::Glibc), None),
        (true, true) => (None, unclear("both musl and glibc")),
        (false, false) => (None, unclear("neither musl nor glibc")),
    }
}

/// Read up to [`LDD_READ_CAP`] bytes of `ldd`, or `None` when it is not a
/// regular file (absent, a directory, a FIFO or device) or cannot be read.
/// Absent, a directory, or unreadable are the cases npm also falls through to
/// its second source on; a FIFO or device is fuzi's own skip, where npm's
/// unbounded read would block or stream.
///
/// Opened with [`fuz_sys::secure_file::open_regular_nonblocking`], following
/// symlinks: `O_NONBLOCK` keeps the open from waiting on a FIFO with no writer,
/// and the regular-file check runs on the open descriptor, so a FIFO or a
/// device (which can stream without end) is refused before any read — and
/// nothing can swap the path between the check and the read.
#[cfg(target_os = "linux")]
fn read_ldd(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let (file, _) = fuz_sys::secure_file::open_regular_nonblocking(path).ok()?;
    let mut bytes = Vec::new();
    file.take(LDD_READ_CAP).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// True iff `haystack` contains `needle` (byte-wise; `ldd` need not be UTF-8).
#[cfg(target_os = "linux")]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True iff any `ld-musl-<arch>.so.1` sits in a [`MUSL_DIRS`] directory.
#[cfg(target_os = "linux")]
fn has_musl_loader(root: &std::path::Path) -> bool {
    MUSL_DIRS
        .iter()
        .any(|d| dir_has_match(&root.join(d), "ld-musl-", ".so.1"))
}

/// True iff a glibc loader sits in a bare loader directory, or a glibc loader
/// or `libc.so.6` in a `<arch>-linux-gnu` multiarch directory.
#[cfg(target_os = "linux")]
fn has_glibc_loader(root: &std::path::Path) -> bool {
    let bare = BARE_DIRS.iter().any(|dir| {
        GLIBC_LOADERS
            .iter()
            .any(|loader| root.join(dir).join(loader).exists())
    });
    bare || MULTIARCH_PARENTS.iter().any(|parent| {
        std::fs::read_dir(root.join(parent)).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                let sub = entry.path();
                entry.file_name().to_string_lossy().contains("-linux-gnu")
                    && (sub.join("libc.so.6").exists()
                        || GLIBC_LOADERS.iter().any(|loader| sub.join(loader).exists()))
            })
        })
    })
}

/// Non-Linux hosts carry no libc filter (and no warning).
#[cfg(not(target_os = "linux"))]
fn probe_libc() -> (Option<Libc>, Option<String>) {
    (None, None)
}

/// True if `dir` contains a file whose name starts with `prefix` and ends with
/// `suffix`.
#[cfg(target_os = "linux")]
fn dir_has_match(dir: &std::path::Path, prefix: &str, suffix: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        name.starts_with(prefix) && name.ends_with(suffix)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- C: Rust -> npm token mapping ---

    #[test]
    fn os_from_rust_clean_and_renamed() {
        assert_eq!(Os::from_rust("linux"), Os::Linux);
        assert_eq!(Os::from_rust("macos"), Os::Darwin);
        assert_eq!(Os::from_rust("windows"), Os::Win32);
        assert_eq!(Os::from_rust("freebsd"), Os::Freebsd);
        assert_eq!(Os::from_rust("solaris"), Os::Sunos);
        assert_eq!(Os::from_rust("illumos"), Os::Sunos);
        assert_eq!(Os::from_rust("android"), Os::Android);
        assert_eq!(Os::from_rust("aix"), Os::Aix);
    }

    #[test]
    fn cpu_from_rust_clean_and_renamed() {
        assert_eq!(Cpu::from_rust("x86_64"), Cpu::X64);
        assert_eq!(Cpu::from_rust("aarch64"), Cpu::Arm64);
        assert_eq!(Cpu::from_rust("x86"), Cpu::Ia32);
        assert_eq!(Cpu::from_rust("powerpc64"), Cpu::Ppc64);
        assert_eq!(Cpu::from_rust("loongarch64"), Cpu::Loong64);
        assert_eq!(Cpu::from_rust("riscv64"), Cpu::Riscv64);
    }

    #[test]
    fn unknown_host_tokens_are_other() {
        assert_eq!(Os::from_rust("haiku"), Os::Other("haiku".to_string()));
        assert_eq!(Cpu::from_rust("sparc64"), Cpu::Other("sparc64".to_string()));
    }

    #[test]
    fn libc_from_npm_only_known_tokens() {
        assert_eq!(Libc::from_npm("glibc"), Some(Libc::Glibc));
        assert_eq!(Libc::from_npm("musl"), Some(Libc::Musl));
        assert_eq!(Libc::from_npm("bionic"), None);
    }

    // --- E: axis predicate ---

    fn pos<T>(token: T) -> PlatformToken<T> {
        PlatformToken::Is(token)
    }

    fn neg<T>(token: T) -> PlatformToken<T> {
        PlatformToken::Not(token)
    }

    #[test]
    fn empty_axis_matches() {
        assert!(axis_ok(&Os::Linux, &[]));
    }

    #[test]
    fn single_positive() {
        assert!(axis_ok(&Os::Linux, &[pos(Os::Linux)]));
        assert!(!axis_ok(&Os::Win32, &[pos(Os::Linux)]));
    }

    #[test]
    fn multi_positive() {
        let declared = [pos(Cpu::X64), pos(Cpu::Arm64)];
        assert!(axis_ok(&Cpu::X64, &declared));
        assert!(axis_ok(&Cpu::Arm64, &declared));
        assert!(!axis_ok(&Cpu::Ia32, &declared));
    }

    #[test]
    fn negation_only() {
        let declared = [neg(Os::Win32)];
        assert!(axis_ok(&Os::Linux, &declared));
        assert!(!axis_ok(&Os::Win32, &declared));
    }

    #[test]
    fn mixed_positive_negative() {
        let declared = [pos(Os::Linux), neg(Os::Android)];
        assert!(axis_ok(&Os::Linux, &declared));
        assert!(!axis_ok(&Os::Android, &declared));
    }

    #[test]
    fn host_in_neither_positive_nor_negative_excluded() {
        // A declared positive set the host isn't in: excluded even without a negation.
        let declared = [pos(Os::Linux), neg(Os::Android)];
        assert!(!axis_ok(&Os::Win32, &declared));
    }

    #[test]
    fn negation_precedence_over_positive() {
        // `[x, !x]` in one axis: the negation wins, host excluded.
        let declared = [pos(Os::Linux), neg(Os::Linux)];
        assert!(!axis_ok(&Os::Linux, &declared));
    }

    #[test]
    fn libc_glibc_filter() {
        let declared = [pos(Libc::Glibc)];
        assert!(libc_ok(Some(Libc::Glibc), &declared));
        assert!(!libc_ok(Some(Libc::Musl), &declared));
        assert!(libc_ok(None, &declared)); // host None = no filter
    }

    #[test]
    fn libc_musl_host_none_matches() {
        let declared = [pos(Libc::Musl)];
        assert!(libc_ok(None, &declared));
    }

    // --- token parsing ---

    #[test]
    fn os_axis_parses_negation() {
        let parsed = parse_os_axis(&["linux".into(), "!win32".into()]).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(matches!(parsed[0], PlatformToken::Is(Os::Linux)));
        assert!(matches!(parsed[1], PlatformToken::Not(Os::Win32)));
    }

    #[test]
    fn sole_any_is_no_filter() {
        // `["any"]` is npm's open allowlist: an empty axis, matching every host.
        assert!(parse_os_axis(&["any".into()]).unwrap().is_empty());
        assert!(parse_libc_axis(&["any".into()]).unwrap().is_empty());
        let host = crate::test_support::host_linux_x64_glibc();
        assert!(host.accepts_raw(&["any".into()], &["any".into()], &["any".into()]));
    }

    #[test]
    fn any_in_a_mixed_list_is_a_literal_that_never_matches() {
        // npm's `checkList` special-cases `any` only as the sole entry; beside
        // other tokens it is the literal name "any", which no host has.
        let parsed = parse_os_axis(&["any".into(), "darwin".into()]).unwrap();
        assert_eq!(
            parsed,
            vec![pos(Os::Other("any".to_string())), pos(Os::Darwin)]
        );
        let host = crate::test_support::host_linux_x64_glibc();
        assert!(!host.accepts_raw(&["any".into(), "darwin".into()], &[], &[]));
        assert!(!host.accepts_raw(&[], &["any".into(), "arm64".into()], &[]));
        assert!(!host.accepts_raw(&[], &[], &["any".into(), "musl".into()]));
        // A negation beside it still excludes only what it names: the literal
        // `any` positive is what fails a non-`any` host here.
        assert!(!host.accepts_raw(&["any".into(), "!win32".into()], &[], &[]));
        assert!(host.accepts_raw(&["linux".into(), "any".into()], &[], &[]));
    }

    #[test]
    fn os_axis_double_negation_refused() {
        assert!(parse_os_axis(&["!!win32".into()]).is_err());
    }

    #[test]
    fn os_axis_empty_token_refused() {
        assert!(parse_os_axis(&[String::new()]).is_err());
    }

    #[test]
    fn libc_axis_unrecognized_is_never_match() {
        let parsed = parse_libc_axis(&["bionic".into()]).unwrap();
        assert!(matches!(parsed[0], PlatformToken::Is(Libc::Unrecognized)));
    }

    #[test]
    fn os_axis_negated_any_refused() {
        // `!any` is a representable-but-meaningless token — refuse, don't no-op.
        assert!(parse_os_axis(&["!any".into()]).is_err());
    }

    #[test]
    fn libc_axis_negated_any_refused() {
        assert!(parse_libc_axis(&["!any".into()]).is_err());
    }

    // --- raw-axis front doors: accepts_raw / expects_os_cpu_raw ---

    #[test]
    fn accepts_raw_matches_host_entry() {
        let host = crate::test_support::host_linux_x64_glibc();
        assert!(host.accepts_raw(&["linux".into()], &["x64".into()], &["glibc".into()]));
    }

    #[test]
    fn accepts_raw_rejects_mismatched_entry() {
        // Wrong cpu — no match on a linux/x64 host.
        let host = crate::test_support::host_linux_x64_glibc();
        assert!(!host.accepts_raw(&["linux".into()], &["arm64".into()], &[]));
    }

    #[test]
    fn accepts_raw_false_on_malformed_token() {
        // A malformed token (`!!x`) must read as not-a-match, never a silent match.
        let host = crate::test_support::host_linux_x64_glibc();
        assert!(!host.accepts_raw(&["!!x".into()], &[], &[]));
    }

    #[test]
    fn expects_os_cpu_raw_matches_and_ignores_libc() {
        // Same os+cpu, wrong libc: the full `accepts_raw` fails on the libc
        // mismatch, but `expects_os_cpu_raw` consults os+cpu only, so the host
        // still *expects* a binary of this shape.
        let host = crate::test_support::host_linux_x64_glibc();
        assert!(!host.accepts_raw(&["linux".into()], &["x64".into()], &["musl".into()]));
        assert!(host.expects_os_cpu_raw(&["linux".into()], &["x64".into()]));
    }

    #[test]
    fn expects_os_cpu_raw_false_on_malformed_token() {
        let host = crate::test_support::host_linux_x64_glibc();
        assert!(!host.expects_os_cpu_raw(&["!!x".into()], &["x64".into()]));
    }

    // --- libc probe (the root-injectable seam) ---
    //
    // Every probe test roots `probe_libc_at` at a tempdir with a fake layout,
    // so nothing here touches the real `/`. The `probe_none_*` test is the
    // guard on the absolute-join gotcha: the real host `/` always carries an
    // `ldd` or a loader, so an empty root yielding anything but `None` would
    // prove the probe leaked to the real filesystem.

    /// Create a file at `root/rel` holding `contents`, making parent dirs as
    /// needed.
    #[cfg(target_os = "linux")]
    fn write(root: &std::path::Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
    }

    /// Create an empty file at `root/rel`.
    #[cfg(target_os = "linux")]
    fn touch(root: &std::path::Path, rel: &str) {
        write(root, rel, "");
    }

    /// The head of glibc's `ldd` script, as Debian ships it.
    #[cfg(target_os = "linux")]
    const GLIBC_LDD: &str = "#!/bin/bash\n# Copyright (C) 1996-2025 Free Software Foundation, Inc.\n# This file is part of the GNU C Library.\n";

    /// Alpine's whole `ldd`.
    #[cfg(target_os = "linux")]
    const MUSL_LDD: &str = "#!/bin/sh\nexec /lib/ld-musl-x86_64.so.1 --list \"$@\"\n";

    /// The evidence source an unclear probe names: a readable `ldd`, or the
    /// loaders when there is none.
    #[cfg(target_os = "linux")]
    const FROM_LDD: &str = "/usr/bin/ldd names";
    #[cfg(target_os = "linux")]
    const FROM_LOADERS: &str = "no /usr/bin/ldd, and the loaders found are";

    /// Unclear evidence yields no libc and a warning naming the source it read
    /// (`source`) and what that source showed (`evidence`).
    #[cfg(target_os = "linux")]
    fn assert_unclear(root: &std::path::Path, source: &str, evidence: &str) {
        let (libc, warning) = probe_libc_at(root);
        assert_eq!(libc, None);
        assert_eq!(
            warning.as_deref(),
            Some(
                format!(
                    "could not detect libc ({source} {evidence}); treating libc as unconstrained — install may be a superset"
                )
                .as_str()
            ),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_reads_glibc_from_ldd() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "usr/bin/ldd", GLIBC_LDD);
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Glibc), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_reads_musl_from_ldd() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "usr/bin/ldd", MUSL_LDD);
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Musl), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_glibc_ldd_outranks_a_stray_musl_loader() {
        // A glibc host with Debian's `musl` package: a real `ld-musl-*` loader
        // beside glibc's. `ldd` is read first, so it is glibc — the loader-first
        // probe read this host as musl and skipped its `-gnu` binaries.
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "usr/bin/ldd", GLIBC_LDD);
        touch(root.path(), "lib/ld-musl-x86_64.so.1");
        touch(root.path(), "lib64/ld-linux-x86-64.so.2");
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Glibc), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_ldd_naming_neither_or_both_is_unclear() {
        // Neither name: npm reads `null`; fuzi installs the superset and warns,
        // and does not fall through to the loaders (a readable `ldd` decides).
        let neither = tempfile::tempdir().unwrap();
        write(neither.path(), "usr/bin/ldd", "#!/bin/sh\necho hi\n");
        touch(neither.path(), "lib64/ld-linux-x86-64.so.2");
        assert_unclear(neither.path(), FROM_LDD, "neither musl nor glibc");

        let both = tempfile::tempdir().unwrap();
        write(
            both.path(),
            "usr/bin/ldd",
            &format!("{GLIBC_LDD}{MUSL_LDD}"),
        );
        assert_unclear(both.path(), FROM_LDD, "both musl and glibc");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_unreadable_ldd_falls_through_to_the_loader() {
        // An `ldd` that cannot be read as a file is treated as absent, as npm's
        // `catch` does.
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin/ldd")).unwrap();
        touch(root.path(), "lib64/ld-linux-x86-64.so.2");
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Glibc), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_fifo_ldd_falls_through_without_blocking() {
        // Opening a FIFO with no writer blocks forever; the probe must open
        // `ldd` without blocking and skip a non-regular one before reading. Run
        // on a thread with a deadline so a regression fails instead of hanging
        // the suite.
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        nix::unistd::mkfifo(
            &root.path().join("usr/bin/ldd"),
            nix::sys::stat::Mode::S_IRWXU,
        )
        .unwrap();
        touch(root.path(), "lib64/ld-linux-x86-64.so.2");
        let (tx, rx) = std::sync::mpsc::channel();
        let path = root.path().to_path_buf();
        std::thread::spawn(move || tx.send(probe_libc_at(&path)).unwrap());
        let probed = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("probe blocked on a FIFO ldd");
        assert_eq!(probed, (Some(Libc::Glibc), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_detects_musl_loader() {
        let root = tempfile::tempdir().unwrap();
        touch(root.path(), "lib/ld-musl-x86_64.so.1");
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Musl), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_detects_musl_loader_under_usr_lib() {
        let root = tempfile::tempdir().unwrap();
        touch(root.path(), "usr/lib/ld-musl-aarch64.so.1");
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Musl), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_detects_glibc_bare_loader() {
        let root = tempfile::tempdir().unwrap();
        touch(root.path(), "lib64/ld-linux-x86-64.so.2");
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Glibc), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_detects_glibc_via_multiarch_libc_so() {
        // Debian/Ubuntu layout: no bare loader, only the multiarch
        // <root>/lib/<arch>-linux-gnu/libc.so.6 — exercises the parent-scan
        // fallback and its `-linux-gnu` dir-name predicate.
        let root = tempfile::tempdir().unwrap();
        touch(root.path(), "lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Glibc), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_detects_glibc_via_multiarch_loader_basename() {
        // The multiarch parent-scan's second branch: a `<arch>-linux-gnu` subdir
        // carrying a `GLIBC_LOADERS` basename but NO `libc.so.6`.
        let root = tempfile::tempdir().unwrap();
        touch(root.path(), "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
        assert_eq!(probe_libc_at(root.path()), (Some(Libc::Glibc), None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_none_and_warns_when_no_loader() {
        // Empty root: no ldd, no loader -> unconstrained + a rendered warning.
        // Also the rooting guard (see the module note above).
        let root = tempfile::tempdir().unwrap();
        assert_unclear(root.path(), FROM_LOADERS, "neither musl nor glibc");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_both_loaders_without_ldd_is_unclear() {
        // A gcompat shim beside musl, or a stray musl beside glibc: with no
        // `ldd` to settle it, neither side is picked — the superset, warned.
        let root = tempfile::tempdir().unwrap();
        touch(root.path(), "lib/ld-musl-x86_64.so.1");
        touch(root.path(), "lib64/ld-linux-x86-64.so.2");
        assert_unclear(root.path(), FROM_LOADERS, "both musl and glibc");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dir_has_match_requires_prefix_and_suffix() {
        // The predicate needs BOTH ends: a musl-prefixed name with the wrong
        // suffix, or a `.so.1`-suffixed name with the wrong prefix, is not a
        // match — and a missing dir is `false`, never an error.
        let root = tempfile::tempdir().unwrap();
        let d = root.path();
        touch(d, "ld-musl-x86_64.so.1"); // both ends
        touch(d, "ld-musl-x86_64.so"); // prefix only (no `.1`)
        touch(d, "libz.so.1"); // suffix only
        assert!(dir_has_match(d, "ld-musl-", ".so.1"));
        assert!(!dir_has_match(d, "ld-musl-", ".notasuffix"));
        assert!(!dir_has_match(d, "no-such-prefix-", ".so.1"));
        assert!(!dir_has_match(
            &d.join("does-not-exist"),
            "ld-musl-",
            ".so.1"
        ));
    }
}
