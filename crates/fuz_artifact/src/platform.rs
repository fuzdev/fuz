//! Release targets, and what a binary's own header says it is for.
//!
//! A release's `target` names its manifest, storage keys, tarball, release
//! log row, and the flat files `install.sh` downloads — but it is the
//! publisher's *assertion*. [`inspect_binary`] reads what the bytes say
//! instead: the executable format, the architecture, and for ELF the dynamic
//! loader (`PT_INTERP`), which names the libc the binary needs.
//! [`check_binary_target`] holds the two to each other, so a release labelled
//! for one platform cannot carry a binary built for another — the producers
//! refuse to publish one, and `fuz` refuses to install one.
//!
//! The supported targets are a closed set ([`ReleaseTarget::ALL`]): `x86_64`
//! and `aarch64` Linux on glibc or musl, and `x86_64` and `aarch64` macOS. The
//! parser
//! is hand-rolled over std and reads a bounded prefix of the file
//! ([`INSPECT_PREFIX_LEN`]); a header, program header table, or interpreter
//! path outside it is refused as malformed rather than read further.

use std::fmt;
use std::str::FromStr;

use fuz_sys::text::{quoted, truncate};

/// How much of a binary [`inspect_binary`] reads: the first 64 KiB.
///
/// Every header it consults — the ELF header, the program header table, the
/// `PT_INTERP` path, the Mach-O header — sits at the front of a linked
/// executable, far inside it.
pub const INSPECT_PREFIX_LEN: usize = 64 * 1024;

/// Longest interpreter path shown in an error, in bytes.
const MAX_SHOWN_INTERP_LEN: usize = 128;

//
// Targets
//

/// A CPU architecture a release can target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    /// `x86_64` (ELF `EM_X86_64`, Mach-O `CPU_TYPE_X86_64`).
    X86_64,
    /// `aarch64` (ELF `EM_AARCH64`, Mach-O `CPU_TYPE_ARM64`).
    Aarch64,
}

impl Arch {
    /// The architecture as a target triple spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The C library a Linux target links against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Libc {
    /// glibc (`*-unknown-linux-gnu`).
    Gnu,
    /// musl (`*-unknown-linux-musl`).
    Musl,
}

impl Libc {
    /// The libc as a target triple's environment spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gnu => "gnu",
            Self::Musl => "musl",
        }
    }

    /// The libc's name in prose.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gnu => "glibc",
            Self::Musl => "musl",
        }
    }
}

/// The operating system of a target; Linux carries its libc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetOs {
    /// Linux, on the given libc.
    Linux(Libc),
    /// macOS.
    Darwin,
}

/// A target a release can be published for: one of the closed set in
/// [`ReleaseTarget::ALL`], parsed from its triple ([`FromStr`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReleaseTarget {
    arch: Arch,
    os: TargetOs,
}

impl ReleaseTarget {
    /// Every supported target, in the order an error lists them.
    pub const ALL: [Self; 6] = [
        Self::linux(Arch::X86_64, Libc::Gnu),
        Self::linux(Arch::Aarch64, Libc::Gnu),
        Self::linux(Arch::X86_64, Libc::Musl),
        Self::linux(Arch::Aarch64, Libc::Musl),
        Self::darwin(Arch::X86_64),
        Self::darwin(Arch::Aarch64),
    ];

    /// The Linux target for `arch` on `libc`.
    #[must_use]
    pub const fn linux(arch: Arch, libc: Libc) -> Self {
        Self {
            arch,
            os: TargetOs::Linux(libc),
        }
    }

    /// The macOS target for `arch`.
    #[must_use]
    pub const fn darwin(arch: Arch) -> Self {
        Self {
            arch,
            os: TargetOs::Darwin,
        }
    }

    /// The target's architecture.
    #[must_use]
    pub const fn arch(self) -> Arch {
        self.arch
    }

    /// The target's operating system.
    #[must_use]
    pub const fn os(self) -> TargetOs {
        self.os
    }

    /// The target's libc: `Some` for Linux, `None` for macOS.
    #[must_use]
    pub const fn libc(self) -> Option<Libc> {
        match self.os {
            TargetOs::Linux(libc) => Some(libc),
            TargetOs::Darwin => None,
        }
    }

    /// The target triple (`x86_64-unknown-linux-gnu`).
    #[must_use]
    pub const fn triple(self) -> &'static str {
        match (self.arch, self.os) {
            (Arch::X86_64, TargetOs::Linux(Libc::Gnu)) => "x86_64-unknown-linux-gnu",
            (Arch::Aarch64, TargetOs::Linux(Libc::Gnu)) => "aarch64-unknown-linux-gnu",
            (Arch::X86_64, TargetOs::Linux(Libc::Musl)) => "x86_64-unknown-linux-musl",
            (Arch::Aarch64, TargetOs::Linux(Libc::Musl)) => "aarch64-unknown-linux-musl",
            (Arch::X86_64, TargetOs::Darwin) => "x86_64-apple-darwin",
            (Arch::Aarch64, TargetOs::Darwin) => "aarch64-apple-darwin",
        }
    }

    /// Every supported triple, comma-separated, for a message.
    #[must_use]
    pub fn supported_list() -> String {
        Self::ALL.map(Self::triple).join(", ")
    }
}

impl fmt::Display for ReleaseTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.triple())
    }
}

/// A target triple outside the supported set ([`ReleaseTarget::ALL`]).
///
/// Carries the text as given — a flag's value or a build's triple — and shows
/// it bounded and escaped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unsupported release target {}: supported are {}",
    quoted(&truncate(.0, crate::MAX_RELEASE_TOKEN_LEN)),
    ReleaseTarget::supported_list()
)]
pub struct UnsupportedTarget(pub String);

impl FromStr for ReleaseTarget {
    type Err = UnsupportedTarget;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|target| target.triple() == s)
            .ok_or_else(|| UnsupportedTarget(s.to_string()))
    }
}

//
// What a binary is
//

/// How an ELF executable is linked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linkage {
    /// Dynamically linked: its `PT_INTERP` names this libc's loader.
    Dynamic(Libc),
    /// Statically linked: no `PT_INTERP` (`ET_EXEC`, or `ET_DYN` for a
    /// static-pie). The header does not say which libc was linked in.
    Static,
}

/// The platform a binary's own header declares ([`inspect_binary`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryPlatform {
    /// A 64-bit little-endian ELF executable: a Linux binary.
    Elf {
        /// Its `e_machine`.
        arch: Arch,
        /// Its loader, or none.
        linkage: Linkage,
    },
    /// A 64-bit Mach-O executable (`MH_MAGIC_64`): a macOS binary.
    MachO {
        /// Its `cputype`.
        arch: Arch,
    },
}

impl BinaryPlatform {
    /// The binary's architecture.
    #[must_use]
    pub const fn arch(self) -> Arch {
        match self {
            Self::Elf { arch, .. } | Self::MachO { arch } => arch,
        }
    }

    /// The one target the header names, or `None` for a static ELF, whose
    /// header does not say which libc it was linked against.
    #[must_use]
    pub const fn target(self) -> Option<ReleaseTarget> {
        match self {
            Self::Elf {
                arch,
                linkage: Linkage::Dynamic(libc),
            } => Some(ReleaseTarget::linux(arch, libc)),
            Self::Elf {
                linkage: Linkage::Static,
                ..
            } => None,
            Self::MachO { arch } => Some(ReleaseTarget::darwin(arch)),
        }
    }
}

impl fmt::Display for BinaryPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf {
                arch,
                linkage: Linkage::Dynamic(libc),
            } => write!(
                f,
                "an {arch} Linux executable dynamically linked against {} ({})",
                libc.name(),
                ReleaseTarget::linux(*arch, *libc)
            ),
            Self::Elf {
                arch,
                linkage: Linkage::Static,
            } => write!(f, "a statically linked {arch} Linux executable"),
            Self::MachO { arch } => write!(
                f,
                "an {arch} macOS executable ({})",
                ReleaseTarget::darwin(*arch)
            ),
        }
    }
}

/// Why [`inspect_binary`] refused a file: it is not a 64-bit little-endian
/// ELF or Mach-O executable for a supported architecture, or its headers do
/// not hold together within [`INSPECT_PREFIX_LEN`].
///
/// The interpreter path is the file's own bytes and is shown bounded and
/// escaped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BinaryFormatError {
    /// Neither an ELF nor a Mach-O magic.
    #[error("not an ELF or Mach-O executable")]
    NotABinary,
    /// A 32-bit ELF (`ELFCLASS32`) or an unknown class.
    #[error("not a 64-bit ELF (EI_CLASS {0})")]
    ElfClass(u8),
    /// A big-endian ELF (`ELFDATA2MSB`) or an unknown data encoding.
    #[error("not a little-endian ELF (EI_DATA {0})")]
    ElfEncoding(u8),
    /// An ELF that is not an executable (`ET_EXEC`) or position-independent
    /// executable (`ET_DYN`): a relocatable object, a core file, ….
    #[error("not an ELF executable (e_type {0})")]
    ElfType(u16),
    /// An `ET_DYN` ELF with no `PT_INTERP` and no entry point: a shared
    /// library, not a static-pie executable.
    #[error("a shared library, not an executable (ET_DYN with no interpreter and no entry point)")]
    ElfSharedLibrary,
    /// An ELF for an architecture outside the supported set.
    #[error("an ELF for an unsupported machine (e_machine {0}; supported: x86_64, aarch64)")]
    ElfMachine(u16),
    /// The ELF's headers are truncated, out of range, or contradictory.
    #[error("malformed ELF: {0}")]
    ElfMalformed(&'static str),
    /// A `PT_INTERP` that names no loader of a supported target.
    #[error("unrecognized ELF interpreter {}", quoted(&truncate(.0, MAX_SHOWN_INTERP_LEN)))]
    UnknownInterpreter(String),
    /// A `PT_INTERP` naming another architecture's loader than `e_machine`.
    #[error(
        "ELF interpreter {} is not {arch}'s, the binary's machine",
        quoted(&truncate(.interpreter, MAX_SHOWN_INTERP_LEN))
    )]
    InterpreterArch {
        /// The `PT_INTERP` path.
        interpreter: String,
        /// The binary's `e_machine`.
        arch: Arch,
    },
    /// A universal (fat) Mach-O — one file for several architectures — or
    /// another file under the same magic (`CA FE BA BE` is also a Java class
    /// file's), in either byte order.
    #[error(
        "a universal (fat) Mach-O or other non-executable; publish one binary per architecture"
    )]
    MachOFat,
    /// A 32-bit or big-endian Mach-O.
    #[error("not a 64-bit little-endian Mach-O")]
    MachOLayout,
    /// A Mach-O for an architecture outside the supported set.
    #[error("a Mach-O for an unsupported CPU (cputype {0:#x}; supported: x86_64, arm64)")]
    MachOCpu(u32),
    /// A Mach-O that is not an executable (`MH_EXECUTE`).
    #[error("not a Mach-O executable (filetype {0})")]
    MachOFileType(u32),
    /// The Mach-O header is cut short.
    #[error("malformed Mach-O: truncated header")]
    MachOTruncated,
}

//
// Inspection
//

const ELF_MAGIC: [u8; 4] = *b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const PT_INTERP: u32 = 3;
const ELF64_EHDR_LEN: usize = 64;
const ELF64_PHDR_LEN: usize = 56;
/// `e_phnum`'s escape value: the real count is in section header 0.
const PN_XNUM: u16 = 0xffff;

const MH_MAGIC_64: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
const MH_MAGIC_64_BE: [u8; 4] = [0xfe, 0xed, 0xfa, 0xcf];
const MH_MAGIC: [u8; 4] = [0xce, 0xfa, 0xed, 0xfe];
const MH_MAGIC_BE: [u8; 4] = [0xfe, 0xed, 0xfa, 0xce];
const FAT_MAGIC: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
const FAT_MAGIC_64: [u8; 4] = [0xca, 0xfe, 0xba, 0xbf];
const FAT_CIGAM: [u8; 4] = [0xbe, 0xba, 0xfe, 0xca];
const FAT_CIGAM_64: [u8; 4] = [0xbf, 0xba, 0xfe, 0xca];
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const MH_EXECUTE: u32 = 2;
const MACHO64_HEADER_LEN: usize = 32;

/// Read what a binary's header says it is for.
///
/// `bytes` is the file or its first [`INSPECT_PREFIX_LEN`] bytes; anything
/// past that is ignored, so a header, program header table, or interpreter
/// path beyond it is refused as malformed. The rules:
///
/// - **ELF**: 64-bit and little-endian, `e_type` `ET_EXEC` or `ET_DYN`,
///   `e_machine` `x86_64` (62) or `aarch64` (183). A `PT_INTERP` of
///   `ld-linux-x86-64.so.2` / `ld-linux-aarch64.so.1` is a glibc dynamic
///   binary, `ld-musl-<arch>.so.1` a musl one (matched on the path's last
///   component), and its architecture must be `e_machine`'s. No `PT_INTERP`
///   is a static binary (`ET_EXEC`, or `ET_DYN` for a static-pie); an `ET_DYN`
///   with neither a `PT_INTERP` nor an entry point is a shared library and is
///   refused.
/// - **Mach-O**: `MH_MAGIC_64` (`CF FA ED FE`), `MH_EXECUTE`, `cputype`
///   `x86_64` or `arm64`. A universal (fat) file is refused.
///
/// # Errors
///
/// [`BinaryFormatError`] naming the first rule the file breaks.
pub fn inspect_binary(bytes: &[u8]) -> Result<BinaryPlatform, BinaryFormatError> {
    let bytes = &bytes[..bytes.len().min(INSPECT_PREFIX_LEN)];
    match bytes.get(..4) {
        Some(magic) if magic == ELF_MAGIC => inspect_elf(bytes),
        Some(magic) if magic == MH_MAGIC_64 => inspect_macho(bytes),
        Some(magic)
            if [FAT_MAGIC, FAT_MAGIC_64, FAT_CIGAM, FAT_CIGAM_64]
                .iter()
                .any(|fat| magic == fat) =>
        {
            Err(BinaryFormatError::MachOFat)
        }
        Some(magic) if magic == MH_MAGIC || magic == MH_MAGIC_BE || magic == MH_MAGIC_64_BE => {
            Err(BinaryFormatError::MachOLayout)
        }
        _ => Err(BinaryFormatError::NotABinary),
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at.checked_add(2)?)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at.checked_add(4)?)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let b = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// A `u64` offset or size as a `usize` index into the prefix, or `None` when
/// it cannot be one.
fn to_index(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}

fn inspect_elf(bytes: &[u8]) -> Result<BinaryPlatform, BinaryFormatError> {
    use BinaryFormatError::ElfMalformed;
    if bytes.len() < ELF64_EHDR_LEN {
        // The class and encoding are refused first when they are there to
        // read, so a short 32-bit file reads as 32-bit.
        if let Some(&class) = bytes.get(4)
            && class != ELFCLASS64
        {
            return Err(BinaryFormatError::ElfClass(class));
        }
        return Err(ElfMalformed("truncated ELF header"));
    }
    let class = bytes[4];
    if class != ELFCLASS64 {
        return Err(BinaryFormatError::ElfClass(class));
    }
    let encoding = bytes[5];
    if encoding != ELFDATA2LSB {
        return Err(BinaryFormatError::ElfEncoding(encoding));
    }
    let e_type = read_u16(bytes, 16).ok_or(ElfMalformed("truncated ELF header"))?;
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(BinaryFormatError::ElfType(e_type));
    }
    let machine = read_u16(bytes, 18).ok_or(ElfMalformed("truncated ELF header"))?;
    let arch = match machine {
        EM_X86_64 => Arch::X86_64,
        EM_AARCH64 => Arch::Aarch64,
        other => return Err(BinaryFormatError::ElfMachine(other)),
    };

    let phoff = read_u64(bytes, 32).ok_or(ElfMalformed("truncated ELF header"))?;
    let phentsize = read_u16(bytes, 54).ok_or(ElfMalformed("truncated ELF header"))?;
    let phnum = read_u16(bytes, 56).ok_or(ElfMalformed("truncated ELF header"))?;
    if phnum == 0 {
        return Err(ElfMalformed("no program headers"));
    }
    if phnum == PN_XNUM {
        return Err(ElfMalformed("program header count overflows e_phnum"));
    }
    if usize::from(phentsize) != ELF64_PHDR_LEN {
        return Err(ElfMalformed("program header entry size is not 56"));
    }
    let table_start = to_index(phoff).ok_or(ElfMalformed("program headers out of range"))?;
    let table_end = usize::from(phnum)
        .checked_mul(ELF64_PHDR_LEN)
        .and_then(|len| table_start.checked_add(len))
        .ok_or(ElfMalformed("program headers out of range"))?;
    if table_start < ELF64_EHDR_LEN || table_end > bytes.len() {
        return Err(ElfMalformed(
            "program headers are outside the binary's first 64 KiB",
        ));
    }

    let mut interp: Option<&[u8]> = None;
    for index in 0..usize::from(phnum) {
        let at = table_start + index * ELF64_PHDR_LEN;
        let p_type = read_u32(bytes, at).ok_or(ElfMalformed("truncated program header"))?;
        if p_type != PT_INTERP {
            continue;
        }
        if interp.is_some() {
            return Err(ElfMalformed("more than one PT_INTERP"));
        }
        let offset = read_u64(bytes, at + 8).ok_or(ElfMalformed("truncated program header"))?;
        let size = read_u64(bytes, at + 32).ok_or(ElfMalformed("truncated program header"))?;
        let start = to_index(offset).ok_or(ElfMalformed("interpreter out of range"))?;
        let end = to_index(size)
            .and_then(|size| start.checked_add(size))
            .ok_or(ElfMalformed("interpreter out of range"))?;
        let path = bytes.get(start..end).ok_or(ElfMalformed(
            "the interpreter path is outside the binary's first 64 KiB",
        ))?;
        interp = Some(path);
    }

    // No loader: a static executable — or, as `ET_DYN`, a shared library,
    // which a static-pie is told from by its entry point (a library's is 0).
    if interp.is_none() && e_type == ET_DYN {
        let entry = read_u64(bytes, 24).ok_or(ElfMalformed("truncated ELF header"))?;
        if entry == 0 {
            return Err(BinaryFormatError::ElfSharedLibrary);
        }
    }
    let linkage = match interp {
        None => Linkage::Static,
        Some(raw) => Linkage::Dynamic(interpreter_libc(raw, arch)?),
    };
    Ok(BinaryPlatform::Elf { arch, linkage })
}

/// The libc a `PT_INTERP` path names, held to the binary's architecture.
fn interpreter_libc(raw: &[u8], arch: Arch) -> Result<Libc, BinaryFormatError> {
    // The segment holds a NUL-terminated path; a missing terminator or an
    // interior NUL is malformed.
    let path = match raw.split_last() {
        Some((0, path)) if !path.contains(&0) => path,
        _ => {
            return Err(BinaryFormatError::ElfMalformed(
                "the interpreter path is not NUL-terminated",
            ));
        }
    };
    let path = String::from_utf8_lossy(path).into_owned();
    let file_name = path.rsplit('/').next().unwrap_or_default();
    let (libc, interp_arch) = match file_name {
        "ld-linux-x86-64.so.2" => (Libc::Gnu, Arch::X86_64),
        "ld-linux-aarch64.so.1" => (Libc::Gnu, Arch::Aarch64),
        "ld-musl-x86_64.so.1" => (Libc::Musl, Arch::X86_64),
        "ld-musl-aarch64.so.1" => (Libc::Musl, Arch::Aarch64),
        _ => return Err(BinaryFormatError::UnknownInterpreter(path)),
    };
    if interp_arch != arch {
        return Err(BinaryFormatError::InterpreterArch {
            interpreter: path,
            arch,
        });
    }
    Ok(libc)
}

fn inspect_macho(bytes: &[u8]) -> Result<BinaryPlatform, BinaryFormatError> {
    if bytes.len() < MACHO64_HEADER_LEN {
        return Err(BinaryFormatError::MachOTruncated);
    }
    let cputype = read_u32(bytes, 4).ok_or(BinaryFormatError::MachOTruncated)?;
    let arch = match cputype {
        CPU_TYPE_X86_64 => Arch::X86_64,
        CPU_TYPE_ARM64 => Arch::Aarch64,
        other => return Err(BinaryFormatError::MachOCpu(other)),
    };
    let filetype = read_u32(bytes, 12).ok_or(BinaryFormatError::MachOTruncated)?;
    if filetype != MH_EXECUTE {
        return Err(BinaryFormatError::MachOFileType(filetype));
    }
    Ok(BinaryPlatform::MachO { arch })
}

//
// Policy
//

/// Why a binary is not for a release's target ([`check_binary_target`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformMismatch {
    /// The binary is for another architecture or operating system.
    ArchOrOs,
    /// The binary is dynamically linked against the other libc.
    Libc,
    /// The binary is statically linked, so its header cannot confirm the
    /// target's libc, and no target was named to vouch for it while the
    /// target (the host's) is a glibc one.
    StaticUnconfirmed,
}

/// Hold a binary's platform to the target its release is labelled with.
///
/// `explicit` is whether the target was named (`--target`, or a label a
/// publisher signed) rather than defaulted to the host's.
///
/// - Another architecture or OS: refused.
/// - Dynamic, against the target's libc: accepted; against the other:
///   refused.
/// - Static, same architecture, Linux target: accepted when `explicit`
///   (either libc — a static glibc build is as valid as a musl one); when
///   defaulted, accepted only on a musl target, since a static binary on a
///   glibc host is most likely a musl build that wants the musl label.
/// - Mach-O: the architecture must match and the target be macOS.
///
/// # Errors
///
/// [`PlatformMismatch`] naming the rule that refused it.
pub fn check_binary_target(
    found: BinaryPlatform,
    target: ReleaseTarget,
    explicit: bool,
) -> Result<(), PlatformMismatch> {
    if found.arch() != target.arch() {
        return Err(PlatformMismatch::ArchOrOs);
    }
    match (found, target.os()) {
        (BinaryPlatform::MachO { .. }, TargetOs::Darwin) => Ok(()),
        (BinaryPlatform::MachO { .. }, TargetOs::Linux(_))
        | (BinaryPlatform::Elf { .. }, TargetOs::Darwin) => Err(PlatformMismatch::ArchOrOs),
        (
            BinaryPlatform::Elf {
                linkage: Linkage::Dynamic(libc),
                ..
            },
            TargetOs::Linux(want),
        ) => {
            if libc == want {
                Ok(())
            } else {
                Err(PlatformMismatch::Libc)
            }
        }
        (
            BinaryPlatform::Elf {
                linkage: Linkage::Static,
                ..
            },
            TargetOs::Linux(want),
        ) => {
            if explicit || want == Libc::Musl {
                Ok(())
            } else {
                Err(PlatformMismatch::StaticUnconfirmed)
            }
        }
    }
}

/// The advice for a binary refused by [`check_binary_target`] on its way to
/// being published as `target`: the `--target` that would name what it is,
/// or the build that would match.
#[must_use]
pub fn publish_target_hint(
    found: BinaryPlatform,
    target: ReleaseTarget,
    mismatch: PlatformMismatch,
) -> String {
    match (mismatch, found.target()) {
        (PlatformMismatch::ArchOrOs | PlatformMismatch::Libc, Some(derived)) => format!(
            "pass --target {derived} to publish it as what it is, or publish a {target} build"
        ),
        (PlatformMismatch::ArchOrOs | PlatformMismatch::Libc, None) => {
            let arch = found.arch();
            format!(
                "pass --target {} (a musl build) or --target {} (a static glibc build), or \
                 publish a {target} build",
                ReleaseTarget::linux(arch, Libc::Musl),
                ReleaseTarget::linux(arch, Libc::Gnu),
            )
        }
        (PlatformMismatch::StaticUnconfirmed, _) => {
            let arch = found.arch();
            format!(
                "pass --target {}, or --target {} for a static glibc build",
                ReleaseTarget::linux(arch, Libc::Musl),
                ReleaseTarget::linux(arch, Libc::Gnu),
            )
        }
    }
}

impl fmt::Display for PlatformMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ArchOrOs => "another architecture or operating system",
            Self::Libc => "the other libc",
            Self::StaticUnconfirmed => {
                "statically linked (a musl build?), and no --target names its libc"
            }
        })
    }
}

/// Minimal ELF and Mach-O executables for tests: just the headers
/// [`inspect_binary`] reads, then a payload, so two stubs for one target can
/// still hash differently.
///
/// Built only for tests: this crate's own, and — through the
/// dev-dependency-only `test_binary_stubs` feature — those of the crates that
/// publish or install releases, whose fixtures need bytes the platform check
/// accepts. Never enable the feature on a normal or build edge
/// (`cargo xtask check-release` refuses it).
#[cfg(any(test, feature = "test_binary_stubs"))]
pub mod test_stubs {
    use super::{
        Arch, CPU_TYPE_ARM64, CPU_TYPE_X86_64, ELF_MAGIC, ELF64_EHDR_LEN, ELF64_PHDR_LEN,
        ELFCLASS64, ELFDATA2LSB, EM_AARCH64, EM_X86_64, ET_DYN, ET_EXEC, Libc, MH_EXECUTE,
        MH_MAGIC_64, PT_INTERP, ReleaseTarget, TargetOs,
    };

    /// Size every stub is padded to before its payload: past the 1 KiB floor
    /// a built artifact's binary is held to.
    const STUB_LEN: usize = 2048;

    /// The fields of an ELF stub, each settable so a parser test can break
    /// one at a time.
    #[derive(Debug, Clone)]
    pub struct ElfStub {
        /// `EI_CLASS` (2 = 64-bit).
        pub class: u8,
        /// `EI_DATA` (1 = little-endian).
        pub encoding: u8,
        /// `e_type`.
        pub e_type: u16,
        /// `e_machine`.
        pub machine: u16,
        /// `e_entry` (nonzero: a library's is 0).
        pub entry: u64,
        /// `e_phoff`.
        pub phoff: u64,
        /// `e_phentsize`.
        pub phentsize: u16,
        /// `e_phnum`, counting the `PT_INTERP` when there is one and a
        /// `PT_LOAD` beside it.
        pub phnum: u16,
        /// The `PT_INTERP` path, NUL-terminated by the builder; `None` for a
        /// static binary.
        pub interp: Option<Vec<u8>>,
        /// Overrides the `PT_INTERP`'s `p_offset` (default: just past the
        /// program headers).
        pub interp_offset: Option<u64>,
        /// Overrides the `PT_INTERP`'s `p_filesz`.
        pub interp_size: Option<u64>,
    }

    impl ElfStub {
        /// A dynamic executable for `arch`, loaded by `interp`.
        #[must_use]
        pub fn dynamic(arch: Arch, interp: &str) -> Self {
            Self {
                interp: Some(interp.as_bytes().to_vec()),
                phnum: 2,
                ..Self::static_exe(arch)
            }
        }

        /// A static `ET_EXEC` executable for `arch`.
        #[must_use]
        #[allow(clippy::cast_possible_truncation)] // the header sizes are constants that fit
        pub const fn static_exe(arch: Arch) -> Self {
            Self {
                class: ELFCLASS64,
                encoding: ELFDATA2LSB,
                e_type: ET_EXEC,
                machine: match arch {
                    Arch::X86_64 => EM_X86_64,
                    Arch::Aarch64 => EM_AARCH64,
                },
                entry: 0x1000,
                phoff: ELF64_EHDR_LEN as u64,
                phentsize: ELF64_PHDR_LEN as u16,
                phnum: 1,
                interp: None,
                interp_offset: None,
                interp_size: None,
            }
        }

        /// A static-pie (`ET_DYN`, no `PT_INTERP`) executable for `arch`.
        #[must_use]
        pub const fn static_pie(arch: Arch) -> Self {
            let mut stub = Self::static_exe(arch);
            stub.e_type = ET_DYN;
            stub
        }

        /// The stub's bytes, then `payload`.
        #[must_use]
        #[allow(clippy::cast_possible_truncation)] // test fixture sizes are tiny
        pub fn build(&self, payload: &[u8]) -> Vec<u8> {
            let mut out = vec![0u8; STUB_LEN];
            out[..4].copy_from_slice(&ELF_MAGIC);
            out[4] = self.class;
            out[5] = self.encoding;
            out[6] = 1; // EI_VERSION
            out[16..18].copy_from_slice(&self.e_type.to_le_bytes());
            out[18..20].copy_from_slice(&self.machine.to_le_bytes());
            out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
            out[24..32].copy_from_slice(&self.entry.to_le_bytes());
            out[32..40].copy_from_slice(&self.phoff.to_le_bytes());
            out[52..54].copy_from_slice(&(ELF64_EHDR_LEN as u16).to_le_bytes());
            out[54..56].copy_from_slice(&self.phentsize.to_le_bytes());
            out[56..58].copy_from_slice(&self.phnum.to_le_bytes());

            // The program headers, at the default offset whatever `phoff`
            // says (a test moving `phoff` is testing the bound): a `PT_LOAD`
            // last, the `PT_INTERP` first when there is one.
            let table = ELF64_EHDR_LEN;
            let count = if self.interp.is_some() { 2 } else { 1 };
            let interp_at = table + count * ELF64_PHDR_LEN;
            if let Some(interp) = &self.interp {
                let mut path = interp.clone();
                path.push(0);
                let offset = self.interp_offset.unwrap_or(interp_at as u64);
                let size = self.interp_size.unwrap_or(path.len() as u64);
                let phdr = &mut out[table..table + ELF64_PHDR_LEN];
                phdr[..4].copy_from_slice(&PT_INTERP.to_le_bytes());
                phdr[8..16].copy_from_slice(&offset.to_le_bytes());
                phdr[32..40].copy_from_slice(&size.to_le_bytes());
                phdr[40..48].copy_from_slice(&size.to_le_bytes());
                out[interp_at..interp_at + path.len()].copy_from_slice(&path);
            }
            let load = table + (count - 1) * ELF64_PHDR_LEN;
            out[load..load + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            out.extend_from_slice(payload);
            out
        }
    }

    /// The glibc loader's path for `arch`.
    #[must_use]
    pub const fn gnu_interp(arch: Arch) -> &'static str {
        match arch {
            Arch::X86_64 => "/lib64/ld-linux-x86-64.so.2",
            Arch::Aarch64 => "/lib/ld-linux-aarch64.so.1",
        }
    }

    /// The musl loader's path for `arch`.
    #[must_use]
    pub const fn musl_interp(arch: Arch) -> &'static str {
        match arch {
            Arch::X86_64 => "/lib/ld-musl-x86_64.so.1",
            Arch::Aarch64 => "/lib/ld-musl-aarch64.so.1",
        }
    }

    /// A Mach-O executable for `arch`, then `payload`.
    #[must_use]
    pub fn macho(arch: Arch, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; STUB_LEN];
        out[..4].copy_from_slice(&MH_MAGIC_64);
        let cputype = match arch {
            Arch::X86_64 => CPU_TYPE_X86_64,
            Arch::Aarch64 => CPU_TYPE_ARM64,
        };
        out[4..8].copy_from_slice(&cputype.to_le_bytes());
        out[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// An executable for `target` — dynamically linked on Linux — then
    /// `payload`.
    #[must_use]
    pub fn for_target(target: ReleaseTarget, payload: &[u8]) -> Vec<u8> {
        match target.os() {
            TargetOs::Linux(Libc::Gnu) => {
                ElfStub::dynamic(target.arch(), gnu_interp(target.arch())).build(payload)
            }
            TargetOs::Linux(Libc::Musl) => {
                ElfStub::dynamic(target.arch(), musl_interp(target.arch())).build(payload)
            }
            TargetOs::Darwin => macho(target.arch(), payload),
        }
    }

    /// The target this code was compiled for (`cfg!`'s arch, OS, and
    /// environment), which matches `fuz_release::current_target()` on every
    /// supported host.
    ///
    /// # Panics
    ///
    /// On a host outside the supported set.
    #[must_use]
    #[allow(clippy::panic)] // a test fixture on an unsupported host
    pub fn host_target() -> ReleaseTarget {
        let arch = if cfg!(target_arch = "x86_64") {
            Arch::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            panic!("test host architecture is not a supported release target")
        };
        if cfg!(target_os = "macos") {
            ReleaseTarget::darwin(arch)
        } else if cfg!(target_env = "musl") {
            ReleaseTarget::linux(arch, Libc::Musl)
        } else {
            ReleaseTarget::linux(arch, Libc::Gnu)
        }
    }

    /// An executable for the host ([`host_target`]), then `payload`: what a
    /// test publishes or installs where it used to write placeholder bytes.
    #[must_use]
    pub fn host(payload: &[u8]) -> Vec<u8> {
        for_target(host_target(), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::test_stubs::{ElfStub, for_target, gnu_interp, host_target, macho, musl_interp};
    use super::*;

    const X86_GNU: ReleaseTarget = ReleaseTarget::linux(Arch::X86_64, Libc::Gnu);
    const X86_MUSL: ReleaseTarget = ReleaseTarget::linux(Arch::X86_64, Libc::Musl);
    const ARM_GNU: ReleaseTarget = ReleaseTarget::linux(Arch::Aarch64, Libc::Gnu);
    const ARM_MUSL: ReleaseTarget = ReleaseTarget::linux(Arch::Aarch64, Libc::Musl);
    const X86_MAC: ReleaseTarget = ReleaseTarget::darwin(Arch::X86_64);
    const ARM_MAC: ReleaseTarget = ReleaseTarget::darwin(Arch::Aarch64);

    #[test]
    fn every_supported_triple_round_trips() {
        for target in ReleaseTarget::ALL {
            assert_eq!(target.triple().parse::<ReleaseTarget>(), Ok(target));
            assert_eq!(target.to_string(), target.triple());
        }
        assert_eq!(X86_GNU.libc(), Some(Libc::Gnu));
        assert_eq!(ARM_MAC.libc(), None);
        assert_eq!(ARM_MUSL.arch(), Arch::Aarch64);
    }

    #[test]
    fn an_unsupported_triple_is_refused_escaped_with_the_supported_list() {
        for bad in [
            "",
            "riscv64gc-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "X86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu ",
            "i686-unknown-linux-gnu",
        ] {
            let err = bad.parse::<ReleaseTarget>().unwrap_err();
            assert_eq!(err, UnsupportedTarget(bad.to_string()));
        }
        let err = "x\u{1b}[2Ky".parse::<ReleaseTarget>().unwrap_err();
        assert_eq!(
            err.to_string(),
            "unsupported release target \"x\\u{1b}[2Ky\": supported are \
             x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-unknown-linux-musl, \
             aarch64-unknown-linux-musl, x86_64-apple-darwin, aarch64-apple-darwin"
        );
    }

    #[test]
    fn dynamic_elf_names_its_libc_for_all_four_linux_targets() {
        for target in [X86_GNU, ARM_GNU, X86_MUSL, ARM_MUSL] {
            let bytes = for_target(target, b"payload");
            let found = inspect_binary(&bytes).unwrap();
            assert_eq!(
                found,
                BinaryPlatform::Elf {
                    arch: target.arch(),
                    linkage: Linkage::Dynamic(target.libc().unwrap()),
                },
                "{target}"
            );
            assert_eq!(found.target(), Some(target));
        }
    }

    #[test]
    fn an_interpreter_is_matched_on_its_last_path_component() {
        let nix = "/nix/store/abc-glibc-2.40/lib/ld-linux-x86-64.so.2";
        let found = inspect_binary(&ElfStub::dynamic(Arch::X86_64, nix).build(b"")).unwrap();
        assert_eq!(found.target(), Some(X86_GNU));
    }

    #[test]
    fn static_and_static_pie_elf_are_static_for_both_arches() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            for stub in [ElfStub::static_exe(arch), ElfStub::static_pie(arch)] {
                let found = inspect_binary(&stub.build(b"")).unwrap();
                assert_eq!(
                    found,
                    BinaryPlatform::Elf {
                        arch,
                        linkage: Linkage::Static
                    }
                );
                assert_eq!(found.target(), None);
            }
        }
    }

    /// An `ET_DYN` with no interpreter is a static-pie only with an entry
    /// point; with none it is a shared library (`libz.so.1`'s shape), refused.
    #[test]
    fn a_shared_library_is_not_a_static_pie() {
        let mut library = ElfStub::static_pie(Arch::X86_64);
        library.entry = 0;
        assert_eq!(
            inspect_binary(&library.build(b"")),
            Err(BinaryFormatError::ElfSharedLibrary)
        );
        // An `ET_EXEC` or a dynamic `ET_DYN` is not judged by its entry.
        let mut exe = ElfStub::static_exe(Arch::X86_64);
        exe.entry = 0;
        assert!(inspect_binary(&exe.build(b"")).is_ok());
        let mut dynamic = ElfStub::dynamic(Arch::X86_64, gnu_interp(Arch::X86_64));
        dynamic.e_type = ET_DYN;
        dynamic.entry = 0;
        assert!(inspect_binary(&dynamic.build(b"")).is_ok());
    }

    #[test]
    fn mach_o_x86_64_and_arm64_are_darwin() {
        assert_eq!(
            inspect_binary(&macho(Arch::X86_64, b"")).unwrap().target(),
            Some(X86_MAC)
        );
        assert_eq!(
            inspect_binary(&macho(Arch::Aarch64, b"")).unwrap().target(),
            Some(ARM_MAC)
        );
    }

    #[test]
    fn mach_o_refusals() {
        let mut fat = macho(Arch::X86_64, b"");
        fat[..4].copy_from_slice(&FAT_MAGIC);
        assert_eq!(inspect_binary(&fat), Err(BinaryFormatError::MachOFat));
        fat[..4].copy_from_slice(&FAT_MAGIC_64);
        assert_eq!(inspect_binary(&fat), Err(BinaryFormatError::MachOFat));
        for magic in [FAT_CIGAM, FAT_CIGAM_64] {
            fat[..4].copy_from_slice(&magic);
            assert_eq!(inspect_binary(&fat), Err(BinaryFormatError::MachOFat));
        }
        for magic in [MH_MAGIC, MH_MAGIC_BE, MH_MAGIC_64_BE] {
            let mut other = macho(Arch::X86_64, b"");
            other[..4].copy_from_slice(&magic);
            assert_eq!(inspect_binary(&other), Err(BinaryFormatError::MachOLayout));
        }
        let mut ppc = macho(Arch::X86_64, b"");
        ppc[4..8].copy_from_slice(&0x0100_0012u32.to_le_bytes());
        assert_eq!(
            inspect_binary(&ppc),
            Err(BinaryFormatError::MachOCpu(0x0100_0012))
        );
        let mut dylib = macho(Arch::Aarch64, b"");
        dylib[12..16].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(
            inspect_binary(&dylib),
            Err(BinaryFormatError::MachOFileType(6))
        );
        assert_eq!(
            inspect_binary(&macho(Arch::X86_64, b"")[..20]),
            Err(BinaryFormatError::MachOTruncated)
        );
    }

    #[test]
    fn elf_class_encoding_and_type_refusals() {
        let mut stub = ElfStub::static_exe(Arch::X86_64);
        stub.class = 1;
        assert_eq!(
            inspect_binary(&stub.build(b"")),
            Err(BinaryFormatError::ElfClass(1))
        );
        // A short 32-bit file still reads as 32-bit.
        assert_eq!(
            inspect_binary(&stub.build(b"")[..52]),
            Err(BinaryFormatError::ElfClass(1))
        );
        let mut stub = ElfStub::static_exe(Arch::X86_64);
        stub.encoding = 2;
        assert_eq!(
            inspect_binary(&stub.build(b"")),
            Err(BinaryFormatError::ElfEncoding(2))
        );
        for e_type in [0, 1, 4] {
            let mut stub = ElfStub::static_exe(Arch::Aarch64);
            stub.e_type = e_type;
            assert_eq!(
                inspect_binary(&stub.build(b"")),
                Err(BinaryFormatError::ElfType(e_type)),
                "ET {e_type}"
            );
        }
        let mut stub = ElfStub::static_exe(Arch::X86_64);
        stub.machine = 40; // EM_ARM
        assert_eq!(
            inspect_binary(&stub.build(b"")),
            Err(BinaryFormatError::ElfMachine(40))
        );
    }

    /// A named edit to an ELF stub.
    type StubEdit = (&'static str, fn(&mut ElfStub));

    /// One cell of the policy table: the binary, the target, the verdict with
    /// the target omitted, and with it named.
    type PolicyCell = (
        BinaryPlatform,
        ReleaseTarget,
        Result<(), PlatformMismatch>,
        Result<(), PlatformMismatch>,
    );

    #[test]
    fn elf_truncated_or_out_of_range_headers_are_malformed() {
        let full = ElfStub::dynamic(Arch::X86_64, gnu_interp(Arch::X86_64)).build(b"");
        assert!(matches!(
            inspect_binary(&full[..40]),
            Err(BinaryFormatError::ElfMalformed(_))
        ));
        // The program header table cut off.
        assert!(matches!(
            inspect_binary(&full[..100]),
            Err(BinaryFormatError::ElfMalformed(_))
        ));

        let cases: [StubEdit; 6] = [
            ("phoff past the prefix", |s| {
                s.phoff = INSPECT_PREFIX_LEN as u64;
            }),
            ("phoff overflow", |s| s.phoff = u64::MAX),
            ("phoff inside the ELF header", |s| s.phoff = 8),
            ("no program headers", |s| s.phnum = 0),
            ("PN_XNUM", |s| s.phnum = PN_XNUM),
            ("phentsize", |s| s.phentsize = 32),
        ];
        for (name, edit) in cases {
            let mut stub = ElfStub::dynamic(Arch::X86_64, gnu_interp(Arch::X86_64));
            edit(&mut stub);
            assert!(
                matches!(
                    inspect_binary(&stub.build(b"")),
                    Err(BinaryFormatError::ElfMalformed(_))
                ),
                "{name}"
            );
        }

        let interp_cases: [StubEdit; 3] = [
            ("interp past the prefix", |s| {
                s.interp_offset = Some(INSPECT_PREFIX_LEN as u64 - 4);
            }),
            ("interp size overflow", |s| s.interp_size = Some(u64::MAX)),
            ("interp not NUL-terminated", |s| s.interp_size = Some(5)),
        ];
        for (name, edit) in interp_cases {
            let mut stub = ElfStub::dynamic(Arch::X86_64, gnu_interp(Arch::X86_64));
            edit(&mut stub);
            // Padded past the prefix, so only the prefix bound can refuse.
            let bytes = stub.build(&vec![0u8; INSPECT_PREFIX_LEN]);
            assert!(
                matches!(
                    inspect_binary(&bytes),
                    Err(BinaryFormatError::ElfMalformed(_))
                ),
                "{name}: {:?}",
                inspect_binary(&bytes)
            );
        }
    }

    #[test]
    fn elf_interpreter_refusals() {
        // aarch64's loader in an x86_64 binary, and the reverse.
        let err =
            inspect_binary(&ElfStub::dynamic(Arch::X86_64, gnu_interp(Arch::Aarch64)).build(b""))
                .unwrap_err();
        assert_eq!(
            err,
            BinaryFormatError::InterpreterArch {
                interpreter: gnu_interp(Arch::Aarch64).to_string(),
                arch: Arch::X86_64
            }
        );
        assert!(matches!(
            inspect_binary(&ElfStub::dynamic(Arch::Aarch64, musl_interp(Arch::X86_64)).build(b"")),
            Err(BinaryFormatError::InterpreterArch { .. })
        ));
        // A loader of no supported target, shown escaped.
        let err = inspect_binary(&ElfStub::dynamic(Arch::X86_64, "/lib/ld\u{1b}[2K.so").build(b""))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "unrecognized ELF interpreter \"/lib/ld\\u{1b}[2K.so\""
        );
        assert!(matches!(
            inspect_binary(&ElfStub::dynamic(Arch::X86_64, "/lib/ld-linux.so.2").build(b"")),
            Err(BinaryFormatError::UnknownInterpreter(_))
        ));
    }

    #[test]
    fn non_binaries_are_refused() {
        for bytes in [&b""[..], b"\x7fEL", b"#!/bin/sh\necho hi\n", b"MZ\x90\x00"] {
            let err = inspect_binary(bytes).unwrap_err();
            assert!(
                matches!(
                    err,
                    BinaryFormatError::NotABinary | BinaryFormatError::ElfMalformed(_)
                ),
                "{bytes:?}: {err:?}"
            );
        }
        assert_eq!(
            inspect_binary(b"fuzf binary content"),
            Err(BinaryFormatError::NotABinary)
        );
    }

    /// This test binary, read from disk, is for the target it was built for.
    #[test]
    fn the_running_test_binary_is_for_the_host_target() {
        let exe = std::env::current_exe().unwrap();
        let bytes = std::fs::read(exe).unwrap();
        let found = inspect_binary(&bytes).unwrap();
        check_binary_target(found, host_target(), true).unwrap();
        if let Some(derived) = found.target() {
            assert_eq!(derived, host_target());
        }
    }

    /// Every cell of the policy table.
    #[test]
    fn the_policy_table() {
        use PlatformMismatch::{ArchOrOs, Libc as LibcMismatch, StaticUnconfirmed};
        let dynamic = |arch, libc| BinaryPlatform::Elf {
            arch,
            linkage: Linkage::Dynamic(libc),
        };
        let fixed = |arch| BinaryPlatform::Elf {
            arch,
            linkage: Linkage::Static,
        };
        let mac = |arch| BinaryPlatform::MachO { arch };
        let (x, a) = (Arch::X86_64, Arch::Aarch64);
        let (gnu, musl) = (Libc::Gnu, Libc::Musl);
        // (binary, target, omitted, explicit)
        let cells: [PolicyCell; 16] = [
            // dynamic, matching libc: accepted
            (dynamic(x, gnu), X86_GNU, Ok(()), Ok(())),
            (dynamic(x, musl), X86_MUSL, Ok(()), Ok(())),
            (dynamic(a, gnu), ARM_GNU, Ok(()), Ok(())),
            // dynamic, other libc: refused either way
            (
                dynamic(x, musl),
                X86_GNU,
                Err(LibcMismatch),
                Err(LibcMismatch),
            ),
            (
                dynamic(a, gnu),
                ARM_MUSL,
                Err(LibcMismatch),
                Err(LibcMismatch),
            ),
            // other arch: refused
            (dynamic(a, gnu), X86_GNU, Err(ArchOrOs), Err(ArchOrOs)),
            (fixed(a), X86_MUSL, Err(ArchOrOs), Err(ArchOrOs)),
            (mac(a), X86_MAC, Err(ArchOrOs), Err(ArchOrOs)),
            // other OS: refused
            (mac(x), X86_GNU, Err(ArchOrOs), Err(ArchOrOs)),
            (dynamic(x, gnu), X86_MAC, Err(ArchOrOs), Err(ArchOrOs)),
            (fixed(a), ARM_MAC, Err(ArchOrOs), Err(ArchOrOs)),
            // static: explicit accepts either libc; omitted only musl
            (fixed(x), X86_GNU, Err(StaticUnconfirmed), Ok(())),
            (fixed(x), X86_MUSL, Ok(()), Ok(())),
            (fixed(a), ARM_GNU, Err(StaticUnconfirmed), Ok(())),
            (fixed(a), ARM_MUSL, Ok(()), Ok(())),
            // Mach-O, matching arch
            (mac(a), ARM_MAC, Ok(()), Ok(())),
        ];
        for (found, target, omitted, explicit) in cells {
            assert_eq!(
                check_binary_target(found, target, false),
                omitted,
                "{found} as {target}, omitted"
            );
            assert_eq!(
                check_binary_target(found, target, true),
                explicit,
                "{found} as {target}, explicit"
            );
        }
    }

    #[test]
    fn publish_hints_name_the_target_to_pass() {
        let musl = BinaryPlatform::Elf {
            arch: Arch::X86_64,
            linkage: Linkage::Dynamic(Libc::Musl),
        };
        assert_eq!(
            publish_target_hint(musl, X86_GNU, PlatformMismatch::Libc),
            "pass --target x86_64-unknown-linux-musl to publish it as what it is, or publish a \
             x86_64-unknown-linux-gnu build"
        );
        let fixed = BinaryPlatform::Elf {
            arch: Arch::X86_64,
            linkage: Linkage::Static,
        };
        assert_eq!(
            publish_target_hint(fixed, X86_GNU, PlatformMismatch::StaticUnconfirmed),
            "pass --target x86_64-unknown-linux-musl, or --target x86_64-unknown-linux-gnu for a \
             static glibc build"
        );
        let arm_static = BinaryPlatform::Elf {
            arch: Arch::Aarch64,
            linkage: Linkage::Static,
        };
        assert!(
            publish_target_hint(arm_static, X86_GNU, PlatformMismatch::ArchOrOs)
                .starts_with("pass --target aarch64-unknown-linux-musl (a musl build)")
        );
    }
}
