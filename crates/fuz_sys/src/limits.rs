//! Shared artifact size ceilings.
//!
//! The transfer (forge and ssh upload/download, https download) and extraction (signed
//! tarball) limits all derive from one 10 GiB ceiling. They live here so the
//! value has one home across `fuz_storage` and `fuz_release`.
//!
//! These stay **named** ceilings rather than collapsing to a single global:
//! consumers that need a tighter per-use cap (e.g. a package manager's
//! per-tarball limit) set their own on top of these, so the names need to be
//! distinguishable even while the underlying value is shared.

/// The shared artifact ceiling (10 GiB) the named limits below derive from.
///
/// All three are disk-quota / sanity guards, not memory guards — the transfer
/// and extract paths stream (bounded memory), so a large value is safe.
/// Gzip-bomb protection is the size-independent compression-ratio check in
/// `fuz_release`, which holds regardless of this ceiling.
const ARTIFACT_CEILING_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Maximum single-artifact transfer size (the `forge://` and `ssh://` storage
/// backends' upload/download paths and the `https://` backend's download).
pub const MAX_TRANSFER_SIZE: u64 = ARTIFACT_CEILING_BYTES;

/// Maximum single extracted file size from a signed tarball.
pub const MAX_FILE_SIZE: u64 = ARTIFACT_CEILING_BYTES;

/// Maximum total extracted size from a signed tarball (disk-exhaustion guard).
pub const MAX_TOTAL_SIZE: u64 = ARTIFACT_CEILING_BYTES;

/// The in-memory buffered ceiling (100 MiB).
///
/// The most bytes a *non-streaming* read or write holds in RAM at once:
/// `fuz_artifact`'s per-binary hashing preflight, which aliases this as
/// `MAX_BINARY_SIZE` so the name says which buffer it guards, and the
/// `https://` storage backend's buffered `download`. Streaming paths use
/// [`MAX_TRANSFER_SIZE`] instead.
pub const MAX_BUFFERED_SIZE: u64 = 100 * 1024 * 1024;

/// The trusted-metadata ceiling (1 MiB).
///
/// Small signed/authoritative JSON blobs — release manifests, `latest-<target>.json`
/// pointers, and artifact/tool `meta.json` records — guarded against a hostile
/// host serving a huge "small" file. Named consumers (`MAX_MANIFEST_SIZE`,
/// `MAX_META_SIZE`) alias this.
pub const MAX_METADATA_SIZE: u64 = 1024 * 1024;

/// Subprocess-capture stderr ceiling (1 MiB) — the diagnostic channel.
///
/// Bytes past it are drained and discarded
/// (`crate::capture::read_capped_draining`), never buffered, so a chatty
/// child can neither exhaust parent memory nor block on a full pipe.
/// Consumers with a tighter per-use bound (e.g. `fuz_storage`'s ssh error
/// tail) set their own on top, per this module's naming rule.
pub const MAX_CAPTURE_STDERR_SIZE: u64 = 1024 * 1024;
