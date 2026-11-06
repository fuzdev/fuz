//! Error types for storage operations

use fuz_sys::text::{escape_untrusted, quoted, truncate};

/// Which storage backend produced an error.
///
/// Drives both the error-message prefix (via `Display`) and the
/// backend-specific remediation hint. Replaces a `&'static str` that callers
/// compared by value (`backend == "Object"`) — where a typo'd label silently
/// mis-routed — with a closed set the compiler checks exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackendKind {
    /// Local filesystem backend.
    File,
    /// Forge file-store backend.
    Forge,
    /// SSH (`scp`/`ssh`) backend.
    Ssh,
    /// Anonymous read-only HTTPS backend.
    Https,
}

impl StorageBackendKind {
    /// The display label used as the error-message prefix.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::File => "FileStorage",
            Self::Forge => "Forge",
            Self::Ssh => "SSH",
            Self::Https => "HTTPS",
        }
    }
}

impl StorageBackendKind {
    /// Whether the backend only reads: it has `download`, `download_capped`,
    /// `download_to_file`, and `exists`, and its `upload`, `upload_file`,
    /// `list`, and `delete` return [`StorageError::Unsupported`].
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::Https => true,
            Self::File | Self::Forge | Self::Ssh => false,
        }
    }
}

impl std::fmt::Display for StorageBackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Most bytes of a key, a path, or a configuration message a [`StorageError`]
/// message shows.
const MAX_SHOWN_LEN: usize = 512;

/// Most bytes of a failed transfer's `message` a [`StorageError`] message
/// shows: the first half of this from its start and the second from its end.
///
/// A transfer's message is free text someone else wrote — `ssh`'s stderr, a
/// forge's response body — and what went wrong is as often at its end as at
/// its start: `ssh` prints a login banner, or its changed-host-key warning,
/// ahead of the line that says why it gave up. Half of this holds that whole
/// warning, and the two halves together are about a screenful.
pub(crate) const MAX_SHOWN_MESSAGE_LEN: usize = 2048;

/// A key, a path, or a configuration message a [`StorageError`] carries, for
/// its message: cut to `MAX_SHOWN_LEN` bytes, then escaped (`fuz_sys::text`),
/// newlines included.
///
/// What a variant carries is whatever it was given — a key built from a
/// version an unsigned pointer names, a parser's message repeating a token —
/// and the message is printed to a terminal. Nothing in it can drive that
/// terminal or add a line to the output.
fn shown(text: &str) -> String {
    escape_untrusted(&truncate(text, MAX_SHOWN_LEN))
}

/// A failed transfer's `message`, for the error's message: whole when it is
/// at most `MAX_SHOWN_MESSAGE_LEN` bytes, otherwise its start and its end —
/// half the bound each, cut on character boundaries — around a mark that says
/// how many bytes are not shown. Each part is escaped as `shown` escapes, so
/// a multi-line body or stderr reads as one line with `\n` in it.
fn shown_message(text: &str) -> String {
    if text.len() <= MAX_SHOWN_MESSAGE_LEN {
        return escape_untrusted(text);
    }
    let half = MAX_SHOWN_MESSAGE_LEN / 2;
    let mut head_end = half;
    while !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = text.len() - half;
    while !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!(
        "{} [... {} bytes not shown ...] {}",
        escape_untrusted(&text[..head_end]),
        tail_start - head_end,
        escape_untrusted(&text[tail_start..])
    )
}

/// Errors from storage operations
///
/// The strings a variant carries are stored as given — unescaped, at whatever
/// length — and the variant's message shows each bounded and escaped, so none
/// of them can add a line to it: a key, a path, or a configuration message
/// from its start (`shown`), a failed transfer's `message` from both ends
/// (`shown_message`). `Io` shows its `io::Error` as it is.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    //
    // Storage operation errors
    //
    #[error("{backend}: path not found: {}", shown(.path))]
    NotFound {
        backend: StorageBackendKind,
        path: String,
    },

    #[error("{backend}: upload failed: {}", shown_message(.message))]
    UploadFailed {
        backend: StorageBackendKind,
        message: String,
    },

    #[error("{backend}: download failed: {}", shown_message(.message))]
    DownloadFailed {
        backend: StorageBackendKind,
        message: String,
    },

    #[error("{backend}: permission denied: {}", shown(.path))]
    PermissionDenied {
        backend: StorageBackendKind,
        path: String,
    },

    #[error("{backend}: file too large: {} ({size} bytes, max {max})", shown(.path))]
    TooLarge {
        backend: StorageBackendKind,
        path: String,
        size: u64,
        max: u64,
    },

    /// The backend has no such operation — a write, list, or delete against a
    /// read-only backend.
    #[error("{backend}: {operation} is not supported on a read-only backend")]
    Unsupported {
        backend: StorageBackendKind,
        operation: &'static str,
    },

    #[error("{0}: I/O error: {1}")]
    Io(StorageBackendKind, #[source] std::io::Error),

    #[error("invalid storage key {}: {reason}", quoted(&truncate(.key, MAX_SHOWN_LEN)))]
    InvalidKey { key: String, reason: &'static str },

    /// Generic setup/configuration error (URI parsing, HTTP client, etc.)
    #[error("{}", shown(.message))]
    InvalidConfig { message: String },

    /// A local storage location that cannot be the store asked for. From
    /// [`crate::FileStorage::open_existing`], which needs an existing
    /// directory: it is missing, or something else is there. From
    /// [`crate::FileStorage::new`], which accepts a missing one: something
    /// that is not a directory is there, or where a parent of it should be.
    /// Nothing was created either way.
    ///
    /// Carries no path, so it can be shown where the location itself must not
    /// be; a caller that may show the location adds it, and says which of the
    /// two it asked for.
    #[error("local storage path is not an existing directory")]
    LocalRootNotDir,
}

impl StorageError {
    /// Returns user-facing hint for how to fix this error.
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::NotFound { .. } => {
                Some("Check the storage path, or publish the artifact first (`fuzf tool publish`)")
            }
            Self::UploadFailed { .. } => Some("Check storage permissions and connectivity"),
            Self::DownloadFailed { .. } => Some("Check network connectivity and retry"),
            Self::PermissionDenied { backend, .. } => match backend {
                StorageBackendKind::Ssh => {
                    Some("Check SSH access (agent/key) and remote path permissions")
                }
                StorageBackendKind::Forge => Some(
                    "Check the forge bearer token (FUZ_FORGE_TOKEN, else api_token under FUZ_FORGE_HOME or ~/.fuz_forge)",
                ),
                StorageBackendKind::File => Some("Check file/directory permissions"),
                StorageBackendKind::Https => Some(
                    "The https:// backend sends no credentials, so the host must serve \
                     the path publicly",
                ),
            },
            // The cap is a policy ceiling, not a memory guard — the streaming
            // methods are already required trait
            // methods (`Storage::upload_file` / `download_to_file`), so
            // switching to them is not the remedy; a smaller artifact is.
            Self::TooLarge { .. } => Some("Artifact exceeds the backend's size ceiling"),
            // The variant's `reason` names the specific rule that failed; this
            // states the general one. It described a 1-200-char lowercase
            // grammar that `validate_forge_key` has never enforced.
            Self::InvalidKey { .. } => Some(
                "Keys are 1-512 chars of [A-Za-z0-9._/-], relative, with no empty, \
                 dot-prefixed, '.' or '..' segments",
            ),
            Self::Unsupported { .. } => {
                Some("Use a writable backend: a local path, forge://, or ssh://")
            }
            Self::LocalRootNotDir => Some(
                "Check the path: a local store is a directory, and naming one never creates it",
            ),
            Self::Io(_, _) | Self::InvalidConfig { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Text that tries to clear the line, return to its start, reverse what
    /// follows, hide a character, close a quote, forge an escape, and add a
    /// line.
    const HOSTILE: &str = "x\u{1b}[2K\r\u{202e}\u{2800}\"'\\n\nhint: y";
    /// [`HOSTILE`] as a message shows it.
    const SHOWN: &str = "x\\u{1b}[2K\\r\\u{202e}\\u{2800}\"'\\\\n\\nhint: y";

    /// Every string a variant carries is escaped in its message, once: an
    /// unsigned pointer's version in a key, a response body, a remote
    /// command's stderr, a parser's message.
    #[test]
    fn every_carried_string_is_escaped_once_in_the_message() {
        let backend = StorageBackendKind::Https;
        let text = || HOSTILE.to_string();
        let cases = [
            (
                StorageError::NotFound {
                    backend,
                    path: text(),
                },
                format!("HTTPS: path not found: {SHOWN}"),
            ),
            (
                StorageError::UploadFailed {
                    backend,
                    message: text(),
                },
                format!("HTTPS: upload failed: {SHOWN}"),
            ),
            (
                StorageError::DownloadFailed {
                    backend,
                    message: text(),
                },
                format!("HTTPS: download failed: {SHOWN}"),
            ),
            (
                StorageError::PermissionDenied {
                    backend,
                    path: text(),
                },
                format!("HTTPS: permission denied: {SHOWN}"),
            ),
            (
                StorageError::TooLarge {
                    backend,
                    path: text(),
                    size: 2,
                    max: 1,
                },
                format!("HTTPS: file too large: {SHOWN} (2 bytes, max 1)"),
            ),
            (
                StorageError::InvalidKey {
                    key: text(),
                    reason: "key contains invalid characters",
                },
                // In quotes the key cannot close.
                "invalid storage key \"x\\u{1b}[2K\\r\\u{202e}\\u{2800}\\\"'\\\\n\\nhint: y\": \
                 key contains invalid characters"
                    .to_string(),
            ),
            (
                StorageError::InvalidConfig { message: text() },
                SHOWN.to_string(),
            ),
        ];
        for (error, expected) in cases {
            let message = error.to_string();
            assert_eq!(message, expected);
            assert_eq!(message.lines().count(), 1, "{message}");
        }
    }

    /// A key or a path of any length is cut before it is escaped, so the
    /// message is bounded and no escape is cut in half.
    #[test]
    fn a_carried_string_is_bounded_before_it_is_escaped() {
        let long = "\u{1b}".repeat(MAX_SHOWN_LEN + 4096);
        let escaped = format!("{}...", "\\u{1b}".repeat(MAX_SHOWN_LEN));
        assert_eq!(
            StorageError::PermissionDenied {
                backend: StorageBackendKind::Forge,
                path: long.clone(),
            }
            .to_string(),
            format!("Forge: permission denied: {escaped}")
        );
        assert_eq!(
            StorageError::InvalidKey {
                key: long,
                reason: "key too long",
            }
            .to_string(),
            format!("invalid storage key \"{escaped}\": key too long")
        );
        // What fits is shown whole.
        let fits = "k".repeat(MAX_SHOWN_LEN);
        assert_eq!(
            StorageError::NotFound {
                backend: StorageBackendKind::File,
                path: fits.clone(),
            }
            .to_string(),
            format!("FileStorage: path not found: {fits}")
        );
    }

    /// The bound holds for every key, path, and configuration message a
    /// variant carries, each on its own.
    #[test]
    fn every_carried_string_is_bounded() {
        let backend = StorageBackendKind::Ssh;
        let long = || "\u{1b}".repeat(MAX_SHOWN_LEN + 4096);
        let escaped = format!("{}...", "\\u{1b}".repeat(MAX_SHOWN_LEN));
        let cases = [
            (
                StorageError::NotFound {
                    backend,
                    path: long(),
                },
                format!("SSH: path not found: {escaped}"),
            ),
            (
                StorageError::PermissionDenied {
                    backend,
                    path: long(),
                },
                format!("SSH: permission denied: {escaped}"),
            ),
            (
                StorageError::TooLarge {
                    backend,
                    path: long(),
                    size: 2,
                    max: 1,
                },
                format!("SSH: file too large: {escaped} (2 bytes, max 1)"),
            ),
            (StorageError::InvalidConfig { message: long() }, escaped),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    /// A failed transfer's message — an upload's response body, a remote
    /// command's stderr, as long as a server makes them — is shown whole up
    /// to its bound, and past it from both ends: what went wrong is as often
    /// in the last line as in the first. Each end is escaped, and what is left
    /// out is counted.
    #[test]
    fn a_transfer_message_is_bounded_from_both_ends() {
        let backend = StorageBackendKind::Ssh;
        let half = MAX_SHOWN_MESSAGE_LEN / 2;
        let both = |message: &str| {
            [
                StorageError::UploadFailed {
                    backend,
                    message: message.to_string(),
                }
                .to_string(),
                StorageError::DownloadFailed {
                    backend,
                    message: message.to_string(),
                }
                .to_string(),
            ]
        };

        // At the bound: whole, escaped.
        let fits = "\n".repeat(MAX_SHOWN_MESSAGE_LEN);
        let shown_whole = "\\n".repeat(MAX_SHOWN_MESSAGE_LEN);
        assert_eq!(
            both(&fits),
            [
                format!("SSH: upload failed: {shown_whole}"),
                format!("SSH: download failed: {shown_whole}"),
            ]
        );

        // One byte past it: the two halves, around the count of what is not
        // shown.
        let long = format!("{}m{}", "\u{1b}".repeat(half), "\r".repeat(half));
        let cut = format!(
            "{} [... 1 bytes not shown ...] {}",
            "\\u{1b}".repeat(half),
            "\\r".repeat(half)
        );
        assert_eq!(
            both(&long),
            [
                format!("SSH: upload failed: {cut}"),
                format!("SSH: download failed: {cut}"),
            ]
        );

        // Any length: the same two halves.
        let long = format!(
            "{}{}{}",
            "\u{1b}".repeat(half),
            "m".repeat(1_000_000),
            "\r".repeat(half)
        );
        let cut = format!(
            "{} [... 1000000 bytes not shown ...] {}",
            "\\u{1b}".repeat(half),
            "\\r".repeat(half)
        );
        assert_eq!(both(&long)[1], format!("SSH: download failed: {cut}"));

        // Both cuts land on a character boundary: here each would otherwise
        // fall inside a two-byte character.
        let wide = format!("a{}b", "\u{e9}".repeat(MAX_SHOWN_MESSAGE_LEN));
        assert!(!wide.is_char_boundary(half) && !wide.is_char_boundary(wide.len() - half));
        let shown = both(&wide);
        assert_eq!(
            shown[1],
            format!(
                "SSH: download failed: a{} [... {} bytes not shown ...] {}b",
                "\u{e9}".repeat((half - 1) / 2),
                wide.len() - (half - 1) - (half - 1),
                "\u{e9}".repeat((half - 1) / 2),
            )
        );
    }

    /// An ordinary key, path, and message read as they are.
    #[test]
    fn ordinary_strings_are_shown_as_they_are() {
        assert_eq!(
            StorageError::InvalidKey {
                key: "../x".to_string(),
                reason: "key contains invalid path segments",
            }
            .to_string(),
            "invalid storage key \"../x\": key contains invalid path segments"
        );
        assert_eq!(
            StorageError::DownloadFailed {
                backend: StorageBackendKind::Ssh,
                message: "ssh/scp failed (exit 255): ssh: connect to host h port 22: refused"
                    .to_string(),
            }
            .to_string(),
            "SSH: download failed: ssh/scp failed (exit 255): ssh: connect to host h port 22: \
             refused"
        );
    }

    #[test]
    fn hint_targets_the_backend_and_omits_opaque_errors() {
        // permission-denied points at ssh access / forge token / fs perms per backend.
        assert!(
            StorageError::PermissionDenied {
                backend: StorageBackendKind::Ssh,
                path: "p".to_string(),
            }
            .hint()
            .unwrap()
            .contains("SSH")
        );
        assert!(
            StorageError::PermissionDenied {
                backend: StorageBackendKind::Forge,
                path: "p".to_string(),
            }
            .hint()
            .unwrap()
            .contains("token")
        );
        assert!(
            StorageError::PermissionDenied {
                backend: StorageBackendKind::File,
                path: "p".to_string(),
            }
            .hint()
            .unwrap()
            .contains("permissions")
        );
        assert!(
            StorageError::PermissionDenied {
                backend: StorageBackendKind::Https,
                path: "p".to_string(),
            }
            .hint()
            .unwrap()
            .contains("no credentials")
        );
        // an unsupported operation points at the backends that can do it.
        let unsupported = StorageError::Unsupported {
            backend: StorageBackendKind::Https,
            operation: "upload",
        };
        assert_eq!(
            unsupported.to_string(),
            "HTTPS: upload is not supported on a read-only backend"
        );
        assert!(unsupported.hint().unwrap().contains("writable backend"));
        // a local root that is not there says why nothing was created.
        assert_eq!(
            StorageError::LocalRootNotDir.to_string(),
            "local storage path is not an existing directory"
        );
        assert!(
            StorageError::LocalRootNotDir
                .hint()
                .unwrap()
                .contains("never creates it")
        );
        // No hint for opaque IO / config errors.
        assert!(
            StorageError::InvalidConfig {
                message: "x".to_string(),
            }
            .hint()
            .is_none()
        );
        assert!(
            StorageError::Io(StorageBackendKind::File, std::io::Error::other("x"))
                .hint()
                .is_none()
        );
    }

    #[test]
    fn backend_kind_label_drives_display() {
        assert_eq!(StorageBackendKind::Forge.to_string(), "Forge");
        assert_eq!(StorageBackendKind::File.label(), "FileStorage");
        assert_eq!(StorageBackendKind::Forge.label(), "Forge");
        assert_eq!(StorageBackendKind::Ssh.label(), "SSH");
        assert_eq!(StorageBackendKind::Https.label(), "HTTPS");
    }
}
