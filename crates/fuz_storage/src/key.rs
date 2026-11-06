//! The on-store key contract, shared by every backend.
//!
//! A key is a relative, `/`-separated path under the storage root. Each
//! backend turns one into something else — a filesystem path, a URL path, a
//! remote shell argument — so one validator decides what a key may be, and no
//! backend joins a key it has not passed through it. The forge *server*
//! enforces the same function on its side (it depends on this crate for it),
//! which is why it keeps the name [`validate_forge_key`].

use crate::error::StorageError;

/// Validate a storage key (traversal-safe; allows interior `/`).
///
/// Keys must be non-empty, ≤512 chars, relative (no leading `/`), have no empty
/// path segments, no `.`/`..` segments, no segment starting with `.`, and use
/// only `[A-Za-z0-9._/-]` — so no NUL, backslash, whitespace, or shell or URL
/// metacharacter. Every backend applies it to every key before the key is
/// joined onto a root, and the forge applies it server-side on upload.
pub fn validate_forge_key(key: &str) -> Result<(), StorageError> {
    let invalid = |reason: &'static str| StorageError::InvalidKey {
        key: key.to_string(),
        reason,
    };
    if key.is_empty() {
        return Err(invalid("key cannot be empty"));
    }
    if key.len() > 512 {
        return Err(invalid("key exceeds 512 characters"));
    }
    if key.starts_with('/') {
        return Err(invalid("key cannot be absolute"));
    }
    if key.ends_with('/') {
        return Err(invalid("key cannot end with '/'"));
    }
    for segment in key.split('/') {
        if segment.is_empty() {
            return Err(invalid("key cannot contain empty path segments"));
        }
        if segment == "." || segment == ".." {
            return Err(invalid("key cannot contain '.' or '..' segments"));
        }
        if segment.starts_with('.') {
            return Err(invalid("key path segments cannot start with '.'"));
        }
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'/'))
    {
        return Err(invalid(
            "key contains invalid characters (allowed: a-z, A-Z, 0-9, '-', '.', '_', '/')",
        ));
    }
    Ok(())
}

/// Validate a `list` prefix: the empty prefix (the whole store), a directory
/// (`tools/fuzd/`), or the start of a key (`tools/fuzd/fuzd-`).
///
/// Everything but the one trailing `/` a directory prefix carries is held to
/// [`validate_forge_key`], so a prefix can no more leave the storage root than
/// a key can: `../`, `/abs/`, and `tools/../x/` are refused.
pub fn validate_list_prefix(prefix: &str) -> Result<(), StorageError> {
    if prefix.is_empty() {
        return Ok(());
    }
    validate_forge_key(prefix.strip_suffix('/').unwrap_or(prefix)).map_err(|error| match error {
        // Name the prefix as given, not with its `/` removed.
        StorageError::InvalidKey { reason, .. } => StorageError::InvalidKey {
            key: prefix.to_string(),
            reason,
        },
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forge_key_accepts_layout_keys() {
        assert!(validate_forge_key("latest.json").is_ok());
        assert!(validate_forge_key("fuz-0.3.0-x86_64-unknown-linux-gnu.manifest.json").is_ok());
        assert!(validate_forge_key("tools/zap/latest.json").is_ok());
        assert!(
            validate_forge_key("tools/zap/0.1.0/zap-0.1.0-x86_64-unknown-linux-gnu.tar.gz").is_ok()
        );
    }

    #[test]
    fn forge_key_rejects_traversal() {
        assert!(validate_forge_key("").is_err());
        assert!(validate_forge_key("/abs").is_err());
        assert!(validate_forge_key("trailing/").is_err());
        assert!(validate_forge_key("a//b").is_err());
        assert!(validate_forge_key("tools/../etc/passwd").is_err());
        assert!(validate_forge_key("tools/./x").is_err());
        assert!(validate_forge_key("tools/.hidden").is_err());
        assert!(validate_forge_key("tools/zap latest.json").is_err()); // space
        assert!(validate_forge_key("tools/zap\\x").is_err()); // backslash
    }

    #[test]
    fn forge_key_rejects_what_a_path_or_a_shell_would_read() {
        for key in ["a\0b", "a\nb", "~/x", "a b", "a*", "a?b", "a%2e%2e/b", "é"] {
            assert!(
                matches!(
                    validate_forge_key(key),
                    Err(StorageError::InvalidKey { .. })
                ),
                "{key:?}"
            );
        }
    }

    #[test]
    fn list_prefix_is_empty_a_directory_or_the_start_of_a_key() {
        for prefix in ["", "tools/fuzd/", "tools/fuzd", "tools/fuzd/fuzd-", "fuz-"] {
            assert!(validate_list_prefix(prefix).is_ok(), "{prefix:?}");
        }
        for prefix in [
            "/",
            "//",
            "../",
            "..",
            "/abs/",
            "tools/../x/",
            "tools//",
            "a/../../x",
            "./",
            ".hidden/",
            "a\0/",
        ] {
            let err = validate_list_prefix(prefix).unwrap_err();
            assert!(
                matches!(&err, StorageError::InvalidKey { key, .. } if key == prefix),
                "{prefix:?}: {err:?}"
            );
        }
    }
}
