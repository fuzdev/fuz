//! Coverage for the storage-URI resolution surface a consumer reaches — the
//! `parse_existing_storage` dispatcher, the one parse `fuz_release`
//! re-exports. Every branch here is pure: no network, no `~/.fuz`, no
//! credentials (each backend authenticates ambiently, so there is no
//! credentials argument to thread).

use fuz_release::{StorageBackend, StorageError, parse_existing_storage};

/// A bare local path resolves to a `FileStorage` backend.
#[test]
fn parse_local_path_is_file_backend() {
    let dir = tempfile::tempdir().unwrap();
    let backend = parse_existing_storage(dir.path().to_str().unwrap()).unwrap();
    assert!(
        matches!(backend, StorageBackend::File(_)),
        "local path -> File"
    );
}

/// A local path that is not an existing directory is refused, and naming it
/// creates nothing: the parse a consumer gets never makes a store.
#[test]
fn parse_refuses_a_missing_local_path_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such").join("store");
    for location in [
        missing.to_str().unwrap().to_string(),
        format!("file://{}", missing.display()),
    ] {
        let err = parse_existing_storage(&location).unwrap_err();
        assert!(
            matches!(err, StorageError::LocalRootNotDir),
            "{location}: {err:?}"
        );
    }
    assert!(!dir.path().join("no-such").exists());
}

/// A `file://` URI resolves to a `FileStorage` backend (the prefix is stripped).
#[test]
fn parse_file_uri_is_file_backend() {
    let dir = tempfile::tempdir().unwrap();
    let uri = format!("file://{}", dir.path().to_str().unwrap());
    let backend = parse_existing_storage(&uri).unwrap();
    assert!(
        matches!(backend, StorageBackend::File(_)),
        "file:// -> File"
    );
}

/// A well-formed `ssh://user@host/path` URI resolves to an `Ssh` backend — URI
/// parsing is pure, so no network or agent contact happens at construction.
#[test]
fn parse_ssh_uri_is_ssh_backend() {
    let backend = parse_existing_storage("ssh://deploy@vps.example.com/var/www/releases").unwrap();
    assert!(matches!(backend, StorageBackend::Ssh(_)), "ssh:// -> Ssh");
}

/// A malformed `ssh://` URI (no username) is rejected at construction with an
/// invalid-config error, not silently treated as a local path.
#[test]
fn parse_rejects_ssh_without_user() {
    let err = parse_existing_storage("ssh://host/path").unwrap_err();
    assert!(
        matches!(err, StorageError::InvalidConfig { .. }),
        "no ssh user -> InvalidConfig, got {err:?}"
    );
}

/// An `https://` URI resolves to the anonymous read-only `Https` backend —
/// construction is pure, so no request is made.
#[test]
fn parse_https_uri_is_https_backend() {
    let backend = parse_existing_storage("https://releases.example.com/base/path").unwrap();
    assert!(
        matches!(backend, StorageBackend::Https(_)),
        "https:// -> Https"
    );
}

/// Plain `http://` reaches the `Https` backend only for a loopback host.
#[test]
fn parse_http_loopback_is_https_backend() {
    let backend = parse_existing_storage("http://127.0.0.1:8080/releases").unwrap();
    assert!(
        matches!(backend, StorageBackend::Https(_)),
        "http://loopback -> Https"
    );
}

/// `http://` to any other host is refused by name — neither an unknown scheme
/// nor a relative local path called `http:`.
#[test]
fn parse_refuses_plaintext_http() {
    let err = parse_existing_storage("http://example.com/releases").unwrap_err();
    match err {
        StorageError::InvalidConfig { message } => {
            assert!(
                message.contains("refusing plaintext http") && message.contains("use https"),
                "plaintext refusal message, got {message:?}"
            );
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
    assert!(
        !std::path::Path::new("http:").exists(),
        "an http:// URI must never be created as a local path"
    );
}

/// A malformed `https://` URI is rejected at construction.
#[test]
fn parse_rejects_https_with_credentials() {
    let err = parse_existing_storage("https://user:pw@example.com/releases").unwrap_err();
    assert!(
        matches!(err, StorageError::InvalidConfig { .. }),
        "userinfo -> InvalidConfig, got {err:?}"
    );
}

/// There is no S3-compatible backend: an `object://` URI falls through to the
/// unknown-scheme error rather than constructing one.
#[test]
fn parse_rejects_object_scheme_as_unknown() {
    let err = parse_existing_storage("object://bucket").unwrap_err();
    match err {
        StorageError::InvalidConfig { message } => {
            assert!(
                message.contains("unknown storage scheme"),
                "object:// -> unknown scheme, got {message:?}"
            );
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

/// An unrecognized URI scheme falls through to the unknown-scheme error rather
/// than being treated as a local path.
#[test]
fn parse_rejects_unknown_scheme() {
    let err = parse_existing_storage("gopher://host").unwrap_err();
    match err {
        StorageError::InvalidConfig { message } => {
            assert!(
                message.contains("unknown storage scheme"),
                "unknown scheme message, got {message:?}"
            );
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}
