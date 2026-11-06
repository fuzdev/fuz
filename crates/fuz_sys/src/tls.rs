//! Process-wide rustls crypto provider for reqwest-over-rustls consumers.
//!
//! `reqwest` is built with the `rustls-no-provider` feature, so the process
//! must install a [`rustls::crypto::CryptoProvider`] before any TLS client is
//! constructed. The `ring` provider drops the `aws-lc-sys` C library and its
//! `cmake` build step, so consumers cross-compile cleanly to a static musl
//! target. Call [`ensure_crypto_provider`] before building any
//! `reqwest::Client`.

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Install the `ring` crypto provider as the process default, exactly once.
///
/// Idempotent and cheap to call before every client construction — a provider
/// already installed by another component is treated as success, since the
/// provider is present either way, which is all the caller needs.
pub fn ensure_crypto_provider() {
    INSTALL.call_once(|| {
        // `install_default` errors only when a provider is already set; either
        // outcome leaves a usable provider installed, so the result is ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
