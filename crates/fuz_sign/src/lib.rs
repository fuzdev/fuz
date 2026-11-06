//! Producer-side signing + publishing for Fuz.
//!
//! This crate holds everything that uses a **private** ed25519 signing key:
//! key generation, the key file's format and its loader (`key_file`), manifest
//! and release-log-head signing (over
//! domain-separated signed bytes), the `publish_*` upload
//! flows, the release log write those flows perform when given a log checkout
//! (`release_log`), the creation of that log from the releases already in
//! storage (`backfill`), the revocation of a logged release (`revoke`), and
//! the deletion of old published releases (`prune`).
//! It is deliberately **not** a dependency of the `fuz` consumer binary — `fuz`
//! only verifies (against
//! `fuz_crypto`'s embedded public keys) and fetches/installs (via
//! `fuz_release`).
//!
//! Signing lives in its own crate rather than behind a cargo feature on
//! `fuz_crypto`/`fuz_release` on purpose: cargo feature unification can route a
//! feature enabled by one workspace member (e.g. `xtask`) into a sibling
//! (`fuz`) on a `--workspace` build, which would silently re-link signing into
//! the consumer. A separate crate can't be unified in, so `cargo xtask
//! check-release` can assert `fuz`'s dependency graph excludes it. Same
//! reasoning as `fuz_testing` being a crate, not a feature.
//!
//! Producers — the forge client `fuzf` (`fuzf tool publish`) and the
//! bootstrap-only signer `cargo xtask` — depend on this crate; the forge
//! server (`fuzfd`) and `fuz`/`fuzd` do not.

pub mod backfill;
pub mod error;
pub mod key;
pub mod key_file;
pub mod prune;
pub mod publish;
pub mod release_log;
pub mod revoke;
mod scratch;
pub mod sign;
mod stream;
pub mod tool;

pub use backfill::{
    BackfillError, BackfillOptions, BackfillPointer, BackfillProblem, BackfillProblemKind,
    BackfillReport, BackfilledTarget, GenesisPlan, LatestTarget, backfill_release_log,
    plan_genesis, sign_genesis,
};
pub use error::KeyError;
pub use key::{KeyMetadata, generate_keypair, parse_key_file, serialize_key_file};
pub use key_file::{KeyFileError, LoadedSigningKey, default_key_path, load_signing_key};
pub use prune::{PruneReport, PrunedRelease, prune_stream};
pub use publish::{PublishOptions, PublishResult, publish_artifact, publish_current};
pub use release_log::{LogEntry, LogOutcome, LogRepo, check_release, record_release};
pub use revoke::{
    PointerAfter, PointerChange, Revocation, RevokeError, RevokeOptions, RevokeReport,
    revoke_release,
};
pub use sign::{sign_head, sign_manifest};
pub use stream::printable;
pub use tool::publish_tool;

// Re-export the signing-key type + zeroizing buffer for the producer CLIs.
pub use ed25519_dalek::SigningKey;
pub use zeroize::Zeroizing;
