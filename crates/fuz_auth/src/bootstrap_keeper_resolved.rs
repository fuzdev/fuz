//! `BootstrapKeeperResolved` — post-bootstrap keeper-account callback.
//!
//! Consumer-specific side effect after the bootstrap pipeline resolves
//! the new keeper account: wiring the daemon-token state's
//! `keeper_account_id`. The canonical implementation is
//! [`crate::DaemonTokenKeeperResolved`], shared by every consumer that wires
//! a daemon token; a consumer without a daemon-token surface leaves the
//! callback `None`. The trait itself stays independent of
//! `SharedDaemonTokenState`.

use futures::future::BoxFuture;
use uuid::Uuid;

/// Callback fired after bootstrap resolves the keeper account.
///
/// `account_id` is the new keeper account's UUID. Consumer
/// implementations plug this into their daemon-token state, write a
/// keeper marker file, etc.
///
/// **Object-safe** — consumed as `Arc<dyn BootstrapKeeperResolved>`
/// (optional field on [`crate::BootstrapOptions`]). Async via
/// [`BoxFuture`], the dyn-trait convention.
pub trait BootstrapKeeperResolved: Send + Sync {
    fn on_keeper_resolved(&self, account_id: Uuid) -> BoxFuture<'static, ()>;
}
