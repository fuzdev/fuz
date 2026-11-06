//! API-token row shapes.

use crate::token_scope::TokenScope;

/// Row from the `api_token` table (fields needed for bearer auth).
#[derive(Debug, Clone)]
pub struct ApiTokenRow {
    pub id: String,
    pub account_id: uuid::Uuid,
    /// What this token may do — the authority narrowing resolved onto
    /// [`ResolvedAuth`](crate::ResolvedAuth). Never optional: the column is
    /// `NOT NULL`, and an unreadable document fails the lookup closed rather
    /// than defaulting to [`TokenScope::Full`].
    pub scope: TokenScope,
    /// How long the token has left — `expires_at - NOW()`, measured on the
    /// database clock in the statement that found it live. `None` for an
    /// eternal token (`expires_at IS NULL`).
    pub expires_in: Option<std::time::Duration>,
}

/// Timestamps of a freshly minted API token, in wire form (UTC ISO 8601).
///
/// Read back off the INSERT's `RETURNING` so the response reports the DB's
/// own rendering, matching `query_api_token_list_for_account`.
#[derive(Debug, Clone)]
pub struct ApiTokenMintedRow {
    pub created_at: String,
    /// `None` for an eternal token.
    pub expires_at: Option<String>,
}

/// Token row for listing — `ClientApiTokenJson` shape. Deliberately
/// omits `token_hash`. Mirrors `fuz_app`'s `Omit<ApiToken, 'token_hash'>`.
#[derive(Debug, Clone)]
pub struct ApiTokenListRow {
    pub id: String,
    pub account_id: uuid::Uuid,
    pub name: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub last_used_ip: Option<String>,
    pub created_at: String,
    /// Human-readable scope label (`full` / `full (grandfathered)` /
    /// `N methods`). A label rather than the document so the list stays a
    /// display surface — nothing authorizes off this.
    pub scope: String,
}
