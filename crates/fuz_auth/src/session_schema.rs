//! Auth-session row shapes.

/// Row from the `auth_session` table (lookup result).
#[derive(Debug, Clone)]
pub struct AuthSessionRow {
    pub account_id: uuid::Uuid,
    /// How long the session has left — `expires_at - NOW()`, measured on the
    /// database clock in the statement that found the session unexpired.
    pub expires_in: std::time::Duration,
}

/// Session row for listing (no token hash exposed). `fuz_app`'s
/// `AuthSessionJson` less `account_id` and `is_current`, which the
/// `account_session_list` handler adds.
#[derive(Debug, Clone)]
pub struct SessionListRow {
    pub id: String,
    pub created_at: String,
    pub expires_at: String,
}
