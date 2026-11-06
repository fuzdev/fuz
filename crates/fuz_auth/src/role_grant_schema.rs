//! Role-grant row shape.

/// Row from the `role_grant` table (active role grants only).
#[derive(Debug, Clone)]
pub struct RoleGrantRow {
    pub id: uuid::Uuid,
    pub actor_id: uuid::Uuid,
    pub role: String,
    /// Scope this grant applies to, or `None` for a global (any-scope)
    /// grant. Consumed by resource-side ACL checks (e.g. `fuz_cell`'s
    /// role-shaped `cell_grant` admit, which matches `(role, scope_id?)`).
    /// `scope_kind` is deliberately not carried: cell grants discriminate
    /// on `scope_id` alone (UUID collisions across kinds are infeasible).
    pub scope_id: Option<uuid::Uuid>,
}

/// The SQL predicate for an **active** role grant aliased `alias`: not
/// revoked and not expired.
///
/// The grant row's own liveness only. Whether its holder is live — the actor
/// and its account not soft-deleted, which doesn't revoke grants — is a join
/// the caller adds where the read needs it (a member list, an admission
/// gate), since a read off an already-resolved actor doesn't.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     fuz_auth::role_grant_active_sql("rg"),
///     "rg.revoked_at IS NULL AND (rg.expires_at IS NULL OR rg.expires_at > NOW())",
/// );
/// ```
#[must_use]
pub fn role_grant_active_sql(alias: &str) -> String {
    format!(
        "{alias}.revoked_at IS NULL AND ({alias}.expires_at IS NULL OR {alias}.expires_at > NOW())"
    )
}
