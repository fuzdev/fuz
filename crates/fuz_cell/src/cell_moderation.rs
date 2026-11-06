//! The `cell.moderation` read rules, in pure and SQL form side by side.
//!
//! `moderation` is free `TEXT` with no CHECK, so each rule is an allowlist
//! over the literals: a marker this module doesn't name (a typo, a future
//! state) admits nothing.
//!
//! **Audience admission** — [`cell_moderation_admits_audience`] and
//! [`cell_moderation_admits_audience_sql`]: unmoderated (`NULL`) or
//! `approved`. A cell's effective audience is its visibility (or grants)
//! **and** its admission, so the public and grant read arms of
//! [`crate::can_view_cell`] require it, as do the `editor` grant arm of
//! [`crate::can_edit_cell`] and the matching arms of
//! [`crate::cell_queries::query_cell_list`] (general and `shared_with`
//! shapes). The owner and global-admin arms don't: an author keeps reading
//! and editing their own pending or rejected contribution, and an admin
//! reads everything.
//!
//! **Stewardship** — [`cell_moderation_is_stewardable`] and
//! [`cell_moderation_is_stewardable_sql`]: exactly `pending` or `rejected`,
//! the states in which the governing root's manager reads a contribution its
//! audience can't ([`crate::can_steward_cell`]). An unknown marker is neither
//! admitted nor stewardable, so only its owner and admins read it.
//!
//! The pure and SQL forms are written once each here, next to each other,
//! over the same literal constants; every predicate and query composes them
//! rather than restating the rule. Twin of `fuz_app`'s
//! `db/cell_moderation.ts`.

/// `cell.moderation` for a gated contribution awaiting a decision.
pub const CELL_MODERATION_PENDING: &str = "pending";

/// `cell.moderation` for an approved contribution.
pub const CELL_MODERATION_APPROVED: &str = "approved";

/// `cell.moderation` for a rejected contribution.
pub const CELL_MODERATION_REJECTED: &str = "rejected";

/// Whether a cell's `moderation` marker admits it to an audience beyond its
/// owner — unmoderated (`None`) or `approved`; `pending`, `rejected`, and any
/// unknown marker do not.
#[must_use]
pub fn cell_moderation_admits_audience(moderation: Option<&str>) -> bool {
    moderation.is_none_or(|m| m == CELL_MODERATION_APPROVED)
}

/// SQL form of [`cell_moderation_admits_audience`] over the cell alias
/// `alias` (a parenthesized boolean expression).
#[must_use]
pub fn cell_moderation_admits_audience_sql(alias: &str) -> String {
    format!("({alias}.moderation IS NULL OR {alias}.moderation = '{CELL_MODERATION_APPROVED}')")
}

/// Whether a cell's `moderation` marker is one its governing root's manager
/// stewards — exactly `pending` or `rejected`.
#[must_use]
pub fn cell_moderation_is_stewardable(moderation: Option<&str>) -> bool {
    moderation.is_some_and(|m| m == CELL_MODERATION_PENDING || m == CELL_MODERATION_REJECTED)
}

/// SQL form of [`cell_moderation_is_stewardable`] over the cell alias `alias`.
#[must_use]
pub fn cell_moderation_is_stewardable_sql(alias: &str) -> String {
    format!("{alias}.moderation IN ('{CELL_MODERATION_PENDING}', '{CELL_MODERATION_REJECTED}')")
}

#[cfg(test)]
mod tests {
    use super::{
        CELL_MODERATION_APPROVED, CELL_MODERATION_PENDING, CELL_MODERATION_REJECTED,
        cell_moderation_admits_audience, cell_moderation_admits_audience_sql,
        cell_moderation_is_stewardable, cell_moderation_is_stewardable_sql,
    };

    #[test]
    fn audience_admission_is_an_allowlist() {
        assert!(cell_moderation_admits_audience(None));
        assert!(cell_moderation_admits_audience(Some(
            CELL_MODERATION_APPROVED
        )));
        assert!(!cell_moderation_admits_audience(Some(
            CELL_MODERATION_PENDING
        )));
        assert!(!cell_moderation_admits_audience(Some(
            CELL_MODERATION_REJECTED
        )));
        // an unknown marker (no CHECK on the column) admits nothing
        assert!(!cell_moderation_admits_audience(Some("Approved")));
        assert!(!cell_moderation_admits_audience(Some("")));
    }

    #[test]
    fn audience_admission_sql_names_the_alias() {
        assert_eq!(
            cell_moderation_admits_audience_sql("c"),
            "(c.moderation IS NULL OR c.moderation = 'approved')"
        );
    }

    #[test]
    fn stewardship_is_exactly_pending_or_rejected() {
        assert!(cell_moderation_is_stewardable(Some(
            CELL_MODERATION_PENDING
        )));
        assert!(cell_moderation_is_stewardable(Some(
            CELL_MODERATION_REJECTED
        )));
        assert!(!cell_moderation_is_stewardable(None));
        assert!(!cell_moderation_is_stewardable(Some(
            CELL_MODERATION_APPROVED
        )));
        assert!(!cell_moderation_is_stewardable(Some("Pending")));
        assert_eq!(
            cell_moderation_is_stewardable_sql("c"),
            "c.moderation IN ('pending', 'rejected')"
        );
    }
}
