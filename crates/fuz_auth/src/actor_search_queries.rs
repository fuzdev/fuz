//! Prefix-based actor search.
//!
//! Sibling to
//! `actor_queries::query_actors_by_ids` — that resolves a batch of ids to
//! labels; this resolves a partial name to candidate actors, same row shape
//! ([`ActorLookupRow`]). Mirrors `fuz_app`'s `auth/actor_search_queries.ts`.
//!
//! Case-insensitive LIKE-prefix on `actor.name`. LIKE wildcards (`%`, `_`,
//! `\`) in the query are escaped at this layer so the prefix-only contract
//! holds — an unescaped `%xyz` would widen to full-LIKE and defeat the
//! per-call cap as a binding bound.
//!
//! When `scope_ids` is non-empty the result is filtered to actors holding an
//! **active** `role_grant` on one of the supplied scopes
//! ([`crate::role_grant_active_sql`]), so a
//! revoked/expired membership no longer confers search visibility. `DISTINCT`
//! collapses an actor holding multiple matching grants into one row. Empty
//! `scope_ids` = admin-global path (no `role_grant` join; the handler gates the
//! admin requirement). Both paths return only active actors of active
//! accounts — a soft-deleted actor, or any actor of a soft-deleted account, is
//! never a result. The row shape omits `account_id` / timestamps — same
//! info-leak posture as `actor_queries::query_actors_by_ids`, whose
//! `ACTOR_LOOKUP_PROJECTION` + decoder both paths here share.

use crate::actor_queries::{ACTOR_LOOKUP_PROJECTION, ActorLookupRow, decode_actor_lookup_row};

/// Escape LIKE wildcards (`\`, `%`, `_`) so a user-supplied query can't widen
/// the prefix match to full-LIKE. Paired with `ESCAPE '\'` in the SQL.
fn escape_like_pattern(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Search actors by case-insensitive prefix on `actor.name`, optionally
/// filtered to actors holding an active `role_grant` on one of `scope_ids`.
///
/// Empty `scope_ids` takes the admin-global path (the handler enforces admin).
/// The caller bounds `limit` (the action layer caps at `ACTOR_SEARCH_LIMIT_MAX`).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_actor_search(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    query: &str,
    scope_ids: &[uuid::Uuid],
    limit: i64,
) -> Result<Vec<ActorLookupRow>, tokio_postgres::Error> {
    let escaped_prefix = escape_like_pattern(&query.to_lowercase());
    let rows = if scope_ids.is_empty() {
        // Admin-global path — no role_grant join. Handler enforces admin.
        let sql = format!(
            "SELECT {ACTOR_LOOKUP_PROJECTION}
             FROM actor act
             JOIN account a ON a.id = act.account_id
             WHERE act.deleted_at IS NULL
               AND a.deleted_at IS NULL
               AND LOWER(act.name) LIKE $1 || '%' ESCAPE '\\'
             ORDER BY display_name, id
             LIMIT $2"
        );
        client.query(&sql, &[&escaped_prefix, &limit]).await?
    } else {
        // Scoped path — actors with an active role_grant on any of `scope_ids`.
        let sql = format!(
            "SELECT DISTINCT {ACTOR_LOOKUP_PROJECTION}
             FROM actor act
             JOIN account a ON a.id = act.account_id
             JOIN role_grant rg ON rg.actor_id = act.id
               AND rg.scope_id = ANY($2::uuid[])
               AND {rg_active}
             WHERE act.deleted_at IS NULL
               AND a.deleted_at IS NULL
               AND LOWER(act.name) LIKE $1 || '%' ESCAPE '\\'
             ORDER BY display_name, id
             LIMIT $3",
            rg_active = crate::role_grant_active_sql("rg"),
        );
        client
            .query(&sql, &[&escaped_prefix, &scope_ids, &limit])
            .await?
    };
    Ok(rows.iter().map(decode_actor_lookup_row).collect())
}

#[cfg(test)]
mod tests {
    use super::escape_like_pattern;

    #[test]
    fn passes_plain_text_through_unchanged() {
        assert_eq!(escape_like_pattern("alice"), "alice");
        assert_eq!(escape_like_pattern(""), "");
    }

    #[test]
    fn escapes_each_like_metacharacter() {
        // `%` and `_` are LIKE wildcards; `\` is the escape char itself —
        // all three must be backslash-escaped so the bound stays a literal
        // prefix and `ESCAPE '\'` in the SQL interprets them as data.
        assert_eq!(escape_like_pattern("%"), "\\%");
        assert_eq!(escape_like_pattern("_"), "\\_");
        assert_eq!(escape_like_pattern("\\"), "\\\\");
    }

    #[test]
    fn escapes_wildcards_mixed_with_text() {
        assert_eq!(escape_like_pattern("a%b_c\\d"), "a\\%b\\_c\\\\d");
    }

    #[test]
    fn neutralizes_a_leading_wildcard_prefix_attack() {
        // The threat the escape exists to close: an unescaped `%admin`
        // would widen the prefix match to a full-LIKE substring scan,
        // defeating the per-call cap as a binding bound. Escaped, the `%`
        // is a literal first character, so the match stays prefix-only.
        assert_eq!(escape_like_pattern("%admin"), "\\%admin");
        assert_eq!(escape_like_pattern("_dmin"), "\\_dmin");
    }

    #[test]
    fn does_not_escape_non_metacharacters() {
        // Punctuation that is not a LIKE metacharacter passes through —
        // only `\ % _` are special.
        assert_eq!(escape_like_pattern("a.b-c@d"), "a.b-c@d");
    }
}
