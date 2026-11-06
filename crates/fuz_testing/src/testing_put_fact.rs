//! `_testing_put_fact` action spec.
//!
//! Test binaries register this on their `ActionRegistry` alongside
//! `_testing_reset` / `_testing_mint_session`. It seeds an **embedded** fact
//! (`fact.bytes`), or an external row when `external_url` is given, so the
//! cross-process fact-serving suite can store facts without a DB handle — the
//! cross-process driver runs over real HTTP and has no `PgFactStore` to call.
//! The referencing cell is seeded separately via the `cell_create` RPC; this
//! action only puts the fact row.
//!
//! Reads `{content: string, content_type?: string, holder?: uuid,
//! external_url?: string}`, hashes the UTF-8 bytes (blake3 via
//! [`fuz_crypto::ContentHash`] — the workspace's single hashing home, matching
//! the TS `fact_hash_bytes`), inserts the row idempotently, and returns
//! `{hash: "blake3:<hex>"}`. `holder` names the actor the put is on behalf of
//! — recorded in `fact_holder` (deduplicated puts included), as a real upload
//! records its uploader, so the suite can drive cell ref admission; absent,
//! the put is a system put with no holder. Embedded is enough for the authz
//! assertions the suite proves (cell-scoped admit, cross-owner-no-leak,
//! 404-mask, bare-hash admin-only); external / X-Accel parity is covered by a
//! consumer's own gate, outside this workspace. `external_url`, when given,
//! writes the row the way a writer past the store could — no bytes, that URL
//! verbatim, unvalidated — so the suite can prove a serve refuses a URL that
//! is not its hash's own address. Mirrors `fuz_app`'s TS `_testing_put_fact`.
//!
//! Gated on the daemon-token credential — effectively keeper-only without
//! forcing the `actor: 'required'` biconditional, matching `_testing_reset`.

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_crypto::ContentHash;
use fuz_http::{InputShape, internal_error_with_source, invalid_input_params, invalid_params};
use serde_json::{Value, json};

/// Declared input keys — the exact key set of the TS twin's
/// `testing_put_fact_action_spec.input` strict object.
const TESTING_PUT_FACT_KEYS: &[&str] = &["content", "content_type", "holder", "external_url"];

/// `content_type`, `holder` and `external_url` are `.optional()` on the twin,
/// so an explicit `null` is refused rather than read as absent.
const TESTING_PUT_FACT_NON_NULLABLE: &[&str] = &["content_type", "holder", "external_url"];

/// Build the `_testing_put_fact` action spec.
///
/// `side_effects: true` so the dispatcher wraps the insert in a transaction.
#[must_use]
pub fn create_testing_put_fact_action_spec() -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
        Box::pin(async move {
            fuz_http::reject_unknown_keys(&params, TESTING_PUT_FACT_KEYS)?;
            // `content_type` is `.optional()` on the twin, so `null` and a
            // non-string are both refused rather than read as absent.
            fuz_http::reject_null_keys(&params, TESTING_PUT_FACT_NON_NULLABLE)?;
            let content = params
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_input_params("content (string) is required", None))?;
            let content_type = fuz_http::parse_optional_str_param(&params, "content_type")?;
            let holder = fuz_http::parse_optional_uuid_param(&params, "holder")?;
            let external_url = fuz_http::parse_optional_str_param(&params, "external_url")?;

            let bytes = content.as_bytes();
            let hash = ContentHash::blake3(bytes).to_prefixed();
            let size = i64::try_from(bytes.len())
                .map_err(|_| invalid_params("content too large", None))?;

            // Idempotent (content addressing). Embedded, unless `external_url`
            // names the row's file — then no bytes (see module doc).
            let embedded: Option<&[u8]> = external_url.is_none().then_some(bytes);
            ctx.db
                .execute(
                    "INSERT INTO fact (hash, bytes, external_url, content_type, size) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (hash) DO NOTHING",
                    &[&hash, &embedded, &external_url, &content_type, &size],
                )
                .await
                .map_err(|e| internal_error_with_source("INSERT fact", &e))?;
            // The holder row, on a dedup hit too, a repeat put refreshing its
            // `created_at` (`fuz_fact`'s put records it the same way). An
            // unknown actor fails the FK.
            if let Some(holder) = holder {
                ctx.db
                    .execute(
                        "INSERT INTO fact_holder (actor_id, hash) VALUES ($1, $2) \
                         ON CONFLICT (actor_id, hash) DO UPDATE SET created_at = NOW()",
                        &[&holder, &hash],
                    )
                    .await
                    .map_err(|e| internal_error_with_source("INSERT fact_holder", &e))?;
            }

            Ok(json!({ "hash": hash }))
        })
    });

    ActionSpec::with_side_effects(
        "_testing_put_fact",
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}
