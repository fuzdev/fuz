//! Who hears `role_grant_offer_supersede` when a cascade ends a pending offer,
//! against a real `PostgreSQL`: each handler runs, its post-commit effects are
//! drained as the dispatcher drains them after its commit, and a recording
//! sender reads what was sent, in order.
//!
//! - **A sibling accept** tells each superseded sibling's grantor; the
//!   recipient is the caller, whose answer lists the siblings.
//! - **A revoke** tells both parties of each offer it ends — the revokee's
//!   incoming siblings, then its own outgoing offers — the grantor of each
//!   first.
//! - **An account removal** (delete by an admin, a self-delete, a purge) tells
//!   each offer's other party: the recipient of an offer the account made,
//!   sent its grantor's actor as `cause_id` (never the account id), and the
//!   grantor of one made to it, sent the removed account. The removed account
//!   hears none of it.
//! - **A self-service disable** tells both parties of each sibling it ends,
//!   the grantor and then the caller, whose answer lists no offers.
//!
//! Twin of `fuz_app`'s `role_grant_offer_actions.notifications*.db.test.ts`
//! and the self-service case in `self_service_role_actions.db.test.ts`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test supersede_notifications -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::collections::HashSet;
use std::sync::Arc;

use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{
    AdminOfferAuthorize, CollectingAuditPostCommit, CreateRoleGrantOfferInput, NotificationSender,
    ROLE_ADMIN, RoleGrantOfferActionSpecs, RoleRegistry, SelfServiceRoleActionSpecs,
    default_expiry_from_now, query_role_grant_offer_create,
};
use fuz_db::ActionDb;
use serde_json::{Value, json};

mod common;
use common::{
    RecordingNotificationSender, build_audit, closer, ctx_observed, fresh_db_pool,
    seed_account_actor, seed_actor_context, seed_role_grant_direct,
};

const SUPERSEDE: &str = "role_grant_offer_supersede";

/// One supersede send read down to what the assertions compare: the target,
/// the offer, the reason, the cause.
#[derive(Debug, PartialEq, Eq)]
struct Supersede {
    account_id: uuid::Uuid,
    offer_id: String,
    reason: String,
    cause_id: String,
}

fn supersede(
    account_id: uuid::Uuid,
    offer_id: uuid::Uuid,
    reason: &str,
    cause: uuid::Uuid,
) -> Supersede {
    Supersede {
        account_id,
        offer_id: offer_id.to_string(),
        reason: reason.to_owned(),
        cause_id: cause.to_string(),
    }
}

/// The supersede sends among `sent`, in order.
fn supersedes(sent: &[(uuid::Uuid, Value)]) -> Vec<Supersede> {
    sent.iter()
        .filter(|(_, frame)| frame["method"] == SUPERSEDE)
        .map(|(account_id, frame)| Supersede {
            account_id: *account_id,
            offer_id: frame["params"]["offer"]["id"]
                .as_str()
                .expect("offer id")
                .to_owned(),
            reason: frame["params"]["reason"]
                .as_str()
                .expect("reason")
                .to_owned(),
            cause_id: frame["params"]["cause_id"]
                .as_str()
                .expect("cause id")
                .to_owned(),
        })
        .collect()
}

/// A pending offer of `role` made by direct query.
async fn offer(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    from_actor: uuid::Uuid,
    to_account: uuid::Uuid,
    role: &str,
) -> uuid::Uuid {
    query_role_grant_offer_create(
        client,
        CreateRoleGrantOfferInput {
            from_actor_id: from_actor,
            to_account_id: to_account,
            to_actor_id: None,
            role: role.to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer")
    .id
}

/// `auth` holding an in-memory active grant — the handlers re-check grants on
/// the context, not the database.
fn with_grant(mut auth: RequestActorContext, id: uuid::Uuid, role: &str) -> RequestActorContext {
    auth.role_grants.push(RoleGrantRow {
        id,
        actor_id: auth.actor.id,
        role: role.to_owned(),
        scope_id: None,
    });
    auth
}

/// What a handler run as `auth` sent once its post-commit effects drained.
struct Observed {
    sender: Arc<RecordingNotificationSender>,
    as_sender: Arc<dyn NotificationSender>,
    post_commit: CollectingAuditPostCommit,
}

impl Observed {
    fn new() -> Self {
        let sender = Arc::new(RecordingNotificationSender::default());
        let as_sender: Arc<dyn NotificationSender> =
            Arc::<RecordingNotificationSender>::clone(&sender);
        Self {
            as_sender,
            sender,
            post_commit: CollectingAuditPostCommit::default(),
        }
    }

    async fn drained(&self) -> Vec<(uuid::Uuid, Value)> {
        self.post_commit.drain().await;
        self.sender.take()
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_sibling_accept_tells_each_siblings_grantor() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_a) = seed_account_actor(&pool, "grantor_a").await;
    let (grantor_b_account, grantor_b) = seed_account_actor(&pool, "grantor_b").await;
    fuz_testing::grant_role(&pool, grantor_a, ROLE_ADMIN).await;
    fuz_testing::grant_role(&pool, grantor_b, ROLE_ADMIN).await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let accepted = offer(&client, grantor_a, recipient.account.id, ROLE_ADMIN).await;
    let sibling = offer(&client, grantor_b, recipient.account.id, ROLE_ADMIN).await;

    let audit = build_audit(pool.clone());
    let closer = closer();
    let observed = Observed::new();
    let ctx = ctx_observed(
        &recipient,
        &audit,
        &closer,
        &observed.post_commit,
        &observed.as_sender,
    );
    RoleGrantOfferActionSpecs::dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": accepted }),
        &ctx,
        &ActionDb::Pool(&client),
        &AdminOfferAuthorize,
        &RoleRegistry::default(),
    )
    .await
    .expect("accept");

    assert_eq!(
        supersedes(&observed.drained().await),
        vec![supersede(
            grantor_b_account,
            sibling,
            "sibling_accepted",
            accepted
        )],
        "the sibling's grantor alone: its recipient is the caller"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_revoke_tells_both_parties_of_each_offer_it_ends() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    // the revoking admin: a second active admin, so the last-admin guard admits
    let admin = seed_actor_context(&pool, "revoking_admin").await;
    let admin_grant = seed_role_grant_direct(&pool, admin.actor.id, ROLE_ADMIN, None).await;
    let admin = with_grant(admin, admin_grant, ROLE_ADMIN);
    let (sibling_grantor_account, sibling_grantor) =
        seed_account_actor(&pool, "sibling_grantor").await;
    let (revokee_account, revokee) = seed_account_actor(&pool, "revokee").await;
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;
    let role_grant_id = seed_role_grant_direct(&pool, revokee, ROLE_ADMIN, None).await;
    let sibling = offer(&client, sibling_grantor, revokee_account, ROLE_ADMIN).await;
    let outgoing = offer(&client, revokee, recipient_account, ROLE_ADMIN).await;

    let audit = build_audit(pool.clone());
    let closer = closer();
    let observed = Observed::new();
    let ctx = ctx_observed(
        &admin,
        &audit,
        &closer,
        &observed.post_commit,
        &observed.as_sender,
    );
    RoleGrantOfferActionSpecs::dispatch(
        "role_grant_revoke",
        &json!({ "actor_id": revokee, "role_grant_id": role_grant_id }),
        &ctx,
        &ActionDb::Pool(&client),
        &AdminOfferAuthorize,
        &RoleRegistry::default(),
    )
    .await
    .expect("revoke");

    let reason = "role_grant_revoked";
    assert_eq!(
        supersedes(&observed.drained().await),
        vec![
            supersede(sibling_grantor_account, sibling, reason, role_grant_id),
            supersede(revokee_account, sibling, reason, role_grant_id),
            supersede(revokee_account, outgoing, reason, role_grant_id),
            supersede(recipient_account, outgoing, reason, role_grant_id),
        ],
        "the incoming sibling, then the outgoing offer, each grantor first"
    );
}

/// An account removal run as `actor` (the removed account's own context on a
/// self-delete) over `removed`, which made one offer and received one.
async fn assert_removal_tells_each_other_party(method: &str, self_remove: bool) {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let admin = seed_actor_context(&pool, "admin").await;
    let admin_grant = seed_role_grant_direct(&pool, admin.actor.id, ROLE_ADMIN, None).await;
    let admin = with_grant(admin, admin_grant, ROLE_ADMIN);
    let removed = seed_actor_context(&pool, "removed").await;
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;
    let (grantor_account, grantor) = seed_account_actor(&pool, "grantor").await;
    let (bystander_account, _) = seed_account_actor(&pool, "bystander").await;
    let outgoing = offer(&client, removed.actor.id, recipient_account, ROLE_ADMIN).await;
    let incoming = offer(&client, grantor, removed.account.id, ROLE_ADMIN).await;
    // a party to neither: its offer stays pending, unannounced
    offer(&client, grantor, bystander_account, ROLE_ADMIN).await;

    let audit = build_audit(pool.clone());
    let closer = closer();
    let observed = Observed::new();
    let actor = if self_remove { &removed } else { &admin };
    let ctx = ctx_observed(
        actor,
        &audit,
        &closer,
        &observed.post_commit,
        &observed.as_sender,
    );
    let params = match (method, self_remove) {
        ("account_purge", _) => json!({ "account_id": removed.account.id, "confirm": true }),
        (_, true) => json!({}),
        _ => json!({ "account_id": removed.account.id }),
    };
    common::admin_dispatch(method, &params, &ctx, &client)
        .await
        .expect(method);

    let sent = observed.drained().await;
    let reason = "account_deleted";
    assert_eq!(
        supersedes(&sent),
        vec![
            // the recipient holds the grantor's actor, never its account id
            supersede(recipient_account, outgoing, reason, removed.actor.id),
            supersede(grantor_account, incoming, reason, removed.account.id),
        ],
        "{method}: the outgoing offer's recipient, then the incoming offer's grantor"
    );
    assert!(
        sent.iter()
            .all(|(account_id, _)| *account_id != removed.account.id),
        "{method}: the removed account is sent nothing"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_admin_delete_tells_each_offers_other_party() {
    assert_removal_tells_each_other_party("account_delete", false).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_self_delete_tells_each_offers_other_party() {
    assert_removal_tells_each_other_party("account_delete", true).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_purge_tells_each_offers_other_party() {
    assert_removal_tells_each_other_party("account_purge", false).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_self_service_disable_tells_both_parties_of_each_sibling() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let caller = seed_actor_context(&pool, "caller").await;
    let grant = seed_role_grant_direct(&pool, caller.actor.id, "teacher", None).await;
    let caller = with_grant(caller, grant, "teacher");
    let (grantor_account, grantor) = seed_account_actor(&pool, "grantor").await;
    let sibling = offer(&client, grantor, caller.account.id, "teacher").await;

    let audit = build_audit(pool.clone());
    let closer = closer();
    let observed = Observed::new();
    let ctx = ctx_observed(
        &caller,
        &audit,
        &closer,
        &observed.post_commit,
        &observed.as_sender,
    );
    let eligible: HashSet<String> = HashSet::from(["teacher".to_owned()]);
    SelfServiceRoleActionSpecs::dispatch(
        "self_service_role_set",
        &json!({ "role": "teacher", "enabled": false }),
        &ctx,
        &client,
        &eligible,
    )
    .await
    .expect("self-service disable");

    assert_eq!(
        supersedes(&observed.drained().await),
        vec![
            supersede(grantor_account, sibling, "role_grant_revoked", grant),
            supersede(caller.account.id, sibling, "role_grant_revoked", grant),
        ],
        "the sibling's grantor, then the caller, whose answer lists no offers"
    );
}
