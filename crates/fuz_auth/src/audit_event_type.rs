//! Closed enumeration of every audit event the spine emits + the
//! per-event routing policy.
//!
//! ## Why this exists
//!
//! Audit events have two failure modes that conflict:
//!
//! - **Pool-routed** (fire-and-forget on a separate connection):
//!   survives the request transaction rolling back. Right for ATTEMPT
//!   and FAILURE audits — a denied admin operation's forensic record
//!   should outlive the rollback that discarded the attempted state
//!   change.
//! - **In-tx** (INSERT in the request's transaction): atomic with the
//!   handler. Right for SUCCESS audits paired with a state mutation
//!   — the audit row should land iff the state row lands.
//!
//! Choosing per emit site by code-reading is footgun-prone. The
//! [`AUDIT_EVENT_SPECS`] table lifts the choice to a single declarative
//! surface: every variant of [`AuditEventType`] declares its
//! `(success_routing, failure_routing)` policy. Compliance reviewers
//! and agents auditing the audit surface read one table, not every
//! emit site.
//!
//! The same table carries a second, unrelated policy for the same reason:
//! [`RevocationScope`], which says what a successful row invalidates so the
//! revocation guard ([`crate::revocation_guard`], closing WebSocket and SSE
//! connections alike) dispatches off one declaration instead of a
//! hand-maintained string list.
//!
//! ## Adding an event
//!
//! 1. Add `Variant => "wire_string"` to the `audit_event_types!`
//!    declaration — that one line yields the variant, its
//!    [`AuditEventType::as_str`] wire string (the `audit_log.event_type`
//!    TEXT value; keep TS wire-compat by matching the exact literal in
//!    `fuz_app/src/lib/auth/audit_emitter.ts`), its
//!    [`AuditEventType::from_wire`] parse arm, and its
//!    [`AuditEventType::ALL`] entry.
//! 2. Add a row to [`AUDIT_EVENT_SPECS`] declaring the routing per
//!    outcome **and** the [`RevocationScope`], and the TS-literal pair in
//!    `wire_strings_match_ts_audit_emitter_literals` — the `ALL`-driven
//!    completeness asserts fail until both exist.
//!
//! The lookup is a linear scan over a small static table — fine at every
//! emit site; convert to `phf` only if the table grows past a few
//! hundred entries.

use crate::audit_emitter::AuditOutcome;
use crate::name_schema::NAME_LENGTH_MAX;

/// Declares [`AuditEventType`] together with its wire strings and the
/// complete [`AuditEventType::ALL`] listing — one declaration, three
/// artifacts, so none can drift from the others. The hand-maintained test
/// lists this replaces are exactly how `CellModerate` went missing from two
/// of them: nothing forced a new variant into a list the compiler never saw.
macro_rules! audit_event_types {
    ( $( $(#[$meta:meta])* $variant:ident => $wire:literal, )+ ) => {
        /// Closed set of audit event types the spine emits.
        ///
        /// `#[non_exhaustive]` so adding a variant isn't a downstream-breaking
        /// change — but every variant MUST have a row in [`AUDIT_EVENT_SPECS`]
        /// (enforced by the [`AuditEventType::ALL`]-driven
        /// `every_variant_has_a_spec_row` test; missing rows also panic at
        /// first use via the `unreachable!` in [`audit_event_spec`]).
        ///
        /// Wire-format strings (used in the `audit_log.event_type` TEXT column
        /// and emitted over the audit-listener fan-out) come from
        /// [`AuditEventType::as_str`]; the `Serialize` impl serializes via that
        /// string so JSON shapes are unchanged.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum AuditEventType {
            $( $(#[$meta])* $variant, )+
        }

        impl AuditEventType {
            /// Every variant, in declaration order. Single-sourced from the
            /// `audit_event_types!` declaration, so it is complete by
            /// construction — tests iterate this to hold the spec table and
            /// the TS wire-literal pins to the full variant set.
            pub const ALL: &'static [Self] = &[ $(Self::$variant),+ ];

            /// Wire-format string. Must match `fuz_app/src/lib/auth/audit_emitter.ts`'s
            /// `event_type` literals — TS is the parity contract.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire,)+ }
            }

            /// Inverse of [`as_str`](Self::as_str) — the wire-format string
            /// back to its variant.
            ///
            /// `None` for a string this enum has no variant for, which is a
            /// legitimate runtime case: `audit_log.event_type` is an open
            /// TEXT column and a consumer emits its own names through
            /// [`AuditEventKind::Custom`]. Callers that dispatch policy off
            /// the result must therefore have a defined answer for `None` —
            /// [`revocation_scope_for_wire`] resolves it to
            /// [`RevocationScope::None`], which is what keeps a consumer's
            /// custom event from silently closing connections.
            #[must_use]
            pub fn from_wire(wire: &str) -> Option<Self> {
                match wire { $($wire => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}

audit_event_types! {
    // --- account self-service ---
    /// Account-grain session login (REST handler).
    Login => "login",
    /// Account-grain session logout (REST handler).
    Logout => "logout",
    /// Account signup (REST handler).
    Signup => "signup",
    /// Password change (REST handler).
    PasswordChange => "password_change",
    /// Account-grain self-service single-session revoke.
    SessionRevoke => "session_revoke",
    /// Account-grain self-service revoke-all-sessions. Admin-grain
    /// cross-account revoke reuses this same `event_type` and carries
    /// `target_account_id` to distinguish.
    SessionRevokeAll => "session_revoke_all",
    /// API token created via session-only self-service.
    TokenCreate => "token_create",
    /// API token revoked via session-only self-service.
    TokenRevoke => "token_revoke",

    // --- admin / cross-account ---
    /// Admin revoke-all-tokens for a target account.
    TokenRevokeAll => "token_revoke_all",
    /// Admin-created invite.
    InviteCreate => "invite_create",
    /// Admin-deleted invite. Failure outcome on `invite_not_found`
    /// also routes here.
    InviteDelete => "invite_delete",

    // --- account / actor lifecycle ---
    /// Account soft-deleted (reversible tombstone — `account.deleted_at`
    /// stamped, sessions + tokens revoked). Admin-gated. Metadata
    /// snapshots `{username, email}` so the row is self-describing.
    AccountDelete => "account_delete",
    /// Account hard-purged (irreversible cascading DB removal).
    /// Keeper-gated + explicit confirm. Metadata snapshots
    /// `{username, email}` so identity survives the row removal.
    AccountPurge => "account_purge",
    /// Account reactivated (soft-delete tombstone cleared — the inverse of
    /// `AccountDelete`). Admin-gated; no self path (a tombstoned account
    /// can't authenticate). Metadata snapshots `{username, email}`.
    AccountUndelete => "account_undelete",
    /// Actor soft-deleted. Emitted per actor alongside the
    /// account-level event. Metadata snapshots `{name}`.
    ActorDelete => "actor_delete",
    /// Actor hard-purged. Emitted per actor alongside
    /// `AccountPurge`. Metadata snapshots `{name}`.
    ActorPurge => "actor_purge",
    /// Actor reactivated. Emitted per actor alongside `AccountUndelete`.
    /// Metadata snapshots `{name}`.
    ActorUndelete => "actor_undelete",

    // --- bootstrap ---
    /// First-boot bootstrap (the keeper-installer flow).
    Bootstrap => "bootstrap",

    // --- consent-flow / role grant offer ---
    /// Role grant offer created (admin-grantable role).
    RoleGrantOfferCreate => "role_grant_offer_create",
    /// Role grant offer accepted by the targeted recipient.
    RoleGrantOfferAccept => "role_grant_offer_accept",
    /// Role grant offer declined by the targeted recipient.
    RoleGrantOfferDecline => "role_grant_offer_decline",
    /// Role grant offer retracted by the grantor pre-decision.
    RoleGrantOfferRetract => "role_grant_offer_retract",
    /// Pending offer past `expires_at`, surfaced by the periodic sweep.
    RoleGrantOfferExpire => "role_grant_offer_expire",
    /// Sibling offer superseded as a side effect of accept or revoke.
    RoleGrantOfferSupersede => "role_grant_offer_supersede",
    /// Role grant row created via offer accept.
    RoleGrantCreate => "role_grant_create",
    /// Active role grant revoked (admin-only).
    RoleGrantRevoke => "role_grant_revoke",

    // --- app settings ---
    /// Global app settings updated (e.g. `open_signup` toggle). Account-shape
    /// event: metadata carries `{setting, old_value, new_value}`.
    AppSettingsUpdate => "app_settings_update",

    // --- db-admin browser (`fuz_db_admin`) ---
    /// Row deleted through the generic db-admin table browser. Emitted only
    /// on a successful delete (post-composite-refusal the delete is provably
    /// single-row, so no count). Account-grain attribution — the browser's
    /// gate is account-grain, so no actor is claimed. Metadata carries
    /// `{table, pk_column, id}`.
    DbAdminRowDelete => "db_admin_row_delete",

    // --- cell content primitive (`fuz_cell`) ---
    // Cell is a spine crate (the twin of fuz_app's TS cell layer), so its
    // events are spine-canonical — pinned against the TS literals like the
    // auth events. (On the TS side they register as consumer "extra events";
    // the wire contract is identical, only the registration mechanism
    // differs — parity is on the emitted rows, not the registry shape.)
    /// Cell created.
    CellCreate => "cell_create",
    /// Cell `data` / `visibility` / `path` updated.
    CellUpdate => "cell_update",
    /// Cell soft-deleted.
    CellDelete => "cell_delete",
    /// Cell cloned (shallow or deep depth-1).
    CellClone => "cell_clone",
    /// Gated contribution moderated (`pending → approved | rejected`, or the
    /// `approved → rejected` takedown) by an authority over the governing root.
    CellModerate => "cell_moderate",
    /// A root's contribution policy set or cleared (`cell_policy_set`) by its
    /// manager.
    CellPolicySet => "cell_policy_set",
    /// Cell grant created (or re-leveled via UPSERT).
    CellGrantCreate => "cell_grant_create",
    /// Cell grant revoked (manage-tier or actor self-revoke).
    CellGrantRevoke => "cell_grant_revoke",
    /// Named relation set (`(source, name) → target`).
    CellFieldSet => "cell_field_set",
    /// Named relation deleted.
    CellFieldDelete => "cell_field_delete",
    /// Ordered child inserted.
    CellItemInsert => "cell_item_insert",
    /// Ordered child moved to a new position.
    CellItemMove => "cell_item_move",
    /// Ordered child removed.
    CellItemDelete => "cell_item_delete",
}

impl serde::Serialize for AuditEventType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Routing axis for an audit emit — pool-routed (rollback-resilient)
/// or in-tx (atomic with the handler's transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRouting {
    /// Pool-routed, fire-and-forget on a separate connection from the
    /// shared pool. Survives the request transaction rolling back —
    /// use for ATTEMPT and FAILURE audits where forensic record must
    /// outlive a denied operation.
    Pool,
    /// In-tx — INSERT runs against the handler's transaction client.
    /// Atomic with the handler: the audit row commits iff the request
    /// tx commits. Use for SUCCESS audits paired with a state mutation
    /// where the audit and state should land together or neither.
    InTx,
}

/// What a **successful** audit row invalidates — the axis the revocation
/// listener dispatches on.
///
/// ## Why this is a column and not a list
///
/// The spine closes live connections in reaction to audit rows in one place:
/// `register_revocation_guard`, whose
/// [`ConnectionCloseTarget::from_audit_event`](crate::ConnectionCloseTarget::from_audit_event)
/// reads the row's scope here and turns it into the one close target every
/// transport closes by — WebSocket sockets and SSE streams alike, through the
/// consumer's [`ConnectionCloser`](crate::ConnectionCloser). Kept as a
/// hand-maintained `&str` list matched against wire literals, the set of
/// revoking events would drift from the events themselves — the failure
/// [`AuditEventType`] itself exists to prevent.
///
/// Declaring the disposition here, once per event, means a new
/// [`AuditEventType`] variant cannot compile without answering the question
/// (it needs an [`AUDIT_EVENT_SPECS`] row), and every reader of it — the
/// listener and any consumer's own match — reads the same answer.
///
/// ## Deliberately not `#[non_exhaustive]`
///
/// [`AuditEventType`] is `#[non_exhaustive]` so adding a variant isn't a
/// downstream break. This enum is the opposite on purpose: it is matched
/// **wildcard-free**, and a `#[non_exhaustive]` here would force every match
/// outside this crate to carry a `_` arm, which is precisely the
/// silent-default this type exists to remove. Adding a variant is meant to
/// break every downstream match until each declares what it does with it.
///
/// ## What the listener does with it
///
/// The variant says what the row invalidated, and `from_audit_event` names
/// its arm for every variant, so the handling is a visible decision instead
/// of a missing entry. On [`Role`](Self::Role) the close ends the sockets
/// and the streams gated on the revoked role — a role-gated socket receives
/// every server push its endpoint sends, which no per-message
/// re-authorization re-checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationScope {
    /// The row invalidates no live connection. The default answer, and the
    /// one a consumer's custom event resolves to.
    None,
    /// One session — the connection whose session-token hash equals the row's
    /// `metadata.session_id`. Narrower than the account on purpose: closing
    /// every connection for a single-session revoke is over-aggressive.
    Session,
    /// One API token — the connection whose `api_token.id` equals the row's
    /// `metadata.token_id`.
    Token,
    /// Every connection on `target_account_id ?? account_id`.
    Account,
    /// The target account's connections whose gating role equals the row's
    /// `metadata.role`, when the revoked grant was global
    /// ([`ConnectionCloseTarget::from_audit_event`](crate::ConnectionCloseTarget::from_audit_event)
    /// — a role gate admits on global grants only).
    Role,
}

/// Declared routing for one [`AuditEventType`].
///
/// The fields encode the **intended** routing per outcome — what the
/// handler authors and compliance reviewers expect. The dispatcher's
/// rollback behavior is a separate concern (in-tx writes inside an
/// Err-returning handler get rolled back regardless of what the table
/// says).
#[derive(Debug, Clone, Copy)]
pub struct AuditEventSpec {
    pub event_type: AuditEventType,
    /// Routing for `outcome: Success` emits. Typically `InTx` on
    /// state-mutating action handlers; `Pool` on REST handlers that
    /// don't dispatch through a request transaction.
    pub success_routing: AuditRouting,
    /// Routing for `outcome: Failure` emits. Typically `Pool` —
    /// failure-outcome audits emitted on an Err path would be rolled
    /// back with the handler if routed in-tx.
    pub failure_routing: AuditRouting,
    /// What a **`Success`** row of this event invalidates, for the revocation
    /// guard (WS and SSE alike). `Failure` rows never revoke on either transport
    /// (they carry caller-submitted metadata), so this axis has no
    /// per-outcome split.
    pub revocation_scope: RevocationScope,
}

impl AuditEventSpec {
    /// Pick the routing for the given outcome.
    #[must_use]
    pub const fn routing_for(&self, outcome: AuditOutcome) -> AuditRouting {
        match outcome {
            AuditOutcome::Success => self.success_routing,
            AuditOutcome::Failure => self.failure_routing,
        }
    }
}

/// Per-event routing policy for every [`AuditEventType`].
///
/// The canonical declaration of which audit events are atomic-with-state
/// vs rollback-resilient. Audit checklist / compliance reviewers read
/// this single table to see the routing for every event the spine
/// emits.
///
/// Conventions encoded here:
///
/// - **Action-spec success audits** that pair with a state mutation
///   route `InTx` on success (the state row + audit row land
///   atomically). Failure audits on the same events route `Pool` so
///   the forensic record survives the rollback that discards the
///   attempted state change.
/// - **REST-handler events** (`Login`, `Logout`, `Signup`,
///   `PasswordChange`, `Bootstrap`) route `Pool` on both outcomes —
///   they don't dispatch through the action transaction-wrap today.
///   When REST handlers are lifted into the action-dispatch model, the
///   table flips to `InTx` on success.
/// - **[`RevocationScope`]** is [`None`](RevocationScope::None) unless the
///   event's success *invalidates a live connection's credential or access*.
///   Nine rows are not: `Logout` / `PasswordChange` / `SessionRevokeAll` /
///   `TokenRevokeAll` / `AccountDelete` / `AccountPurge` are account-wide,
///   `SessionRevoke` and `TokenRevoke` name the one credential they killed,
///   and `RoleGrantRevoke` names the lost role. Granting access
///   (`RoleGrantCreate`, `TokenCreate`, `AccountUndelete`) revokes nothing,
///   and neither does an event about a *different* subject than a live
///   connection's identity (the `Cell*` and `Actor*` families, `InviteDelete`,
///   `DbAdminRowDelete`).
///
/// Add a new event by extending [`AuditEventType`] and appending a row
/// here. The order isn't load-bearing.
pub static AUDIT_EVENT_SPECS: &[AuditEventSpec] = &[
    // --- REST handlers — pool-routed everywhere (no dispatcher tx today) ---
    AuditEventSpec {
        event_type: AuditEventType::Login,
        success_routing: AuditRouting::Pool,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::Logout,
        success_routing: AuditRouting::Pool,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Account,
    },
    AuditEventSpec {
        event_type: AuditEventType::Signup,
        success_routing: AuditRouting::Pool,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::PasswordChange,
        success_routing: AuditRouting::Pool,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Account,
    },
    AuditEventSpec {
        event_type: AuditEventType::Bootstrap,
        success_routing: AuditRouting::Pool,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::DbAdminRowDelete,
        success_routing: AuditRouting::Pool,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    // --- Action specs — success atomic with state, failure pool-routed ---
    AuditEventSpec {
        event_type: AuditEventType::SessionRevoke,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Session,
    },
    AuditEventSpec {
        event_type: AuditEventType::SessionRevokeAll,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Account,
    },
    AuditEventSpec {
        event_type: AuditEventType::TokenCreate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::TokenRevoke,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Token,
    },
    AuditEventSpec {
        event_type: AuditEventType::TokenRevokeAll,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Account,
    },
    AuditEventSpec {
        event_type: AuditEventType::InviteCreate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::InviteDelete,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    // --- account / actor deletion — success atomic with the mutation,
    // failure pool-routed (forensic record of a denied delete/purge). ---
    AuditEventSpec {
        event_type: AuditEventType::AccountDelete,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Account,
    },
    AuditEventSpec {
        event_type: AuditEventType::AccountPurge,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Account,
    },
    AuditEventSpec {
        event_type: AuditEventType::AccountUndelete,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::ActorDelete,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::ActorPurge,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::ActorUndelete,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::RoleGrantOfferCreate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::RoleGrantOfferAccept,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::RoleGrantOfferDecline,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::RoleGrantOfferRetract,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::RoleGrantOfferExpire,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::RoleGrantOfferSupersede,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::RoleGrantCreate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::RoleGrantRevoke,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::Role,
    },
    // --- app settings — success atomic with the mutation ---
    AuditEventSpec {
        event_type: AuditEventType::AppSettingsUpdate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    // --- cell content primitive — success atomic with the mutation,
    // failure pool-routed (the cell handlers emit on success only today). ---
    AuditEventSpec {
        event_type: AuditEventType::CellCreate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellUpdate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellDelete,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellClone,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellModerate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellPolicySet,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellGrantCreate,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellGrantRevoke,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellFieldSet,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellFieldDelete,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellItemInsert,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellItemMove,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
    AuditEventSpec {
        event_type: AuditEventType::CellItemDelete,
        success_routing: AuditRouting::InTx,
        failure_routing: AuditRouting::Pool,
        revocation_scope: RevocationScope::None,
    },
];

/// Look up the [`AuditEventSpec`] for an event type.
///
/// Panics with `unreachable!` if a variant is missing from
/// [`AUDIT_EVENT_SPECS`] — every [`AuditEventType`] MUST have a spec
/// row. The panic is a development-time bug, not a runtime
/// condition.
#[must_use]
pub fn audit_event_spec(event_type: AuditEventType) -> &'static AuditEventSpec {
    AUDIT_EVENT_SPECS
        .iter()
        .find(|s| s.event_type == event_type)
        .unwrap_or_else(|| unreachable!("missing AuditEventSpec row for {event_type:?}"))
}

/// [`RevocationScope`] for a wire-format `audit_log.event_type` string.
///
/// The entry point the revocation guard uses, since an [`AuditLogEvent`]
/// carries its event type as the open TEXT column, not as an
/// [`AuditEventType`].
///
/// A string with no variant — a consumer's custom event — resolves to
/// [`RevocationScope::None`]. That default is the safe one *here* and only
/// here: a consumer event the spine has never heard of must not close another
/// crate's connections. A consumer that does want its own event to revoke
/// closes the connections from its handler, the way `account_delete` queues
/// a post-commit close through
/// [`AuthenticatedActionContext::close_connections_after_commit`](crate::AuthenticatedActionContext::close_connections_after_commit).
///
/// [`AuditLogEvent`]: crate::AuditLogEvent
#[must_use]
pub fn revocation_scope_for_wire(event_type: &str) -> RevocationScope {
    AuditEventType::from_wire(event_type).map_or(RevocationScope::None, |t| {
        audit_event_spec(t).revocation_scope
    })
}

/// Audit event identity for an emit — a spine-canonical [`AuditEventType`]
/// or a consumer-defined custom event.
///
/// The `audit_log.event_type` column is an open TEXT string (see
/// `audit_event_schema`), so a consumer extends the audit log by emitting
/// its own event names. Spine events route via [`AUDIT_EVENT_SPECS`]; custom
/// events carry their own per-outcome routing since they have no spec row.
/// `Serialize` emits the wire string, so JSON shapes are identical across
/// variants. Build via [`crate::AuditLogInput::for_event`] (spine) or
/// [`crate::AuditLogInput::for_custom_event`] (consumer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventKind {
    /// A spine-canonical event; routing comes from [`AUDIT_EVENT_SPECS`].
    Spine(AuditEventType),
    /// A consumer-defined event, carrying its own routing.
    Custom {
        /// Wire-format event name (the `audit_log.event_type` string).
        name: &'static str,
        /// Routing for a `Success` outcome.
        success_routing: AuditRouting,
        /// Routing for a `Failure` outcome.
        failure_routing: AuditRouting,
    },
}

impl AuditEventKind {
    /// Wire-format string for the `audit_log.event_type` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spine(event_type) => event_type.as_str(),
            Self::Custom { name, .. } => name,
        }
    }

    /// Resolve the routing for `outcome` — spine events consult
    /// [`AUDIT_EVENT_SPECS`]; custom events use their carried routing.
    #[must_use]
    pub fn routing_for(self, outcome: AuditOutcome) -> AuditRouting {
        match self {
            Self::Spine(event_type) => audit_event_spec(event_type).routing_for(outcome),
            Self::Custom {
                success_routing,
                failure_routing,
                ..
            } => match outcome {
                AuditOutcome::Success => success_routing,
                AuditOutcome::Failure => failure_routing,
            },
        }
    }
}

impl From<AuditEventType> for AuditEventKind {
    fn from(event_type: AuditEventType) -> Self {
        Self::Spine(event_type)
    }
}

impl serde::Serialize for AuditEventKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Whether `s` is a valid audit event-type name — a letter, then letters,
/// digits, `_`, `.`, `/` and `-`, at most [`NAME_LENGTH_MAX`] long: its own
/// grammar under the shared name cap.
///
/// Twin of the TS `AuditEventTypeName` (`/^[A-Za-z][A-Za-z0-9_./-]*$/` under
/// `NAME_LENGTH_MAX`, in `fuz_app`'s `auth/audit_log_schema.ts`): `snake_case`,
/// dotted and namespaced consumer names pass; an empty string, a leading
/// separator or digit, whitespace, control characters, non-ASCII letters and a
/// name past the cap (bytes, which on the grammar are its UTF-16 code units)
/// do not. It
/// judges a name a caller supplies (the `audit_log_list` filter), not the
/// spine's own [`AuditEventType`] wire strings, which all pass.
///
/// Hand-rolled instead of regex, for the same reason
/// [`crate::primitive_schemas::is_valid_username_for_creation`] is: `regex`
/// isn't a workspace dependency, and a byte scan is faster than a DFA compile.
/// A `const fn` (an indexed byte loop) so
/// [`crate::AuditLogInput::for_custom_event`] can assert a consumer's name in
/// `const` context.
#[must_use]
pub const fn is_valid_audit_event_type_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > NAME_LENGTH_MAX || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        if !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-')) {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `name` is the wire string of a spine-canonical [`AuditEventType`].
///
/// A `const fn` (indexed byte loops) so
/// [`crate::AuditLogInput::for_custom_event`] can refuse a custom name that
/// collides with a spine event — one the revocation guard and the
/// `audit_log_list` filter would read as the spine's own.
#[must_use]
pub(crate) const fn is_spine_audit_event_type_name(name: &str) -> bool {
    let name = name.as_bytes();
    let mut i = 0;
    while i < AuditEventType::ALL.len() {
        let wire = AuditEventType::ALL[i].as_str().as_bytes();
        if wire.len() == name.len() {
            let mut j = 0;
            while j < wire.len() && wire[j] == name[j] {
                j += 1;
            }
            if j == wire.len() {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `AuditEventTypeName` grammar, row for row: the shapes it admits and
    /// one of each it refuses.
    #[test]
    fn audit_event_type_name_grammar() {
        for name in [
            "login",
            "a",
            "Z9",
            "cell_create",
            "app.event",
            "ns/event-name",
            "x_.-/",
            // fuz_app's `extra_events` acceptance cases
            "app.classroom.create",
            "app/classroom/update",
            "app-classroom-delete",
            "app_classroom_archive",
        ] {
            assert!(is_valid_audit_event_type_name(name), "{name:?} should pass");
        }
        for name in [
            "",
            "_login",
            "9login",
            ".login",
            "/login",
            "-login",
            "log in",
            "login\n",
            "login\0",
            "'; DROP TABLE --",
            "l\u{f6}gin",
            "\u{c4}rger",
            "login!",
            // fuz_app's `extra_events` refusal cases
            " login_alt",
            ".classroom_create",
            "classroom create",
            "1classroom_create",
        ] {
            assert!(
                !is_valid_audit_event_type_name(name),
                "{name:?} should fail"
            );
        }
        // every spine event type is on the grammar, its cap included
        for event_type in AuditEventType::ALL {
            assert!(is_valid_audit_event_type_name(event_type.as_str()));
        }
    }

    /// The grammar takes the shared name cap, as the twin's
    /// `AuditEventTypeName` does.
    #[test]
    fn an_audit_event_type_name_is_capped_at_the_name_length_max() {
        assert_eq!(NAME_LENGTH_MAX, 64);
        let at_max = format!("app.{}", "a".repeat(NAME_LENGTH_MAX - 4));
        assert_eq!(at_max.len(), NAME_LENGTH_MAX);
        assert!(is_valid_audit_event_type_name(&at_max));
        assert!(!is_valid_audit_event_type_name(&format!("{at_max}a")));
    }

    /// Every spine wire string is reserved; typical consumer custom names
    /// (an app's own domain events) don't collide with one.
    #[test]
    fn spine_audit_event_type_names_are_reserved() {
        for et in AuditEventType::ALL {
            assert!(
                is_spine_audit_event_type_name(et.as_str()),
                "{:?} should be reserved",
                et.as_str()
            );
        }
        for name in [
            // a group-chat app
            "group_create",
            "group_update",
            "group_invite_create",
            "group_invite_accept",
            "group_invite_redeem",
            "group_invite_revoke",
            "group_invite_expire",
            // a classroom app
            "classroom_create",
            "classroom_update",
            "classroom_delete",
            "classroom_join_request_create",
            "classroom_join_request_decide",
            "classroom_invite_create",
            "classroom_invite_resolve",
            "admin_orphan_facts_delete",
            "upload_image",
            // near misses of a spine name
            "session_revoke_al",
            "session_revoke_all_",
            "",
        ] {
            assert!(
                !is_spine_audit_event_type_name(name),
                "{name:?} should not be reserved"
            );
        }
        const { assert!(is_spine_audit_event_type_name("session_revoke_all")) };
    }

    /// The grammar evaluates in `const` context — what lets
    /// `AuditLogInput::for_custom_event` refuse an off-grammar name at compile
    /// time.
    #[test]
    fn audit_event_type_name_grammar_is_const() {
        const { assert!(is_valid_audit_event_type_name("app.classroom.create")) };
        const { assert!(!is_valid_audit_event_type_name("1classroom_create")) };
    }

    #[test]
    fn every_variant_has_a_spec_row() {
        // `ALL` is complete by construction (single-sourced from the
        // `audit_event_types!` declaration), so this covers every variant —
        // no hand list to forget. The length check catches a duplicate or
        // orphaned spec row.
        for et in AuditEventType::ALL {
            let _ = audit_event_spec(*et);
        }
        assert_eq!(
            AUDIT_EVENT_SPECS.len(),
            AuditEventType::ALL.len(),
            "one spec row per variant — no duplicates, no orphans",
        );
    }

    #[test]
    fn wire_strings_match_ts_audit_emitter_literals() {
        // Pins every variant's wire string against the TS literal in
        // `fuz_app/src/lib/auth/audit_emitter.ts`. The
        // `audit_log.event_type` TEXT column is the cross-impl wire
        // contract — any rename here without a TS-side rename
        // (the twins rename together) breaks
        // every consumer reading the audit log.
        //
        // When porting a new TS event_type, add the variant to
        // `AuditEventType`, the row to `AUDIT_EVENT_SPECS`, and the pair
        // below.
        let pairs: &[(AuditEventType, &str)] = &[
            // REST handlers
            (AuditEventType::Login, "login"),
            (AuditEventType::Logout, "logout"),
            (AuditEventType::Signup, "signup"),
            (AuditEventType::PasswordChange, "password_change"),
            (AuditEventType::Bootstrap, "bootstrap"),
            // Account self-service
            (AuditEventType::SessionRevoke, "session_revoke"),
            (AuditEventType::SessionRevokeAll, "session_revoke_all"),
            (AuditEventType::TokenCreate, "token_create"),
            (AuditEventType::TokenRevoke, "token_revoke"),
            // Admin / cross-account
            (AuditEventType::TokenRevokeAll, "token_revoke_all"),
            (AuditEventType::InviteCreate, "invite_create"),
            (AuditEventType::InviteDelete, "invite_delete"),
            // Account / actor lifecycle
            (AuditEventType::AccountDelete, "account_delete"),
            (AuditEventType::AccountPurge, "account_purge"),
            (AuditEventType::AccountUndelete, "account_undelete"),
            (AuditEventType::ActorDelete, "actor_delete"),
            (AuditEventType::ActorPurge, "actor_purge"),
            (AuditEventType::ActorUndelete, "actor_undelete"),
            // Consent-flow / role grant offer
            (
                AuditEventType::RoleGrantOfferCreate,
                "role_grant_offer_create",
            ),
            (
                AuditEventType::RoleGrantOfferAccept,
                "role_grant_offer_accept",
            ),
            (
                AuditEventType::RoleGrantOfferDecline,
                "role_grant_offer_decline",
            ),
            (
                AuditEventType::RoleGrantOfferRetract,
                "role_grant_offer_retract",
            ),
            (
                AuditEventType::RoleGrantOfferExpire,
                "role_grant_offer_expire",
            ),
            (
                AuditEventType::RoleGrantOfferSupersede,
                "role_grant_offer_supersede",
            ),
            (AuditEventType::RoleGrantCreate, "role_grant_create"),
            (AuditEventType::RoleGrantRevoke, "role_grant_revoke"),
            // App settings
            (AuditEventType::AppSettingsUpdate, "app_settings_update"),
            // db-admin browser
            (AuditEventType::DbAdminRowDelete, "db_admin_row_delete"),
            // Cell content primitive
            (AuditEventType::CellCreate, "cell_create"),
            (AuditEventType::CellUpdate, "cell_update"),
            (AuditEventType::CellDelete, "cell_delete"),
            (AuditEventType::CellClone, "cell_clone"),
            (AuditEventType::CellModerate, "cell_moderate"),
            (AuditEventType::CellPolicySet, "cell_policy_set"),
            (AuditEventType::CellGrantCreate, "cell_grant_create"),
            (AuditEventType::CellGrantRevoke, "cell_grant_revoke"),
            (AuditEventType::CellFieldSet, "cell_field_set"),
            (AuditEventType::CellFieldDelete, "cell_field_delete"),
            (AuditEventType::CellItemInsert, "cell_item_insert"),
            (AuditEventType::CellItemMove, "cell_item_move"),
            (AuditEventType::CellItemDelete, "cell_item_delete"),
        ];
        // Exactly one pin per variant — a bare length assert would still
        // pass with a duplicated pair shadowing a missing variant.
        for et in AuditEventType::ALL {
            assert_eq!(
                pairs.iter().filter(|(v, _)| v == et).count(),
                1,
                "exactly one TS wire-literal pin for {et:?}",
            );
        }
        for &(variant, expected) in pairs {
            assert_eq!(
                variant.as_str(),
                expected,
                "{variant:?} wire string drifted from TS literal"
            );
        }
    }

    #[test]
    fn routing_for_picks_per_outcome() {
        let spec = audit_event_spec(AuditEventType::TokenCreate);
        assert_eq!(spec.routing_for(AuditOutcome::Success), AuditRouting::InTx);
        assert_eq!(spec.routing_for(AuditOutcome::Failure), AuditRouting::Pool);
    }

    #[test]
    fn rest_handler_events_are_pool_on_both_outcomes() {
        for et in [
            AuditEventType::Login,
            AuditEventType::Logout,
            AuditEventType::Signup,
            AuditEventType::PasswordChange,
            AuditEventType::Bootstrap,
        ] {
            let spec = audit_event_spec(et);
            assert_eq!(
                spec.success_routing,
                AuditRouting::Pool,
                "{et:?} success should be Pool (no dispatcher tx)"
            );
            assert_eq!(
                spec.failure_routing,
                AuditRouting::Pool,
                "{et:?} failure should be Pool"
            );
        }
    }

    /// `from_wire` is the inverse of `as_str` on every variant. Generated
    /// from the same macro arm, so this is a shape assert rather than a
    /// drift one — but a hand edit to either match is exactly the kind of
    /// change that would otherwise go unnoticed.
    #[test]
    fn from_wire_round_trips_every_variant() {
        for et in AuditEventType::ALL {
            assert_eq!(
                AuditEventType::from_wire(et.as_str()),
                Some(*et),
                "{et:?} does not round-trip through its wire string"
            );
        }
        assert_eq!(
            AuditEventType::from_wire("fuz_forge_repo_updated"),
            None,
            "a consumer's custom event is not a spine variant"
        );
    }

    /// **The revocation table is the one the revocation guard reads.**
    ///
    /// Pins the whole non-`None` set by name. A variant silently dropping to
    /// `None` fails here, and so does one silently gaining a scope.
    #[test]
    fn the_revoking_events_are_the_expected_ones() {
        let expected: &[(AuditEventType, RevocationScope)] = &[
            (AuditEventType::Logout, RevocationScope::Account),
            (AuditEventType::PasswordChange, RevocationScope::Account),
            (AuditEventType::SessionRevoke, RevocationScope::Session),
            (AuditEventType::SessionRevokeAll, RevocationScope::Account),
            (AuditEventType::TokenRevoke, RevocationScope::Token),
            (AuditEventType::TokenRevokeAll, RevocationScope::Account),
            (AuditEventType::AccountDelete, RevocationScope::Account),
            (AuditEventType::AccountPurge, RevocationScope::Account),
            (AuditEventType::RoleGrantRevoke, RevocationScope::Role),
        ];
        for &(et, scope) in expected {
            assert_eq!(
                audit_event_spec(et).revocation_scope,
                scope,
                "{et:?} declares the wrong revocation scope"
            );
        }
        // ...and nothing else revokes. Driven off `ALL`, so a new variant
        // that declares a scope without being listed above fails here.
        for et in AuditEventType::ALL {
            if expected.iter().any(|(v, _)| v == et) {
                continue;
            }
            assert_eq!(
                audit_event_spec(*et).revocation_scope,
                RevocationScope::None,
                "{et:?} revokes but is not in the expected set — add it here \
                 and to the revocation guard's coverage"
            );
        }
    }

    /// **A pool-routed revocation is closed by its handler, not the listener.**
    ///
    /// A pool-routed success audit is fail-open: the revocation commits whether
    /// or not the audit INSERT lands, and the revocation guard fires only on
    /// a written row. So for these events the handler's direct
    /// `ConnectionCloser` close is the only close guaranteed to run — which is
    /// why it closes account-wide before the audit write, through a closer
    /// that reaches SSE as well as WS. An in-tx revocation needs no such care:
    /// a failed INSERT fails the handler and rolls the revocation back.
    ///
    /// Pins the set exactly. A new pool-routed closer — or one of these
    /// moving to another scope — fails here, and the question it raises is
    /// whether its handler closes directly on every transport. A pool-routed
    /// `Role` revocation in particular has no direct-close path today: no
    /// handler closes a `ConnectionCloseTarget::Role`, which only the audit
    /// listener reaches.
    #[test]
    fn the_pool_routed_revocations_are_logout_and_password_change() {
        let mut pool_routed: Vec<(AuditEventType, RevocationScope)> = AUDIT_EVENT_SPECS
            .iter()
            .filter(|spec| {
                spec.revocation_scope != RevocationScope::None
                    && spec.success_routing == AuditRouting::Pool
            })
            .map(|spec| (spec.event_type, spec.revocation_scope))
            .collect();
        // The table's row order isn't load-bearing, so neither is this one's.
        pool_routed.sort_by_key(|(event_type, _)| event_type.as_str());
        assert_eq!(
            pool_routed,
            [
                (AuditEventType::Logout, RevocationScope::Account),
                (AuditEventType::PasswordChange, RevocationScope::Account),
            ],
            "a pool-routed revocation's close must not depend on its audit \
             write — confirm its handler closes directly on every transport",
        );
    }

    /// The listeners' entry point resolves through the table, and gives a
    /// consumer's custom event the inert answer.
    #[test]
    fn revocation_scope_for_wire_reads_the_table() {
        assert_eq!(
            revocation_scope_for_wire("token_revoke"),
            RevocationScope::Token
        );
        assert_eq!(
            revocation_scope_for_wire("role_grant_revoke"),
            RevocationScope::Role
        );
        assert_eq!(
            revocation_scope_for_wire("login"),
            RevocationScope::None,
            "a successful login revokes nothing through the listeners — the \
             sessions its cap evicts are closed by the login handler itself"
        );
        assert_eq!(
            revocation_scope_for_wire("fuz_forge_repo_updated"),
            RevocationScope::None,
            "a consumer's custom event must not close spine connections"
        );
    }

    #[test]
    fn spine_event_kind_delegates_to_event_type() {
        let kind = AuditEventKind::Spine(AuditEventType::CellCreate);
        assert_eq!(kind.as_str(), "cell_create");
        // Spine routing comes from the spec table.
        let spec = audit_event_spec(AuditEventType::CellCreate);
        assert_eq!(
            kind.routing_for(AuditOutcome::Success),
            spec.routing_for(AuditOutcome::Success)
        );
        assert_eq!(
            serde_json::to_value(kind).unwrap(),
            serde_json::Value::String("cell_create".to_owned())
        );
    }

    #[test]
    fn custom_event_kind_carries_name_and_routing() {
        let kind = AuditEventKind::Custom {
            name: "classroom_create",
            success_routing: AuditRouting::InTx,
            failure_routing: AuditRouting::Pool,
        };
        assert_eq!(kind.as_str(), "classroom_create");
        assert_eq!(kind.routing_for(AuditOutcome::Success), AuditRouting::InTx);
        assert_eq!(kind.routing_for(AuditOutcome::Failure), AuditRouting::Pool);
        // Wire shape is the bare string — identical to a spine event.
        assert_eq!(
            serde_json::to_value(kind).unwrap(),
            serde_json::Value::String("classroom_create".to_owned())
        );
    }
}
