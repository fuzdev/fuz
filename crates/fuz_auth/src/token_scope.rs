//! [`TokenScope`] — the per-credential authority narrowing stored on
//! `api_token.scope`.
//!
//! Twin of `fuz_app`'s `token_scope.ts`. The stored document is the wire
//! contract; both spines read the same `api_token.scope` JSONB.
//!
//! ## The whole vocabulary
//!
//! Two variants, and three rules:
//!
//! 1. **[`Full`](TokenScope::Full) must be spelled at mint.**
//!    `account_token_create` takes a required `scope`, the column is `NOT
//!    NULL`, and session / daemon-token credentials resolve to `Full` by
//!    construction. There is no absent state — which is the whole point.
//!    `fuz_forge`'s `fuz_forge_api_token_policy` has the opposite shape (a
//!    missing row means "unscoped, allow everything"), and that permissive
//!    default is the defect this design refuses.
//! 2. **[`Methods`](TokenScope::Methods) denies every method it does not
//!    list.** An empty set is legal and renders the token inert for RPC —
//!    unlike [`CredentialGate::Only(&[])`](crate::CredentialGate), which is
//!    rejected because it renders an *action* unreachable. A token that calls
//!    no RPC is a coherent thing to want (`fuz_forge`'s file-store tokens are
//!    exactly that).
//! 3. **A narrowed token is RPC-only.** `Methods` denies every non-RPC spine
//!    surface outright — `fuz_db_admin`, `fuz_fact_serving`'s bare-hash read,
//!    the audit SSE stream, and the WS upgrade. See
//!    [`admits_non_rpc_surface`](TokenScope::admits_non_rpc_surface) for why
//!    that blunt rule is load-bearing rather than lazy, and for the two
//!    surfaces whose *disposition* differs (`fuz_fact_serving`'s cell-scoped
//!    read and `/api/account/status` answer as for the anonymous caller
//!    instead of refusing — same rule, different remedy).
//!
//! ## Serialized shape
//!
//! ```json
//! {"version": 1, "kind": "full"}
//! {"version": 1, "kind": "full", "grandfathered": true}
//! {"version": 1, "kind": "methods", "methods": ["cell_get", "cell_list"]}
//! ```
//!
//! `version` is carried so the document can grow a `surfaces` arm (per-surface
//! selectivity) or an `extensions` arm (consumer resource-bound grants) without
//! a format break. Neither exists in v1.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::name_schema::is_valid_name_bytes;

/// Current `TokenScope` document version.
pub const TOKEN_SCOPE_VERSION: u32 = 1;

/// Serialized-document cap, in UTF-8 bytes of the document's compact JSON.
///
/// Compact is what [`TokenScopeDocument::to_json`] and the twin's
/// `JSON.stringify` write — never the text Postgres prints a `jsonb` as
/// (`scope::text`), which adds a space after every `:` and `,`. Matches
/// `fuz_app`'s `MAX_TOKEN_SCOPE_BYTES`, which measures the same, and
/// `fuz_forge`'s `MAX_POLICY_BYTES` — method lists are small, and a token whose
/// scope needs more than this is one that wants [`TokenScope::Full`].
pub const MAX_TOKEN_SCOPE_BYTES: usize = 4 * 1024;

/// What a credential is permitted to do, beyond what its account could do.
///
/// Sessions and daemon tokens are always [`Full`](Self::Full): a browser
/// session *is* full account authority (narrowing it is what role grants are
/// for), and the daemon token is singular, filesystem-proved, and keeper-bound.
/// Only API tokens can be narrowed, because only they are minted with an
/// intent that outlives the minting session.
///
/// **Not an `Option<_>`.** An absent scope is exactly the permissive default
/// this type refuses; here the permissive case is a value that has to be
/// typed, exactly as [`CredentialGate::Any`](crate::CredentialGate) is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenScope {
    /// Full account authority — every RPC method, every spine surface.
    Full,
    /// Narrowed: only these RPC methods, and no non-RPC spine surface.
    Methods(BTreeSet<String>),
}

impl TokenScope {
    /// True iff `method` may be dispatched under this scope.
    ///
    /// Consulted by `check_action_auth_post_authorization` between the
    /// credential gate and the role gate.
    #[must_use]
    pub fn admits_method(&self, method: &str) -> bool {
        match self {
            Self::Full => true,
            Self::Methods(methods) => methods.contains(method),
        }
    }

    /// True iff a non-RPC spine surface may be reached under this scope.
    ///
    /// **Rule 3, and it is the load-bearing one.** A method-name allowlist
    /// alone would have been a false promise: `fuz_db_admin` serves paginated
    /// rows of any `public` table (including `account.password_hash`,
    /// `auth_session`, and `api_token`) plus row `DELETE`, gated on a global
    /// role that a bearer credential satisfies. A token whose UI badge read
    /// "scoped to `cell_get`" could still delete an account row.
    ///
    /// So a narrowed token reaches no non-RPC surface at all. That is strictly
    /// more restrictive than naming each surface, needs no vocabulary to
    /// maintain, and is one sentence a user can hold: *a scoped token is
    /// RPC-only*. Per-surface selectivity is a `surfaces` arm the versioned
    /// document can grow later; nothing today wants it.
    ///
    /// **The remedy is the surface's, not this predicate's.** Every gated
    /// surface but two answers `false` with a `403`
    /// ([`token_scope_surface_denied_response`](crate::token_scope_surface_denied_response)).
    /// The exceptions answer as for the anonymous caller instead.
    /// `fuz_fact_serving`'s cell-scoped fact read, reached through
    /// [`AuthGate::public_request_context`](crate::AuthGate::public_request_context),
    /// is *pure-public*, so a refusal would enforce nothing — the holder drops
    /// the `Authorization` header and re-reads every public cell as an
    /// anonymous caller — and it downgrades the credential to anonymous.
    /// `/api/account/status` answers the narrowed token with its anonymous
    /// `401`, which tells the holder no more than dropping the header would.
    /// Same answer from this predicate; the disposition is the route's to
    /// choose, and only a route with an anonymous reading may choose that one.
    #[must_use]
    pub const fn admits_non_rpc_surface(&self) -> bool {
        matches!(self, Self::Full)
    }
}

/// The stored `api_token.scope` document — a [`TokenScope`] plus the row fact
/// of whether it was backfilled.
///
/// `grandfathered` lives here rather than on [`TokenScope`] because it is a
/// fact about the *row* (the `api_token_scope` migration wrote it; no minter
/// chose it) that only the token-list read cares about. The enforcement path
/// never branches on it, which is what stops "grandfathered" from becoming a
/// third authority level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenScopeDocument {
    pub version: u32,
    pub scope: TokenScope,
    /// `true` only for rows the `api_token_scope` migration backfilled — tokens
    /// minted before scoping existed, which hold full authority until
    /// re-minted. Surfaced in the token list so the debt is a visible number
    /// rather than an invisible default; never consulted for authorization.
    pub grandfathered: bool,
}

/// Flat serde shape of [`TokenScopeDocument`].
///
/// The document is *externally* a `kind`-tagged union, but serde's
/// `deny_unknown_fields` is incompatible with `flatten` — the flattened keys
/// read as unknown to the outer struct — and dropping strictness would let a
/// v2 document carrying a grant arm a v1 reader doesn't understand parse as
/// permissively-narrower-than-stored. So the wire shape is one flat strict
/// struct, validated into the enum by [`TokenScopeDocument::parse`].
///
/// This is stricter than the flatten form, not just equivalent: it also refuses
/// the contradiction `{"kind":"full","methods":[…]}`, which a tagged enum would
/// have silently accepted by ignoring the stray field.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTokenScopeDocument {
    version: u32,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    methods: Option<BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    grandfathered: bool,
}

/// `kind` discriminants. Stable wire strings — the TS twin reads these.
const KIND_FULL: &str = "full";
const KIND_METHODS: &str = "methods";

/// The `scope` input `account_token_create` takes: the stored document minus
/// its row-owned fields, `{"kind":"full"}` or
/// `{"kind":"methods","methods":[…]}`.
///
/// Strict, twinning the TS `TokenScopeInput` (a strict `object` per arm): an
/// unknown key — `version` and `grandfathered` included, which the constructors
/// stamp and the migration owns — is refused, never dropped, and so are a
/// `methods` on `kind: "full"` and a `null` `methods`. Duplicate method names
/// collapse into one (the set is what the scope admits).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTokenScopeInput {
    kind: String,
    /// Absent → `None`; a `null` is refused at decode rather than read as
    /// absent.
    #[serde(default, deserialize_with = "deserialize_present")]
    methods: Option<BTreeSet<String>>,
}

/// Decode a present field straight into `T`, so an explicit `null` is `T`'s
/// type error instead of `Option`'s `None` (absence is the field's `default`).
fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl RawTokenScopeInput {
    /// The document a mint stores for this input.
    ///
    /// # Errors
    ///
    /// [`TokenScopeError::Malformed`] on an unknown `kind` or a `kind` /
    /// `methods` disagreement.
    pub fn into_document(self) -> Result<TokenScopeDocument, TokenScopeError> {
        scope_from_parts(&self.kind, self.methods).map(TokenScopeDocument::from_scope)
    }
}

/// The scope a `kind` and an optional `methods` set denote.
///
/// The one `kind`/`methods` agreement rule, shared by the stored-document
/// parse ([`TokenScopeDocument::parse`]) and the mint input
/// ([`RawTokenScopeInput`]).
///
/// # Errors
///
/// [`TokenScopeError::Malformed`] on an unknown `kind`, a `methods` on
/// `kind: "full"`, or a `kind: "methods"` without one.
pub fn scope_from_parts(
    kind: &str,
    methods: Option<BTreeSet<String>>,
) -> Result<TokenScope, TokenScopeError> {
    match (kind, methods) {
        (KIND_FULL, None) => Ok(TokenScope::Full),
        (KIND_METHODS, Some(methods)) => Ok(TokenScope::Methods(methods)),
        (KIND_FULL, Some(_)) => Err(TokenScopeError::Malformed {
            message: "kind \"full\" must not carry a `methods` field".to_owned(),
        }),
        (KIND_METHODS, None) => Err(TokenScopeError::Malformed {
            message: "kind \"methods\" requires a `methods` field".to_owned(),
        }),
        (kind, _) => Err(TokenScopeError::Malformed {
            message: format!("unknown scope kind {kind:?}"),
        }),
    }
}

impl TokenScopeDocument {
    /// A deliberately-minted full-authority scope.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            version: TOKEN_SCOPE_VERSION,
            scope: TokenScope::Full,
            grandfathered: false,
        }
    }

    /// A freshly minted document for `scope` — current version, not
    /// grandfathered.
    #[must_use]
    pub const fn from_scope(scope: TokenScope) -> Self {
        Self {
            version: TOKEN_SCOPE_VERSION,
            scope,
            grandfathered: false,
        }
    }

    /// A narrowed scope over `methods`.
    #[must_use]
    pub const fn methods(methods: BTreeSet<String>) -> Self {
        Self {
            version: TOKEN_SCOPE_VERSION,
            scope: TokenScope::Methods(methods),
            grandfathered: false,
        }
    }

    /// The runtime scope this document denotes.
    #[must_use]
    pub fn to_scope(&self) -> TokenScope {
        self.scope.clone()
    }

    /// Stable label for the token list / UI: `full`, `full (grandfathered)`,
    /// or `N methods`.
    #[must_use]
    pub fn label(&self) -> String {
        match &self.scope {
            TokenScope::Full if self.grandfathered => "full (grandfathered)".to_owned(),
            TokenScope::Full => "full".to_owned(),
            TokenScope::Methods(methods) => format!("{} methods", methods.len()),
        }
    }

    /// Parse a stored document, enforcing the size cap, the version, and the
    /// `kind`/`methods` agreement.
    ///
    /// The cap is measured on the document's compact serialization, not on
    /// `raw`: the stored text is Postgres's `scope::text`, spaced, so a
    /// document minted at the cap reads back past it. The twin measures the
    /// same, the `JSON.stringify` of the value its driver parsed.
    ///
    /// A `raw` past twice the cap is refused before it is parsed. Postgres
    /// prints a `jsonb` as its compact form plus one space after each `:` and
    /// `,` outside strings, each of which is a byte of that form beside its
    /// braces, so the printed text of a document either spine can write is
    /// under twice the cap and never refused here.
    ///
    /// **Fail-closed**: an unreadable or unknown-version document is an error,
    /// never a fall-through to full authority. `fuz_forge`'s hydrate path
    /// deliberately widens on a DB blip (`hydrate_policy` logs and returns
    /// `None`, which its `policy_check` treats as unscoped) — safe there only
    /// because a role gate still applies. Here the scope *is* the gate, so
    /// widening on a parse failure would hand a narrowed token full authority
    /// exactly when something is already wrong.
    ///
    /// # Errors
    ///
    /// Returns [`TokenScopeError`] on an over-cap, malformed, contradictory, or
    /// unknown-version document.
    pub fn parse(raw: &str) -> Result<Self, TokenScopeError> {
        if raw.len() > 2 * MAX_TOKEN_SCOPE_BYTES {
            return Err(TokenScopeError::TooLarge {
                size: raw.len(),
                max: MAX_TOKEN_SCOPE_BYTES,
            });
        }
        let malformed = |e: serde_json::Error| TokenScopeError::Malformed {
            message: e.to_string(),
        };
        let value: serde_json::Value = serde_json::from_str(raw).map_err(malformed)?;
        let size = serde_json::to_string(&value).map_err(malformed)?.len();
        if size > MAX_TOKEN_SCOPE_BYTES {
            return Err(TokenScopeError::TooLarge {
                size,
                max: MAX_TOKEN_SCOPE_BYTES,
            });
        }
        let doc = RawTokenScopeDocument::deserialize(value).map_err(malformed)?;
        if doc.version != TOKEN_SCOPE_VERSION {
            return Err(TokenScopeError::UnknownVersion {
                version: doc.version,
            });
        }
        let scope = scope_from_parts(&doc.kind, doc.methods)?;
        Ok(Self {
            version: doc.version,
            scope,
            grandfathered: doc.grandfathered,
        })
    }

    /// Serialize for storage, enforcing the size cap on the compact JSON this
    /// returns.
    ///
    /// # Errors
    ///
    /// Returns [`TokenScopeError`] when the document exceeds
    /// [`MAX_TOKEN_SCOPE_BYTES`] or fails to serialize.
    pub fn to_json(&self) -> Result<String, TokenScopeError> {
        let raw = match &self.scope {
            TokenScope::Full => RawTokenScopeDocument {
                version: self.version,
                kind: KIND_FULL.to_owned(),
                methods: None,
                grandfathered: self.grandfathered,
            },
            TokenScope::Methods(methods) => RawTokenScopeDocument {
                version: self.version,
                kind: KIND_METHODS.to_owned(),
                methods: Some(methods.clone()),
                grandfathered: self.grandfathered,
            },
        };
        let json = serde_json::to_string(&raw).map_err(|e| TokenScopeError::Malformed {
            message: e.to_string(),
        })?;
        if json.len() > MAX_TOKEN_SCOPE_BYTES {
            return Err(TokenScopeError::TooLarge {
                size: json.len(),
                max: MAX_TOKEN_SCOPE_BYTES,
            });
        }
        Ok(json)
    }
}

/// Failure modes for reading or writing a [`TokenScopeDocument`].
#[derive(Debug, thiserror::Error)]
pub enum TokenScopeError {
    #[error("token scope document is {size} bytes, exceeding the {max} byte cap")]
    TooLarge { size: usize, max: usize },
    #[error("token scope document is malformed: {message}")]
    Malformed { message: String },
    #[error("token scope document declares unknown version {version}")]
    UnknownVersion { version: u32 },
}

/// A non-RPC surface's capability string, `surface:<name>` — what a surface
/// denial ([`token_scope_surface_denied_response`](crate::token_scope_surface_denied_response))
/// reports as its `required_scope`.
///
/// Only the `surface:` arm: a non-RPC surface is not an action method, so a
/// denial naming an `rpc:<method>` capability would put a method name in front
/// of a route no method gate guards. [`Self::new`] refuses anything but a
/// well-formed `surface:<name>` — the name on the shared name grammar,
/// [`is_valid_name`](crate::is_valid_name): runs of `[a-z]` joined by single
/// underscores, `[a-z]+(?:_[a-z]+)*`, at most
/// [`NAME_LENGTH_MAX`](crate::NAME_LENGTH_MAX) long — and is `const`, so a
/// surface declared as a `const` that breaks the grammar fails to compile.
/// Twin of `fuz_app`'s `is_route_scope_capability`, which refuses the same
/// values at route registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceCapability(&'static str);

impl SurfaceCapability {
    /// The `surface:` prefix every surface capability carries.
    const PREFIX: &'static [u8] = b"surface:";

    /// Wrap a declared surface capability.
    ///
    /// # Panics
    ///
    /// Panics unless `capability` is `surface:` followed by a name on the
    /// shared name grammar, `[a-z]+(?:_[a-z]+)*` and at most
    /// [`NAME_LENGTH_MAX`](crate::NAME_LENGTH_MAX) long — in a `const`, a
    /// compile error.
    #[must_use]
    pub const fn new(capability: &'static str) -> Self {
        assert!(
            Self::is_surface_capability(capability.as_bytes()),
            "a surface capability is `surface:<name>`, the name [a-z]+(?:_[a-z]+)*, at most 64 characters"
        );
        Self(capability)
    }

    /// The capability string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    const fn is_surface_capability(bytes: &[u8]) -> bool {
        let prefix = Self::PREFIX;
        if bytes.len() < prefix.len() {
            return false;
        }
        let (head, name) = bytes.split_at(prefix.len());
        let mut i = 0;
        while i < prefix.len() {
            if head[i] != prefix[i] {
                return false;
            }
            i += 1;
        }
        is_valid_name_bytes(name)
    }
}

impl std::fmt::Display for SurfaceCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The non-RPC surfaces **this workspace** mounts.
///
/// Exists so the denial body names *which* surface refused, using the same
/// `<section>:<id>` capability-string format `fuz_forge` established for its own
/// policy (`rpc:<method>`, `forge.push:<repo_id>`) — one vocabulary, so a
/// consumer that does log or audit its refusals has a name to reach for rather
/// than inventing a second one. The spine emits no audit row for a scope denial
/// itself.
///
/// **Not a vocabulary consumers extend through.** A consumer crate mounting its
/// own non-RPC surface names it directly —
/// [`token_scope_surface_denied_response`](crate::token_scope_surface_denied_response)
/// takes the capability string, not this enum — so nothing here has to grow a
/// variant for someone else's route. The enum stays closed because that is what
/// makes [`ALL`](Self::ALL)'s exhaustiveness test meaningful over the surfaces
/// this workspace is responsible for gating. The name itself decides nothing:
/// rule 3 is all-or-nothing, so it only labels which surface refused. Twin of
/// `fuz_app`'s `TOKEN_SURFACES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSurface {
    /// `fuz_db_admin`'s table browser (`/api/db/*`).
    DbAdmin,
    /// `fuz_fact_serving`'s admin-only bare-hash read (`GET /api/facts/:hash`).
    FactBare,
    /// The admin audit SSE stream.
    AuditStream,
    /// The WebSocket upgrade.
    WsUpgrade,
}

impl TokenSurface {
    /// Stable capability string for denial bodies and audit rows.
    #[must_use]
    pub const fn capability(self) -> SurfaceCapability {
        SurfaceCapability::new(match self {
            Self::DbAdmin => "surface:db_admin",
            Self::FactBare => "surface:fact_bare",
            Self::AuditStream => "surface:audit_stream",
            Self::WsUpgrade => "surface:ws_upgrade",
        })
    }

    /// Every surface, for exhaustive iteration in the census test.
    pub const ALL: &'static [Self] = &[
        Self::DbAdmin,
        Self::FactBare,
        Self::AuditStream,
        Self::WsUpgrade,
    ];
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_TOKEN_SCOPE_BYTES, SurfaceCapability, TOKEN_SCOPE_VERSION, TokenScope,
        TokenScopeDocument, TokenScopeError, TokenSurface,
    };
    use std::collections::BTreeSet;

    fn methods(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn full_admits_every_method_and_surface() {
        let scope = TokenScope::Full;
        assert!(scope.admits_method("anything"));
        assert!(scope.admits_non_rpc_surface());
    }

    /// Rule 2: anything not listed is denied.
    #[test]
    fn methods_denies_what_it_does_not_list() {
        let scope = TokenScope::Methods(methods(&["cell_get", "cell_list"]));
        assert!(scope.admits_method("cell_get"));
        assert!(scope.admits_method("cell_list"));
        assert!(!scope.admits_method("cell_create"));
        assert!(!scope.admits_method(""));
    }

    /// Rule 3 — the property that keeps a narrowed token out of the db-admin
    /// browser. If this ever returns `true` for a `Methods` scope, a token
    /// badged "scoped to one method" can read `password_hash` and delete rows.
    #[test]
    fn a_narrowed_token_reaches_no_non_rpc_surface() {
        let narrow = TokenScope::Methods(methods(&["cell_get"]));
        assert!(!narrow.admits_non_rpc_surface());
        // ...including a narrowed token that lists *every* method it knows of:
        // narrowing is the signal, not the size of the list.
        let broad = TokenScope::Methods(methods(&["cell_get", "cell_list", "account_verify"]));
        assert!(!broad.admits_non_rpc_surface());
        // The empty set is legal and inert, not an error.
        let inert = TokenScope::Methods(BTreeSet::new());
        assert!(!inert.admits_method("cell_get"));
        assert!(!inert.admits_non_rpc_surface());
    }

    #[test]
    fn document_round_trips_through_the_stored_wire_shape() {
        let full = TokenScopeDocument::full();
        assert_eq!(full.to_json().unwrap(), r#"{"version":1,"kind":"full"}"#);
        assert_eq!(
            TokenScopeDocument::parse(&full.to_json().unwrap()).unwrap(),
            full
        );

        let narrow = TokenScopeDocument::methods(methods(&["cell_get", "cell_list"]));
        assert_eq!(
            narrow.to_json().unwrap(),
            r#"{"version":1,"kind":"methods","methods":["cell_get","cell_list"]}"#
        );
        assert_eq!(
            TokenScopeDocument::parse(&narrow.to_json().unwrap()).unwrap(),
            narrow
        );
    }

    /// The exact document the `api_token_scope` migration backfills. If this
    /// drifts from the SQL literal, every pre-scoping token fails to parse and
    /// (per `parse`'s fail-closed contract) stops working — loudly, which is
    /// the intended direction, but this pins it so it doesn't happen by
    /// accident.
    #[test]
    fn grandfathered_backfill_parses_and_denotes_full() {
        let raw = r#"{"version":1,"kind":"full","grandfathered":true}"#;
        let doc = TokenScopeDocument::parse(raw).unwrap();
        assert!(doc.grandfathered);
        assert_eq!(doc.to_scope(), TokenScope::Full);
        assert_eq!(doc.label(), "full (grandfathered)");
        // Round-trips byte-identically, so a re-serialize doesn't silently
        // launder the grandfathered flag away.
        assert_eq!(doc.to_json().unwrap(), raw);
    }

    /// `grandfathered` is a row fact, not an authority level — a deliberately
    /// minted `full` and a backfilled one denote the same `TokenScope`, and the
    /// enforcement path cannot tell them apart.
    #[test]
    fn grandfathered_is_not_a_third_authority_level() {
        let deliberate = TokenScopeDocument::full();
        let backfilled = TokenScopeDocument {
            grandfathered: true,
            ..TokenScopeDocument::full()
        };
        assert_eq!(deliberate.to_scope(), backfilled.to_scope());
        assert_ne!(deliberate.label(), backfilled.label());
    }

    /// Fail-closed: a malformed / over-cap / future-version document is an
    /// error, never a silent widening to full authority.
    #[test]
    fn unreadable_documents_are_errors_not_full_authority() {
        assert!(matches!(
            TokenScopeDocument::parse("not json"),
            Err(TokenScopeError::Malformed { .. })
        ));
        // An unknown `kind` must not deserialize into anything permissive.
        assert!(matches!(
            TokenScopeDocument::parse(r#"{"version":1,"kind":"unscoped"}"#),
            Err(TokenScopeError::Malformed { .. })
        ));
        // A future version is refused rather than best-effort read: v2 may add
        // a `surfaces` arm, and reading it as v1 would ignore the narrowing.
        assert!(matches!(
            TokenScopeDocument::parse(r#"{"version":2,"kind":"full"}"#),
            Err(TokenScopeError::UnknownVersion { version: 2 })
        ));
        // Unknown fields are refused too (`deny_unknown_fields`), so a v1
        // reader can't silently drop a grant arm it doesn't understand.
        assert!(matches!(
            TokenScopeDocument::parse(r#"{"version":1,"kind":"full","surfaces":{}}"#),
            Err(TokenScopeError::Malformed { .. })
        ));
        // Contradictions are refused rather than resolved in either direction —
        // a tagged enum would have ignored the stray `methods` and granted
        // full authority.
        assert!(matches!(
            TokenScopeDocument::parse(r#"{"version":1,"kind":"full","methods":["cell_get"]}"#),
            Err(TokenScopeError::Malformed { .. })
        ));
        assert!(matches!(
            TokenScopeDocument::parse(r#"{"version":1,"kind":"methods"}"#),
            Err(TokenScopeError::Malformed { .. })
        ));
        let huge = format!(
            r#"{{"version":1,"kind":"methods","methods":["{}"]}}"#,
            "x".repeat(MAX_TOKEN_SCOPE_BYTES)
        );
        assert!(matches!(
            TokenScopeDocument::parse(&huge),
            Err(TokenScopeError::TooLarge { .. })
        ));
    }

    /// The compact JSON of a `methods` document over `methods`, in the order
    /// given, as `fuz_app`'s `JSON.stringify` writes it.
    fn compact_methods_json(methods: &[String]) -> String {
        serde_json::to_string(&serde_json::json!({
            "version": TOKEN_SCOPE_VERSION,
            "kind": "methods",
            "methods": methods,
        }))
        .unwrap()
    }

    /// The text Postgres prints a `jsonb` as: a space after every `:` and `,`.
    /// The fixture's names hold neither, so a plain replace spells it.
    fn postgres_jsonb_text(compact: &str) -> String {
        compact.replace(':', ": ").replace(',', ", ")
    }

    /// Method names whose `methods` document is exactly `bytes` compact UTF-8
    /// bytes: `account_token_list`, names ending in `filler`, and an ASCII
    /// pad. The twin's tests build the same list.
    fn methods_at_bytes(bytes: usize, filler: &str) -> Vec<String> {
        let mut methods = vec!["account_token_list".to_owned()];
        for i in 0.. {
            let next = format!("scope_cap_{i:03}_{filler}");
            let mut trial = methods.clone();
            trial.extend([next.clone(), String::new()]);
            if compact_methods_json(&trial).len() > bytes {
                break;
            }
            methods.push(next);
        }
        let mut trial = methods.clone();
        trial.push(String::new());
        methods.push("x".repeat(bytes - compact_methods_json(&trial).len()));
        methods
    }

    /// The cap counts UTF-8 bytes of the compact JSON, at mint and at read:
    /// a two-byte document at the cap is far under it in UTF-16 code units, the
    /// twin's old unit, and one byte past it is refused both ways. The same
    /// document as Postgres prints it, spaced, is past the cap and still read,
    /// whatever order the twin wrote its methods in.
    #[test]
    fn the_cap_counts_compact_utf8_bytes() {
        let at_cap = methods_at_bytes(MAX_TOKEN_SCOPE_BYTES, &"\u{00E9}".repeat(40));
        let doc = TokenScopeDocument::methods(at_cap.iter().cloned().collect());
        let json = doc.to_json().unwrap();
        assert_eq!(json.len(), MAX_TOKEN_SCOPE_BYTES);
        assert!(json.encode_utf16().count() < MAX_TOKEN_SCOPE_BYTES - 1000);
        assert_eq!(TokenScopeDocument::parse(&json).unwrap(), doc);

        let mut ts_order = at_cap;
        ts_order.reverse();
        let ts_json = compact_methods_json(&ts_order);
        assert_eq!(ts_json.len(), MAX_TOKEN_SCOPE_BYTES);
        let spaced = postgres_jsonb_text(&ts_json);
        assert!(spaced.len() > MAX_TOKEN_SCOPE_BYTES, "{}", spaced.len());
        assert_eq!(TokenScopeDocument::parse(&spaced).unwrap(), doc);

        let over = methods_at_bytes(MAX_TOKEN_SCOPE_BYTES + 1, &"\u{00E9}".repeat(40));
        let over_doc = TokenScopeDocument::methods(over.iter().cloned().collect());
        assert!(matches!(
            over_doc.to_json(),
            Err(TokenScopeError::TooLarge { size, .. }) if size == MAX_TOKEN_SCOPE_BYTES + 1
        ));
        assert!(matches!(
            TokenScopeDocument::parse(&postgres_jsonb_text(&compact_methods_json(&over))),
            Err(TokenScopeError::TooLarge { size, .. }) if size == MAX_TOKEN_SCOPE_BYTES + 1
        ));
    }

    /// An ASCII document under the cap whose spaced text is past it reads, as
    /// it did not when the cap measured the text Postgres printed.
    #[test]
    fn a_compact_document_under_the_cap_reads_from_its_spaced_text() {
        let methods = methods_at_bytes(MAX_TOKEN_SCOPE_BYTES - 50, "m");
        let compact = compact_methods_json(&methods);
        assert_eq!(compact.len(), MAX_TOKEN_SCOPE_BYTES - 50);
        let spaced = postgres_jsonb_text(&compact);
        assert!(spaced.len() > MAX_TOKEN_SCOPE_BYTES, "{}", spaced.len());
        assert_eq!(
            TokenScopeDocument::parse(&spaced).unwrap(),
            TokenScopeDocument::methods(methods.into_iter().collect())
        );
    }

    /// A text past twice the cap is refused before it is parsed, by its own
    /// length: a document at the cap padded with whitespace parses, and is
    /// refused only by that check. The spaced text of a document at the cap is
    /// under it, so reads.
    #[test]
    fn a_text_past_twice_the_cap_is_refused_unparsed() {
        let compact = compact_methods_json(&methods_at_bytes(MAX_TOKEN_SCOPE_BYTES, "m"));
        let spaced = postgres_jsonb_text(&compact);
        assert!(spaced.len() < 2 * MAX_TOKEN_SCOPE_BYTES, "{}", spaced.len());
        assert!(TokenScopeDocument::parse(&spaced).is_ok());

        let padded = format!(
            "{compact}{}",
            " ".repeat(2 * MAX_TOKEN_SCOPE_BYTES + 1 - compact.len())
        );
        assert!(serde_json::from_str::<serde_json::Value>(&padded).is_ok());
        assert!(matches!(
            TokenScopeDocument::parse(&padded),
            Err(TokenScopeError::TooLarge { size, .. }) if size == 2 * MAX_TOKEN_SCOPE_BYTES + 1
        ));
        assert!(TokenScopeDocument::parse(&padded[..padded.len() - 1]).is_ok());
    }

    #[test]
    fn oversized_documents_are_refused_at_write_too() {
        let big = TokenScopeDocument::methods(
            (0..500)
                .map(|i| format!("some_fairly_long_method_name_{i}"))
                .collect(),
        );
        assert!(matches!(
            big.to_json(),
            Err(TokenScopeError::TooLarge { .. })
        ));
    }

    /// Adding a `TokenSurface` variant fails to compile here, on purpose —
    /// the same technique `credential_types_are_exhaustively_reviewed` uses.
    /// A new non-RPC surface must be added to `ALL` *and* wired to an actual
    /// check at its route; this is the site that forces the second half to be
    /// remembered.
    #[test]
    fn surfaces_are_exhaustively_reviewed() {
        for surface in TokenSurface::ALL {
            match surface {
                TokenSurface::DbAdmin
                | TokenSurface::FactBare
                | TokenSurface::AuditStream
                | TokenSurface::WsUpgrade => {}
            }
        }
        assert_eq!(
            TokenSurface::ALL.len(),
            4,
            "a new surface needs a scope check at its route — see this test's docs",
        );
    }

    #[test]
    fn capability_strings_are_stable() {
        assert_eq!(
            TokenSurface::DbAdmin.capability().as_str(),
            "surface:db_admin"
        );
        assert_eq!(
            TokenSurface::FactBare.capability().as_str(),
            "surface:fact_bare"
        );
        assert_eq!(
            TokenSurface::AuditStream.capability().as_str(),
            "surface:audit_stream"
        );
        assert_eq!(
            TokenSurface::WsUpgrade.capability().as_str(),
            "surface:ws_upgrade"
        );
    }

    /// A surface capability is `surface:<name>` and nothing else — an
    /// `rpc:<method>` capability, a bare name, and a malformed name are each
    /// refused, as the twin's `is_route_scope_capability` refuses them.
    #[test]
    fn a_surface_capability_is_surface_prefixed_and_well_formed() {
        for good in [
            "surface:a",
            "surface:upload",
            "surface:file_bytes",
            "surface:a_b_c",
            "surface:db_admin",
        ] {
            assert_eq!(SurfaceCapability::new(good).as_str(), good);
        }
        for bad in [
            "rpc:account_verify",
            "rpc:surface",
            "upload",
            "surface:",
            "surface:_upload",
            "surface:upload_",
            "surface:file__bytes",
            "surface:file___bytes",
            "surface:a_b__c",
            "surface:__upload",
            "surface:upload__",
            "surface:__",
            "surface:Upload",
            "surface:file-bytes",
            "surface:file bytes",
            "surface:9lives",
            " surface:upload",
        ] {
            assert!(
                std::panic::catch_unwind(|| SurfaceCapability::new(bad)).is_err(),
                "{bad} must be refused"
            );
        }
    }

    /// The surface name holds the shared name cap, as the twin's
    /// `is_route_scope_capability` does.
    #[test]
    fn a_surface_name_is_capped_at_the_name_length_max() {
        let at_max: &'static str = format!("surface:{}", "a".repeat(crate::NAME_LENGTH_MAX)).leak();
        assert_eq!(SurfaceCapability::new(at_max).as_str(), at_max);
        let past_max: &'static str =
            format!("surface:{}", "a".repeat(crate::NAME_LENGTH_MAX + 1)).leak();
        assert!(
            std::panic::catch_unwind(|| SurfaceCapability::new(past_max)).is_err(),
            "a surface name past the cap must be refused"
        );
    }

    #[test]
    fn version_constant_matches_the_documents_it_builds() {
        assert_eq!(TokenScopeDocument::full().version, TOKEN_SCOPE_VERSION);
        assert_eq!(TokenScopeDocument::full().scope, TokenScope::Full);
    }
}
