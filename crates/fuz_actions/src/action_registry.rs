//! [`ActionRegistry`] — value-type lookup table for registered actions.
//!
//! **A runtime registry, not codegen match arms**: specs register as values at
//! startup and dispatch looks them up by method.
//!
//! ## Storage: `HashMap<&'static str, ActionEntry>`
//!
//! `&str` keys are matched on cache-friendly small constants;
//! `HashMap` (FxHash-able) wins over `Vec<(method, _)>` linear scan
//! at >~10 entries, and a registry holds the spine's auth and cell
//! families plus each consumer's own verbs. No `Box<dyn ActionRegistry>`
//! trait — concrete struct, monomorphized lookup.
//!
//! ## Compile-time invariants enforced at build
//!
//! - **Unique method names** — registering two specs with the same
//!   method returns [`RegistryBuildError::DuplicateMethod`].
//! - **No empty method** — `"".to_owned()` rejected at build.
//! - **Auth-spec cross-axis invariants (1/3/4/5)** — each spec's
//!   `fuz_auth::AuthSpec::validate` runs at compile, returning
//!   [`RegistryBuildError::InvalidAuthSpec`] on a violation (roles ⟹
//!   actor required; no accountless actors; the unrestricted leaf
//!   declares no role / credential gates; no empty credential allowlist).
//!   Mirrors `fuz_app`'s `RouteAuth` `.superRefine`.
//! - **Rate-limit / account axis** — an account-keyed class
//!   ([`RateLimitClass::Account`] / [`RateLimitClass::Both`]) requires
//!   `auth.account` = [`AuthAxis::Required`], since the per-account bucket
//!   is keyed on the caller's account and only that axis guarantees one;
//!   otherwise [`RegistryBuildError::AccountRateLimitWithoutRequiredAccount`].
//!   Mirrors the same check in `fuz_app`'s
//!   `compile_action_registry.ts`, which compares against `'required'`
//!   exactly: `account: Optional` with `actor: Required` is refused too,
//!   though the 401 gate would guarantee an account there.
//! - **Void input / actor** — an [`InputShape::Void`] spec whose auth resolves an
//!   acting actor (`auth.actor` not [`AuthAxis::None`]) is refused with
//!   [`RegistryBuildError::VoidInputWithActor`]: a void input cannot carry the
//!   `acting` selector. This is the void half of `fuz_app`'s
//!   `assert_route_auth_acting_biconditional`.
//!
//! The remaining invariants from `fuz_app`'s `compile_action_registry.ts`
//! (the auth-shape *biconditional*'s object half — invariant 2; JSON-RPC §4.2 wire
//! validity) need typed-input introspection the Rust spine lacks
//! pre-codegen, so they stay on a future codegen layer. Its
//! `auth.required_scope` refusal has nothing to check here: `AuthSpec`
//! carries no such field.
//!
//! ## No trait abstraction
//!
//! Design crates with concrete pools, query functions,
//! and no `trait FooStore`. No `trait ActionRegistry`. Consumers compose
//! `ActionRegistry` values directly.

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;
use fuz_auth::{AuthAxis, RateLimitClass};
use fuz_http::{InputShape, JsonrpcError};
use serde_json::Value;

use crate::action_context::ActionContext;
use crate::action_output::ActionOutput;
use crate::action_spec::ActionSpec;

/// Handler closure stored on an [`ActionSpec`].
///
/// `Arc` because the registry stores N specs and the dispatcher clones
/// the handler arc into the request frame so the handler future can
/// outlive a borrow of the registry. `BoxFuture<'static, ...>` because
/// the handler future is opaque to the dispatcher.
///
/// The closure receives owned `Value` params + an owned [`ActionContext`]
/// wrapper. Owned because the future is `'static` — borrowed lifetimes
/// can't be expressed cleanly through the trait-object boundary without
/// HRTB acrobatics that don't pay for themselves. The shape mirrors
/// what `fuz_app`'s TS handlers see (frozen input + frozen context).
///
/// Cost trade: one `Arc::clone` + one `BoxFuture` allocation per
/// dispatch. That is invisible against the DB tx wrap that dominates
/// side-effect actions;
/// when a future workload demands it, we can revisit a generic dispatch
/// shape (per-spec monomorphized closures stored as type-erased
/// `dyn AsyncFn`).
pub type ActionHandler = Arc<
    dyn for<'a> Fn(Value, ActionContext<'a>) -> BoxFuture<'a, Result<Value, JsonrpcError>>
        + Send
        + Sync,
>;

/// Handler closure returning an [`ActionOutput`] instead of a `Value`.
///
/// For a handler whose output is large enough that rendering it once,
/// straight into the response, matters (see [`ActionOutput::serialize`]).
/// Registered via [`ActionSpec::new_output`]; otherwise the same contract as
/// [`ActionHandler`].
pub type ActionOutputHandler = Arc<
    dyn for<'a> Fn(Value, ActionContext<'a>) -> BoxFuture<'a, Result<ActionOutput, JsonrpcError>>
        + Send
        + Sync,
>;

/// One entry in the registry — the spec is stored as-is.
///
/// Stored in a `HashMap` keyed by `spec.method`. The `Arc<ActionSpec>`
/// indirection lets the dispatcher hold a `Arc<ActionSpec>` for the
/// duration of the handler future without forcing the registry's
/// `HashMap` to be borrowed across `.await` points.
#[derive(Clone)]
pub struct ActionEntry {
    pub spec: Arc<ActionSpec>,
}

impl std::fmt::Debug for ActionEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionEntry")
            .field("spec", &self.spec)
            .finish()
    }
}

/// Errors raised during [`ActionRegistry::compile`].
#[derive(Debug, thiserror::Error)]
pub enum RegistryBuildError {
    #[error("duplicate method registered: {0}")]
    DuplicateMethod(&'static str),
    #[error("empty method name")]
    EmptyMethod,
    /// A spec's [`fuz_auth::AuthSpec`] violated a cross-axis registry invariant
    /// (1: roles ⟹ actor required; 3: no accountless actors; 4: unrestricted
    /// is leaf; 5: no empty credential allowlist). Fail loud at
    /// registry-compile time, mirroring `fuz_app`'s `RouteAuth` `.superRefine`.
    #[error("invalid auth spec for method '{method}': {reason}")]
    InvalidAuthSpec {
        method: &'static str,
        reason: &'static str,
    },
    /// A spec declared an account-keyed rate-limit class
    /// ([`RateLimitClass::Account`] / [`RateLimitClass::Both`]) on an account
    /// axis other than [`AuthAxis::Required`], so a request could reach the
    /// gate with no account to key the per-account bucket on. Fail loud at
    /// registry-compile time, mirroring `fuz_app`'s `compile_action_registry`.
    #[error(
        "invalid rate limit for method '{method}': rate_limit '{}' requires auth.account = Required (no account is guaranteed for account-keyed limiting; use Ip or require the account)",
        .class.name()
    )]
    AccountRateLimitWithoutRequiredAccount {
        method: &'static str,
        class: RateLimitClass,
    },
    /// A spec declared [`InputShape::Void`] with an auth spec that resolves an
    /// acting actor, but a void input cannot carry the `acting` selector, so
    /// the actor could never be chosen. Fail loud at registry-compile time,
    /// mirroring the void half of `fuz_app`'s
    /// `assert_route_auth_acting_biconditional`.
    #[error(
        "invalid input for method '{method}': a void input cannot carry `acting`, but auth.actor is not None"
    )]
    VoidInputWithActor { method: &'static str },
}

/// Runtime lookup table mapping wire method → registered spec.
///
/// Built once at consumer boot via [`Self::compile`] from a flat slice
/// of `ActionSpec`s. The registry is then shared as `Arc<ActionRegistry>`
/// across the HTTP RPC + WS dispatchers — both transports look up via
/// `&str` and dispatch through the same handler closures.
#[derive(Clone, Debug)]
pub struct ActionRegistry {
    entries: HashMap<&'static str, ActionEntry>,
}

impl ActionRegistry {
    /// Build a registry from a slice of specs.
    ///
    /// Consumers compose multi-source registries by concatenating
    /// slices before calling `compile`:
    ///
    /// ```ignore
    /// let mut all_specs: Vec<ActionSpec> = Vec::new();
    /// all_specs.extend(my_account_specs());     // fuz_auth account ones
    /// all_specs.extend(my_admin_specs());        // fuz_auth admin ones
    /// all_specs.extend(zzz_workspace_specs());   // consumer-side
    /// let registry = ActionRegistry::compile(all_specs)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RegistryBuildError`] on the first spec that fails an
    /// invariant: an empty or duplicate method name, an `AuthSpec` that fails
    /// `fuz_auth::AuthSpec::validate`, or an account-keyed rate-limit class
    /// on an account axis that is not [`AuthAxis::Required`], or an
    /// [`InputShape::Void`] spec whose auth resolves an acting actor.
    pub fn compile(
        specs: impl IntoIterator<Item = ActionSpec>,
    ) -> Result<Self, RegistryBuildError> {
        let mut entries: HashMap<&'static str, ActionEntry> = HashMap::new();
        for spec in specs {
            if spec.method.is_empty() {
                return Err(RegistryBuildError::EmptyMethod);
            }
            let method = spec.method;
            if entries.contains_key(method) {
                return Err(RegistryBuildError::DuplicateMethod(method));
            }
            // Registry-time auth invariants (1/3/4/5) — fail loud at boot.
            if let Err(reason) = spec.auth.validate() {
                return Err(RegistryBuildError::InvalidAuthSpec { method, reason });
            }
            // An account-keyed class needs a guaranteed account to key its
            // bucket on — fail loud at boot, not by sharing one bucket among
            // every accountless caller at runtime.
            if !matches!(spec.auth.account, AuthAxis::Required)
                && let Some(class) = spec
                    .rate_limit
                    .filter(|c| matches!(c, RateLimitClass::Account | RateLimitClass::Both))
            {
                return Err(RegistryBuildError::AccountRateLimitWithoutRequiredAccount {
                    method,
                    class,
                });
            }
            // A void input has no `acting` key to select an actor with.
            if matches!(spec.input, InputShape::Void) && spec.auth.needs_actor() {
                return Err(RegistryBuildError::VoidInputWithActor { method });
            }
            entries.insert(
                method,
                ActionEntry {
                    spec: Arc::new(spec),
                },
            );
        }
        Ok(Self { entries })
    }

    /// Look up an entry by wire method name.
    ///
    /// Returns the entry — callers handle the `None` case by emitting
    /// `method_not_found` per JSON-RPC 2.0 §5.1.
    #[must_use]
    pub fn get(&self, method: &str) -> Option<&ActionEntry> {
        self.entries.get(method)
    }

    /// Number of registered methods.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no methods are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over every registered method.
    pub fn methods(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.entries.keys().copied()
    }

    /// Iterate over every registered entry (for introspection / tests).
    pub fn entries(&self) -> impl Iterator<Item = (&'static str, &ActionEntry)> + '_ {
        self.entries.iter().map(|(k, v)| (*k, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_auth::{AuthSpec, CredentialGate};
    use fuz_http::InputShape;
    use serde_json::Value;

    fn dummy_handler() -> ActionHandler {
        Arc::new(|_params: Value, _ctx: ActionContext<'_>| Box::pin(async move { Ok(Value::Null) }))
    }

    #[test]
    fn compile_empty_registry() {
        let r = ActionRegistry::compile(Vec::new()).unwrap();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
    }

    #[test]
    fn compile_rejects_empty_method() {
        let spec = ActionSpec::new(
            "",
            AuthSpec::public(),
            InputShape::Object,
            false,
            dummy_handler(),
        );
        let err = ActionRegistry::compile([spec]).unwrap_err();
        assert!(matches!(err, RegistryBuildError::EmptyMethod));
    }

    #[test]
    fn compile_rejects_duplicate_method() {
        let a = ActionSpec::new(
            "ping",
            AuthSpec::public(),
            InputShape::Object,
            false,
            dummy_handler(),
        );
        let b = ActionSpec::new(
            "ping",
            AuthSpec::public(),
            InputShape::Object,
            false,
            dummy_handler(),
        );
        let err = ActionRegistry::compile([a, b]).unwrap_err();
        assert!(matches!(err, RegistryBuildError::DuplicateMethod("ping")));
    }

    #[test]
    fn lookup_hits_and_misses() {
        let spec = ActionSpec::new(
            "ping",
            AuthSpec::public(),
            InputShape::Object,
            false,
            dummy_handler(),
        );
        let r = ActionRegistry::compile([spec]).unwrap();
        assert!(r.get("ping").is_some());
        assert!(r.get("missing").is_none());
        let methods: Vec<&'static str> = r.methods().collect();
        assert_eq!(methods, vec!["ping"]);
    }

    /// `AuthSpec` shapes whose account axis is not `Required` and that pass
    /// `AuthSpec::validate` — one per non-`Required` `AuthAxis` value, plus
    /// the `account: Optional, actor: Required` shape the 401 gate would
    /// guarantee an account for, which the twin refuses all the same.
    fn auth_without_a_required_account() -> [AuthSpec; 4] {
        [
            AuthSpec::public(),
            AuthSpec::optional_identity(CredentialGate::Any),
            AuthSpec {
                account: AuthAxis::Optional,
                actor: AuthAxis::None,
                roles: None,
                credentials: CredentialGate::Any,
            },
            AuthSpec {
                account: AuthAxis::Optional,
                actor: AuthAxis::Required,
                roles: None,
                credentials: CredentialGate::Any,
            },
        ]
    }

    fn assert_refused_as_account_keyed(spec: ActionSpec, expected: RateLimitClass) {
        let auth = spec.auth;
        let err = ActionRegistry::compile([spec])
            .expect_err("an account-keyed class without a required account must be refused");
        assert!(
            matches!(
                err,
                RegistryBuildError::AccountRateLimitWithoutRequiredAccount {
                    method: "throttled",
                    class,
                } if class == expected
            ),
            "{auth:?}: {err:?}"
        );
    }

    #[test]
    fn compile_rejects_an_account_keyed_rate_limit_without_a_required_account() {
        for auth in auth_without_a_required_account() {
            auth.validate()
                .expect("the fixture is otherwise a valid spec");
            for class in [RateLimitClass::Account, RateLimitClass::Both] {
                let spec = ActionSpec::new(
                    "throttled",
                    auth,
                    InputShape::Object,
                    false,
                    dummy_handler(),
                )
                .with_rate_limit(class);
                assert_refused_as_account_keyed(spec, class);
            }
        }
    }

    #[test]
    fn compile_rejection_names_the_method_and_class() {
        let spec = ActionSpec::new(
            "throttled",
            AuthSpec::public(),
            InputShape::Object,
            false,
            dummy_handler(),
        )
        .with_rate_limit(RateLimitClass::Both);
        let message = ActionRegistry::compile([spec]).unwrap_err().to_string();
        assert!(message.contains("'throttled'"), "{message}");
        assert!(message.contains("'both'"), "{message}");
    }

    #[test]
    fn compile_accepts_an_account_keyed_rate_limit_on_a_required_account() {
        for auth in [
            AuthSpec::account_grain(CredentialGate::Any),
            AuthSpec::authenticated(CredentialGate::Any),
        ] {
            for class in [RateLimitClass::Account, RateLimitClass::Both] {
                let gated =
                    ActionSpec::new("gated", auth, InputShape::Object, false, dummy_handler())
                        .with_rate_limit(class);
                let r = ActionRegistry::compile([gated])
                    .unwrap_or_else(|e| panic!("{auth:?} with {class:?}: {e}"));
                assert_eq!(r.len(), 1);
            }
        }
    }

    /// The IP axis needs no account, so `Ip` stands on any account axis.
    #[test]
    fn compile_accepts_an_ip_rate_limit_without_a_required_account() {
        for auth in auth_without_a_required_account() {
            let gated = ActionSpec::new("gated", auth, InputShape::Object, false, dummy_handler())
                .with_rate_limit(RateLimitClass::Ip);
            let r = ActionRegistry::compile([gated])
                .unwrap_or_else(|e| panic!("{auth:?} with Ip: {e}"));
            assert_eq!(r.len(), 1);
        }
    }

    #[test]
    fn compile_rejects_a_void_input_whose_auth_resolves_an_actor() {
        for auth in [
            AuthSpec::authenticated(CredentialGate::Any),
            AuthSpec {
                account: AuthAxis::Required,
                actor: AuthAxis::Optional,
                roles: None,
                credentials: CredentialGate::Any,
            },
        ] {
            auth.validate()
                .expect("the fixture is otherwise a valid spec");
            let spec = ActionSpec::new("voided", auth, InputShape::Void, false, dummy_handler());
            let err = ActionRegistry::compile([spec])
                .expect_err("a void input with an acting actor must be refused");
            assert!(
                matches!(
                    err,
                    RegistryBuildError::VoidInputWithActor { method: "voided" }
                ),
                "{auth:?}: {err:?}"
            );
            assert!(err.to_string().contains("'voided'"), "{err}");
        }
    }

    #[test]
    fn compile_accepts_a_void_input_without_an_actor() {
        for auth in [
            AuthSpec::public(),
            AuthSpec::account_grain(CredentialGate::Any),
        ] {
            let spec = ActionSpec::new("voided", auth, InputShape::Void, false, dummy_handler());
            let r = ActionRegistry::compile([spec]).unwrap_or_else(|e| panic!("{auth:?}: {e}"));
            assert_eq!(r.len(), 1);
        }
    }

    /// An `AuthSpec` that fails `validate` is refused as that, ahead of the
    /// rate-limit check, matching the twin, whose `RouteAuth` parse runs
    /// before the registration loop.
    #[test]
    fn compile_reports_an_invalid_auth_spec_before_the_rate_limit_axis() {
        let accountless_actor = AuthSpec {
            account: AuthAxis::None,
            actor: AuthAxis::Required,
            roles: None,
            credentials: CredentialGate::Any,
        };
        let spec = ActionSpec::new(
            "throttled",
            accountless_actor,
            InputShape::Object,
            false,
            dummy_handler(),
        )
        .with_rate_limit(RateLimitClass::Account);
        let err = ActionRegistry::compile([spec]).unwrap_err();
        assert!(
            matches!(
                err,
                RegistryBuildError::InvalidAuthSpec {
                    method: "throttled",
                    ..
                }
            ),
            "{err:?}"
        );
    }
}
