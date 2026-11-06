//! Built-in role constants and the role registry.
//!
//! Roles are open-vocabulary string values; two ship with the spine and
//! carry special semantics (keeper = filesystem-readable trust, admin =
//! cross-account management). A consumer declares its own roles in a
//! [`RoleRegistry`], which the spine reads to decide grantability — the
//! right-sized Rust twin of TS `create_role_registry`: the registry is the one
//! seam that decides which roles a grant may name.

use std::collections::HashMap;

use crate::name_schema::{NAME_LENGTH_MAX, is_valid_name};

/// Highest-trust role — implies filesystem read of the daemon token
/// file. Matches `fuz_app`'s `ROLE_KEEPER`.
pub const ROLE_KEEPER: &str = "keeper";

/// Cross-account management role. Matches `fuz_app`'s `ROLE_ADMIN`.
pub const ROLE_ADMIN: &str = "admin";

/// A surface through which a role may be conferred.
///
/// Closed enum — the TS `grant_path` open registry has no real consumers, so
/// the Rust port fixes the set. v1 only
/// queries [`GrantPath::Admin`]; `SelfService` and `Bootstrap` are carried so
/// the shape is right when those paths wire in, without an enum churn later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantPath {
    /// Admin-conferrable — via the consent flow (`role_grant_offer_create`)
    /// and the immediate `role_grant_assign`. The only path v1 enforces.
    Admin,
    /// Holder-togglable via `self_service_role_set`. Carried, not yet read by
    /// the Rust spine (self-service eligibility is still its own explicit
    /// `eligible_roles` arg — convergence deferred).
    SelfService,
    /// CLI / daemon-token only (keeper). Never web-conferrable.
    Bootstrap,
}

/// One role's metadata: its name and the surfaces it may be conferred through.
///
/// The right-sized Rust port of TS `RoleSpec` — `name` + `grant_paths` only;
/// the inert `applicable_scope_kinds` / `required_credential_types` are omitted.
#[derive(Debug, Clone)]
pub struct RoleSpec {
    /// Unique role name. Must satisfy [`is_valid_name`], the shared name
    /// grammar.
    pub name: String,
    /// Surfaces through which this role may be conferred.
    pub grant_paths: Vec<GrantPath>,
}

impl RoleSpec {
    /// Construct a role spec — convenience for consumer registration.
    #[must_use]
    pub fn new(name: impl Into<String>, grant_paths: Vec<GrantPath>) -> Self {
        Self {
            name: name.into(),
            grant_paths,
        }
    }
}

/// Construction error for a [`RoleRegistry`] — a startup misconfiguration.
///
/// The consumer `.expect()`s at boot, so a bad role config fails loud
/// immediately rather than at first grant. Mirrors TS `create_role_registry`'s
/// throws.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoleRegistryError {
    /// An app role reused a builtin name (`keeper` / `admin`).
    #[error("app role \"{0}\" collides with a builtin role")]
    BuiltinCollision(String),
    /// Two app roles share a name.
    #[error("duplicate role name \"{0}\"")]
    Duplicate(String),
    /// A role name violated [`is_valid_name`].
    #[error(
        "invalid role name \"{0}\": must be lowercase letters and underscores \
         (a-z_), no leading, trailing or consecutive underscores, at most {max} characters",
        max = NAME_LENGTH_MAX
    )]
    InvalidName(String),
}

/// The app's role vocabulary: the builtins (`keeper`, `admin`) plus any
/// consumer-defined roles.
///
/// Reads drive **conferral** (admin-only):
/// [`is_admin_grantable`](RoleRegistry::is_admin_grantable) gates the
/// offer/revoke paths and `role_grant_assign`;
/// [`list_admin_grantable`](RoleRegistry::list_admin_grantable) feeds the
/// `/admin` "+role" UI via `admin_account_list.grantable_roles`. The default
/// registry (builtins only) admits exactly today's `["admin"]`, so behaviour is
/// byte-identical when a consumer supplies nothing.
///
/// Right-sized Rust twin of TS `create_role_registry`.
#[derive(Debug, Clone)]
pub struct RoleRegistry {
    specs: HashMap<String, RoleSpec>,
}

impl Default for RoleRegistry {
    /// The builtins-only registry: `keeper` (bootstrap) + `admin` (admin path).
    fn default() -> Self {
        let mut specs = HashMap::with_capacity(2);
        specs.insert(
            ROLE_KEEPER.to_owned(),
            RoleSpec::new(ROLE_KEEPER, vec![GrantPath::Bootstrap]),
        );
        specs.insert(
            ROLE_ADMIN.to_owned(),
            RoleSpec::new(ROLE_ADMIN, vec![GrantPath::Admin]),
        );
        Self { specs }
    }
}

impl RoleRegistry {
    /// Build a registry from consumer-defined roles, merged atop the builtins.
    ///
    /// Construction-time guards (fail-loud at boot, mirroring TS
    /// `create_role_registry`): each name is valid ([`is_valid_name`]), none
    /// collides with a builtin, and no two app roles share a name.
    ///
    /// # Errors
    /// [`RoleRegistryError`] on an invalid, builtin-colliding, or duplicate name.
    pub fn new(consumer_roles: Vec<RoleSpec>) -> Result<Self, RoleRegistryError> {
        let mut registry = Self::default();
        for spec in consumer_roles {
            if !is_valid_name(&spec.name) {
                return Err(RoleRegistryError::InvalidName(spec.name));
            }
            if is_builtin_role(&spec.name) {
                return Err(RoleRegistryError::BuiltinCollision(spec.name));
            }
            // Builtins are already excluded above, so a hit here is an
            // earlier-inserted app role — a duplicate.
            if registry.specs.contains_key(&spec.name) {
                return Err(RoleRegistryError::Duplicate(spec.name));
            }
            registry.specs.insert(spec.name.clone(), spec);
        }
        Ok(registry)
    }

    /// Whether `role` may be conferred admin-side — i.e. its `grant_paths`
    /// includes [`GrantPath::Admin`]. Registry-driven replacement for the old
    /// admin-grantable hardcode; the default registry admits exactly `admin`.
    /// Returns `false` for unknown roles.
    #[must_use]
    pub fn is_admin_grantable(&self, role: &str) -> bool {
        self.specs
            .get(role)
            .is_some_and(|spec| spec.grant_paths.contains(&GrantPath::Admin))
    }

    /// Every admin-grantable role name, sorted (deterministic — `HashMap`
    /// iteration order is not). Feeds `admin_account_list.grantable_roles`.
    #[must_use]
    pub fn list_admin_grantable(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .specs
            .values()
            .filter(|spec| spec.grant_paths.contains(&GrantPath::Admin))
            .map(|spec| spec.name.clone())
            .collect();
        out.sort();
        out
    }

    /// Whether `role` is in the vocabulary — a builtin or a consumer role,
    /// with or without a grant path. The check `cell_grant_create` runs on a
    /// role-shaped principal, so the auth and cell-grant vocabularies are one
    /// registry. Mirrors TS `role_specs.has(role)`.
    #[must_use]
    pub fn contains(&self, role: &str) -> bool {
        self.specs.contains_key(role)
    }

    /// Every role name in the vocabulary — the builtins plus any consumer
    /// roles — sorted (deterministic; `HashMap` iteration order is not).
    #[must_use]
    pub fn role_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self.specs.keys().cloned().collect();
        out.sort();
        out
    }
}

/// Whether `name` is a builtin role (`keeper` / `admin`).
///
/// Builtin roles are **global-only**: no grant path binds one to a scope
/// (`role_grant_assign`, `role_grant_offer_create`, and
/// `role_grant_offer_accept` refuse it), and every gate that reads one checks
/// the global grant, so a scoped builtin row confers nothing.
#[must_use]
pub fn is_builtin_role(name: &str) -> bool {
    name == ROLE_KEEPER || name == ROLE_ADMIN
}

#[cfg(test)]
mod tests {
    use super::{GrantPath, RoleRegistry, RoleRegistryError, RoleSpec};
    use crate::name_schema::{NAME_LENGTH_MAX, is_valid_name};

    fn role(name: &str, paths: Vec<GrantPath>) -> RoleSpec {
        RoleSpec::new(name, paths)
    }

    #[test]
    fn default_registry_grants_only_admin() {
        let registry = RoleRegistry::default();
        // The default registry: only `admin` is admin-grantable.
        assert!(registry.is_admin_grantable("admin"));
        assert!(!registry.is_admin_grantable("keeper")); // bootstrap path only
        assert!(!registry.is_admin_grantable("post")); // unknown role
        assert_eq!(registry.list_admin_grantable(), vec!["admin".to_owned()]);
    }

    #[test]
    fn app_role_with_admin_path_is_grantable() {
        let registry = RoleRegistry::new(vec![
            role("react", vec![GrantPath::Admin]),
            role("reply", vec![GrantPath::Admin]),
            role("post", vec![GrantPath::Admin]),
        ])
        .expect("valid registry");
        assert!(registry.is_admin_grantable("post"));
        assert!(registry.is_admin_grantable("admin")); // builtin still present
        // Sorted: admin, post, react, reply.
        assert_eq!(
            registry.list_admin_grantable(),
            vec![
                "admin".to_owned(),
                "post".to_owned(),
                "react".to_owned(),
                "reply".to_owned(),
            ]
        );
    }

    #[test]
    fn role_names_lists_builtins_plus_app_roles_sorted() {
        // The default registry vocabulary is exactly the two builtins.
        assert_eq!(
            RoleRegistry::default().role_names(),
            vec!["admin".to_owned(), "keeper".to_owned()]
        );
        // Consumer roles join the builtins.
        let registry = RoleRegistry::new(vec![
            role("react", vec![GrantPath::Admin]),
            role("reply", vec![GrantPath::Admin]),
            role("post", vec![GrantPath::Admin]),
        ])
        .expect("valid registry");
        assert_eq!(
            registry.role_names(),
            vec![
                "admin".to_owned(),
                "keeper".to_owned(),
                "post".to_owned(),
                "react".to_owned(),
                "reply".to_owned(),
            ]
        );
    }

    #[test]
    fn app_role_without_admin_path_is_not_grantable() {
        // A self-service-only role is not admin-grantable.
        let registry =
            RoleRegistry::new(vec![role("subscriber", vec![GrantPath::SelfService])]).unwrap();
        assert!(!registry.is_admin_grantable("subscriber"));
        assert_eq!(registry.list_admin_grantable(), vec!["admin".to_owned()]);
    }

    #[test]
    fn builtin_collision_is_rejected() {
        assert_eq!(
            RoleRegistry::new(vec![role("admin", vec![GrantPath::Admin])]).unwrap_err(),
            RoleRegistryError::BuiltinCollision("admin".to_owned())
        );
        assert_eq!(
            RoleRegistry::new(vec![role("keeper", vec![GrantPath::Bootstrap])]).unwrap_err(),
            RoleRegistryError::BuiltinCollision("keeper".to_owned())
        );
    }

    #[test]
    fn duplicate_app_role_is_rejected() {
        assert_eq!(
            RoleRegistry::new(vec![
                role("post", vec![GrantPath::Admin]),
                role("post", vec![GrantPath::Admin]),
            ])
            .unwrap_err(),
            RoleRegistryError::Duplicate("post".to_owned())
        );
    }

    #[test]
    fn invalid_names_are_rejected() {
        for bad in [
            "_post", "post_", "Post", "po st", "po-st", "", "po__st", "po___st", "a_b__c",
            "__post", "post__", "__",
        ] {
            assert!(!is_valid_name(bad), "{bad:?} should be invalid");
            assert_eq!(
                RoleRegistry::new(vec![role(bad, vec![GrantPath::Admin])]).unwrap_err(),
                RoleRegistryError::InvalidName(bad.to_owned())
            );
        }
        for good in ["post", "a", "classroom_teacher", "react", "a_b_c"] {
            assert!(is_valid_name(good), "{good:?} should be valid");
        }
    }

    #[test]
    fn a_role_name_is_capped_at_its_length_max() {
        assert_eq!(NAME_LENGTH_MAX, 64);
        let at_max = "a".repeat(NAME_LENGTH_MAX);
        let over_max = "a".repeat(NAME_LENGTH_MAX + 1);
        assert!(is_valid_name(&at_max));
        assert!(!is_valid_name(&over_max));
        // underscores count toward the length like any other character
        let with_underscores = format!("{}aa", "a_".repeat(NAME_LENGTH_MAX / 2 - 1));
        assert_eq!(with_underscores.len(), NAME_LENGTH_MAX);
        assert!(is_valid_name(&with_underscores));
        assert!(!is_valid_name(&format!("{with_underscores}a")));

        // the registry rides the grammar: a consumer role past the cap fails at boot
        assert!(RoleRegistry::new(vec![role(&at_max, vec![GrantPath::Admin])]).is_ok());
        assert_eq!(
            RoleRegistry::new(vec![role(&over_max, vec![GrantPath::Admin])]).unwrap_err(),
            RoleRegistryError::InvalidName(over_max)
        );
    }

    /// The message states the cap from the constant, so the two cannot drift.
    #[test]
    fn an_invalid_role_name_error_states_the_length_cap() {
        let rendered = RoleRegistryError::InvalidName("Bad".to_owned()).to_string();
        assert_eq!(
            rendered,
            format!(
                "invalid role name \"Bad\": must be lowercase letters and underscores (a-z_), \
                 no leading, trailing or consecutive underscores, at most \
                 {NAME_LENGTH_MAX} characters"
            )
        );
        assert!(rendered.ends_with("at most 64 characters"), "{rendered}");
    }
}
