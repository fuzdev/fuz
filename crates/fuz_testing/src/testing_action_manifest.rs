//! `_testing_action_manifest` action spec.
//!
//! Test binaries append this to their `ActionRegistry` after the rest of the
//! mount is assembled. It dumps the live RPC method set as a normalized
//! `{method, input, side_effects, account, actor, roles, credential_types,
//! rate_limit}` manifest — JSON-shaped to match `fuz_app`'s TS `ActionManifest`
//! — so the cross-backend harness can diff a Rust backend's RPC surface
//! against the TS reference's via
//! `assert_action_manifests_equal` (exact method-set + per-method auth shape).
//! The action-surface twin of `_testing_schema_snapshot`.
//!
//! Mirrors `fuz_app`'s TS `create_testing_action_manifest_action`
//! (`testing/cross_backend/testing_reset_actions.ts`): the manifest is built
//! once at assembly time from every mounted spec **plus this action's own
//! descriptor** (the manifest action is itself a live method, so it must appear
//! in the dump it serves), and the handler serves that cached value.
//!
//! **Protocol actions excluded.** `heartbeat` is HTTP-unreachable on both
//! impls (WS-only on the TS spine; `ws_only` on the Rust registry), but
//! `peer/ping` is organized differently — the TS spine mounts it on the HTTP
//! endpoint the manifest enumerates as well as the WS one, the Rust stub
//! compiles one shared registry — so including the protocol family would be a
//! spurious cross-impl diff. The builder drops every
//! [`PROTOCOL_ACTION_SPECS`] method by name, matching the TS scope (whose
//! mount list never contains them). `cancel` needs no filter on either side:
//! it is a notification the WS read loop owns and is mounted on no dispatch
//! map at all.
//!
//! Read-only + daemon-token gated (`crate::TESTING_ACTION_AUTH`), matching
//! `_testing_reset` and its siblings.

use std::collections::HashSet;
use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec, PROTOCOL_ACTION_SPECS};
use fuz_auth::{AuthAxis, AuthSpec, RateLimitClass};
use fuz_http::InputShape;
use serde_json::{Value, json};

/// This action's own wire method name — folded into the manifest it serves.
/// Matches the TS `testing_action_manifest_action_spec.method`.
const TESTING_ACTION_MANIFEST_METHOD: &str = "_testing_action_manifest";

/// Map an [`AuthAxis`] to its TS `AuthAxisState` wire string
/// (`'none' | 'optional' | 'required'`).
const fn auth_axis_name(axis: AuthAxis) -> &'static str {
    match axis {
        AuthAxis::None => "none",
        AuthAxis::Optional => "optional",
        AuthAxis::Required => "required",
    }
}

/// Sorted owned copy of a `&str` iterator — `[]` when the gate is absent, so
/// the cross-impl diff never trips on a `None`-vs-`[]` or declaration-order
/// difference between impls. Matches the TS `sorted_strings`.
fn sorted_strings<'a>(items: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut v: Vec<String> = items.map(ToOwned::to_owned).collect();
    v.sort();
    v
}

/// Normalize one spec's method + input shape + auth + side-effects + rate
/// limit into a manifest entry, matching the TS `action_manifest_entry`.
/// `AuthSpec` is `Copy`, so it's taken by value.
///
/// `input` is the spec's declared [`InputShape`] — `"void"` or `"object"`,
/// the TS side's `is_void_schema(spec.input)` — so a parameterless method one
/// spine declares and the other does not is a parity diff.
///
/// `rate_limit` is the spec's own class — the one the dispatcher gates, the
/// auth-family specs' included. It comes off the spec, so a consumer's own
/// undeclared method reports `null` even when it shares a name with an auth
/// family's.
fn manifest_entry(
    method: &str,
    input: InputShape,
    auth: AuthSpec,
    side_effects: bool,
    rate_limit: Option<RateLimitClass>,
) -> Value {
    json!({
        "method": method,
        "input": input.name(),
        "side_effects": side_effects,
        "account": auth_axis_name(auth.account),
        "actor": auth_axis_name(auth.actor),
        "roles": sorted_strings(auth.roles.unwrap_or(&[]).iter().copied()),
        // `CredentialGate::Any` flattens to `[]` — the same wire shape the
        // old `credential_types: None` produced, so the cross-backend parity
        // diff against fuz_app's optional `credential_types` is unchanged.
        "credential_types": sorted_strings(
            auth.credentials.allowed().iter().map(|c| c.name()),
        ),
        // Always present: an ungated method serializes an explicit `null`,
        // matching the TS entry's nullable-not-optional `rate_limit`, so a
        // missing key reads as drift rather than a default.
        "rate_limit": rate_limit.map(RateLimitClass::name),
    })
}

/// Build the normalized `{methods: [...]}` manifest from a backend's live RPC
/// mount.
///
/// Drops the protocol actions (`heartbeat` / `peer/ping`) and folds in this
/// action's own descriptor (it's appended to the mount *after* `mounted` is
/// built, so it isn't in the list yet — exactly like the TS mirror). Entries
/// are sorted by `method` (byte order, which equals the TS string order for
/// the ASCII method names) so two impls producing the same set serialize
/// identically regardless of mount order.
fn build_action_manifest(mounted: &[ActionSpec]) -> Value {
    let protocol_methods: HashSet<&str> =
        PROTOCOL_ACTION_SPECS().iter().map(|s| s.method).collect();

    let mut entries: Vec<(&str, Value)> = mounted
        .iter()
        .filter(|s| !protocol_methods.contains(s.method))
        .map(|s| {
            (
                s.method,
                manifest_entry(s.method, s.input, s.auth, s.side_effects, s.rate_limit),
            )
        })
        .collect();
    entries.push((
        TESTING_ACTION_MANIFEST_METHOD,
        manifest_entry(
            TESTING_ACTION_MANIFEST_METHOD,
            InputShape::Void,
            crate::TESTING_ACTION_AUTH,
            false,
            None,
        ),
    ));
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let methods: Vec<Value> = entries.into_iter().map(|(_, entry)| entry).collect();
    json!({ "methods": methods })
}

/// Build the `_testing_action_manifest` action over a backend's full live RPC
/// mount.
///
/// The handler closes over a manifest computed once here from `mounted` (see
/// `build_action_manifest`); each call clones and returns the cached value,
/// so dispatch does no work beyond the daemon-token gate and the void rule its
/// TS twin's `s.void` input declares ([`InputShape::Void`], held by the
/// dispatcher).
/// Append it to the registry **last**, passing the assembled spec list — it must enumerate every
/// method mounted above it.
#[must_use]
pub fn create_testing_action_manifest_action_spec(mounted: &[ActionSpec]) -> ActionSpec {
    let manifest = build_action_manifest(mounted);

    let handler: ActionHandler = Arc::new(move |_params: Value, _ctx: ActionContext<'_>| {
        let manifest = manifest.clone();
        Box::pin(async move { Ok(manifest) })
    });

    ActionSpec::read_only(
        TESTING_ACTION_MANIFEST_METHOD,
        crate::TESTING_ACTION_AUTH,
        InputShape::Void,
        handler,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fuz_actions::{ActionHandler, ActionRegistry, ActionSpec, PROTOCOL_ACTION_SPECS};
    use fuz_auth::{AuthSpec, CredentialGate, RateLimitClass};
    use fuz_http::InputShape;
    use serde_json::Value;

    use super::{TESTING_ACTION_MANIFEST_METHOD, build_action_manifest};

    /// A handler that never runs — these tests read only `method` / `auth` /
    /// `side_effects` off the specs and the built manifest.
    fn noop_handler() -> ActionHandler {
        Arc::new(|_params: Value, _ctx| Box::pin(async { Ok(Value::Null) }))
    }

    /// A mount mixing protocol actions, a public read, a parameterless read, a
    /// gated mutation, a spec declaring its own rate-limit class, an
    /// adapter-built auth-family spec carrying its entry's class, and a
    /// consumer spec that merely shares an auth-family method name — the
    /// shapes the manifest must normalize and the protocol filter must drop.
    fn sample_mount() -> Vec<ActionSpec> {
        let mut specs = PROTOCOL_ACTION_SPECS();
        specs.push(ActionSpec::read_only(
            "zeta_read",
            AuthSpec::public(),
            InputShape::Object,
            noop_handler(),
        ));
        specs.push(ActionSpec::with_side_effects(
            "alpha_write",
            super::super::TESTING_ACTION_AUTH,
            InputShape::Object,
            noop_handler(),
        ));
        specs.push(
            ActionSpec::read_only(
                "mu_throttled_read",
                AuthSpec::account_grain(CredentialGate::Any),
                InputShape::Object,
                noop_handler(),
            )
            .with_rate_limit(RateLimitClass::Both),
        );
        // What the auth adapter builds: the entry's class on `rate_limit`.
        specs.push(
            ActionSpec::with_side_effects(
                "nu_auth_family_write",
                AuthSpec::account_grain(CredentialGate::Any),
                InputShape::Object,
                noop_handler(),
            )
            .with_rate_limit(RateLimitClass::Account),
        );
        // A parameterless method — the TS twin's `s.void` input.
        specs.push(ActionSpec::read_only(
            "omicron_void_read",
            AuthSpec::public(),
            InputShape::Void,
            noop_handler(),
        ));
        // A consumer spec that happens to share an auth-family method name
        // and declares no class of its own — the manifest reports what this
        // spec carries, never what the registry of the same name says.
        specs.push(ActionSpec::with_side_effects(
            "role_grant_offer_create",
            AuthSpec::public(),
            InputShape::Object,
            noop_handler(),
        ));
        specs
    }

    /// The sample is a mount the registry accepts, so the manifest is tested
    /// over shapes a live server can serve.
    #[test]
    fn sample_mount_compiles_into_a_registry() {
        let mount = sample_mount();
        let count = mount.len();
        let registry = ActionRegistry::compile(mount)
            .unwrap_or_else(|e| panic!("the sample mount must compile: {e}"));
        assert_eq!(registry.len(), count);
    }

    fn methods_of(manifest: &Value) -> Vec<&str> {
        manifest["methods"]
            .as_array()
            .expect("methods array")
            .iter()
            .map(|m| m["method"].as_str().expect("method string"))
            .collect()
    }

    #[test]
    fn manifest_excludes_protocol_actions_and_folds_in_itself() {
        let manifest = build_action_manifest(&sample_mount());
        let methods = methods_of(&manifest);
        // heartbeat / peer/ping dropped; the two domain methods + the
        // manifest's own descriptor present.
        for protocol in PROTOCOL_ACTION_SPECS() {
            assert!(
                !methods.contains(&protocol.method),
                "protocol method {} must be excluded",
                protocol.method,
            );
        }
        assert!(methods.contains(&"zeta_read"));
        assert!(methods.contains(&"alpha_write"));
        assert!(methods.contains(&TESTING_ACTION_MANIFEST_METHOD));
    }

    #[test]
    fn manifest_is_sorted_by_method() {
        let manifest = build_action_manifest(&sample_mount());
        let methods = methods_of(&manifest);
        let mut sorted = methods.clone();
        sorted.sort_unstable();
        assert_eq!(methods, sorted, "entries must be sorted by method");
    }

    #[test]
    fn entry_normalizes_auth_axes_and_side_effects() {
        let manifest = build_action_manifest(&sample_mount());
        let methods = manifest["methods"].as_array().expect("methods array");
        let find = |name: &str| {
            methods
                .iter()
                .find(|m| m["method"] == name)
                .unwrap_or_else(|| panic!("entry {name} present"))
                .clone()
        };

        // Public read: ungated axes serialize to "none" + empty lists, no side effects.
        let zeta = find("zeta_read");
        assert_eq!(zeta["account"], "none");
        assert_eq!(zeta["actor"], "none");
        assert_eq!(zeta["roles"], serde_json::json!([]));
        assert_eq!(zeta["credential_types"], serde_json::json!([]));
        assert_eq!(zeta["side_effects"], false);

        // Daemon-token gated mutation: account required, daemon-token credential.
        let alpha = find("alpha_write");
        assert_eq!(alpha["account"], "required");
        assert_eq!(alpha["actor"], "none");
        assert_eq!(
            alpha["credential_types"],
            serde_json::json!(["daemon_token"])
        );
        assert_eq!(alpha["side_effects"], true);

        // The manifest's own descriptor carries the daemon-token gate, read-only.
        let own = find(TESTING_ACTION_MANIFEST_METHOD);
        assert_eq!(own["account"], "required");
        assert_eq!(own["credential_types"], serde_json::json!(["daemon_token"]));
        assert_eq!(own["side_effects"], false);
    }

    #[test]
    fn entry_resolves_the_rate_limit_class() {
        let manifest = build_action_manifest(&sample_mount());
        let methods = manifest["methods"].as_array().expect("methods array");
        let find = |name: &str| {
            methods
                .iter()
                .find(|m| m["method"] == name)
                .unwrap_or_else(|| panic!("entry {name} present"))
                .clone()
        };

        // An ungated spec serializes an explicit `null`, key present.
        let zeta = find("zeta_read");
        assert!(zeta.get("rate_limit").is_some(), "the key is never omitted");
        assert_eq!(zeta["rate_limit"], Value::Null);

        // A consumer spec declaring its own class resolves that class.
        assert_eq!(find("mu_throttled_read")["rate_limit"], "both");

        // An adapter-built auth-family spec reports its entry's class.
        assert_eq!(find("nu_auth_family_write")["rate_limit"], "account");

        // A spec that only shares an auth-family method name reports `null`
        // — provenance is the spec, not a global method-name lookup.
        assert_eq!(find("role_grant_offer_create")["rate_limit"], Value::Null);

        // The manifest's own descriptor is ungated.
        assert_eq!(
            find(TESTING_ACTION_MANIFEST_METHOD)["rate_limit"],
            Value::Null
        );
    }

    #[test]
    fn entry_reports_the_declared_input_shape() {
        let manifest = build_action_manifest(&sample_mount());
        let methods = manifest["methods"].as_array().expect("methods array");
        let input_of = |name: &str| {
            methods
                .iter()
                .find(|m| m["method"] == name)
                .unwrap_or_else(|| panic!("entry {name} present"))["input"]
                .clone()
        };

        assert_eq!(input_of("omicron_void_read"), "void");
        assert_eq!(input_of("zeta_read"), "object");
        // The manifest's own `s.void` input is a void input.
        assert_eq!(input_of(TESTING_ACTION_MANIFEST_METHOD), "void");
    }
}
