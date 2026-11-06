//! The clean reachability + hoisting + platform **prune** — the resolution core
//! `fuzi.lock` needs, computed standalone here.
//!
//! # What this is (and is *not*)
//!
//! [`reachable_set`] walks the lockfile graph from the root and returns the set
//! of `node_modules/…` keys that are **reachable** through followed edges *and*
//! **platform-compatible** with the host. It is the precise, internally
//! consistent host tree — fuzi's source of truth for `fuzi.lock`, where fuzi is
//! free to be *more* correct than npm.
//!
//! It is deliberately **not** wired into the `package-lock.json` install path.
//! That path keeps the v0 host-filtered **superset** ([`crate::build_plan`]):
//! build-safe, never a subset, no graph walk. The two diverge on exactly the
//! cases this prune was built to catch — a version-conflicted hoisted optional
//! whose transitive deps npm leaves `extraneous` at the root. fuzi's clean prune
//! drops those orphans; the v0 superset keeps them (harmless, unloaded). Matching
//! npm's tree byte-for-byte would mean reproducing npm's bug.
//!
//! # The algorithm
//!
//! An entry installs iff it is **platform-compatible** *and* **reachable** from
//! the root through followed edges:
//!
//! - **Reachability** — walk from `packages[""]`, seeding with the root's
//!   `dependencies` + `devDependencies` + `optionalDependencies` +
//!   `peerDependencies`; from each visited (non-root) entry follow its
//!   `dependencies` + `optionalDependencies` + `peerDependencies`. A transitive
//!   entry never contributes `devDependencies` — npm installs dev deps for the
//!   root project only.
//! - **Hoisting** — a dep name `D` requested from key `K` resolves to the
//!   nearest existing `…/node_modules/D`, walking up `K`'s `node_modules`
//!   ancestors to the top level (npm's hoisting; see [`resolve_dep`]).
//! - **Platform filter on the edge** — an edge to a platform-mismatched target
//!   is not followed, so the target *and its exclusive subtree* are pruned. This
//!   is what drops the orphans: the off-host wasm32 package is pruned, leaving
//!   its `@napi-rs/wasm-runtime` puller unreachable, leaving `@emnapi/*` (which
//!   carry no platform constraint of their own) unreachable too.
//!
//! The prune reads only the **edge maps** and the **platform axes** of each
//! entry — never the per-entry `optional`/`dev`/`peer` reason flags. The reason
//! is derived from the *path* by which an entry is (or isn't) reached, which is
//! strictly more correct than trusting npm's pre-computed flags.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::Omit;
use crate::entry::InstallPath;
use crate::lockfile::raw::{RawLockfile, RawPackageEntry};
use crate::platform::Platform;

/// Compute the clean install set: every `node_modules/…` key reachable from the
/// root through followed edges that is also platform-compatible with `host`.
///
/// `omit` drops dependency classes by removing their edge maps from the walk —
/// `Dev` drops the root's `devDependencies` seed (transitive walks never carry
/// dev anyway), `Optional` and `Peer` drop those maps everywhere. A package
/// reachable through a *retained* edge survives even if some other path to it
/// was omitted (reachability handles the join).
///
/// The result is the deterministic (`BTreeSet`) set of reachable keys; the root
/// `""` key is the seed, never a member. Returns an empty set for a lockfile
/// with no root entry or no dependencies.
///
/// # The `--omit` × reachability coupling
///
/// Modelling omit as edge-map selection (the "seed-set" choice) is tentative. It is
/// validated exactly against the fuz projects' own lockfiles (a local survey of
/// their `package-lock.json` files) at `omit == []`; the partial-omit arms are
/// unit-tested but not surveyed. The alternative — a per-entry
/// `RegistryEntry::retained_under` post-filter — is what the v0 install path uses
/// and may differ on a package reachable by mixed edge classes.
#[must_use]
pub fn reachable_set(raw: &RawLockfile, host: &Platform, omit: &[Omit]) -> BTreeSet<InstallPath> {
    Walk::new(&raw.packages, host, omit).run(!omit.contains(&Omit::Dev))
}

/// State for one reachability walk: the borrowed lockfile, per-key platform
/// compatibility (computed once), the retained edge-map flags, and the BFS
/// frontier. Lookups into `packages` are `'a`-scoped (the map is borrowed, not
/// owned), so the walk freely mutates `visited`/`queue` while holding entry
/// references — no field-borrow conflict.
struct Walk<'a> {
    packages: &'a BTreeMap<String, RawPackageEntry>,
    platform_ok: HashMap<&'a str, bool>,
    follow_optional: bool,
    follow_peer: bool,
    visited: BTreeSet<String>,
    queue: VecDeque<String>,
}

impl<'a> Walk<'a> {
    fn new(
        packages: &'a BTreeMap<String, RawPackageEntry>,
        host: &Platform,
        omit: &[Omit],
    ) -> Self {
        Self {
            packages,
            platform_ok: packages
                .iter()
                .map(|(key, entry)| {
                    (
                        key.as_str(),
                        host.accepts_raw(&entry.os, &entry.cpu, &entry.libc),
                    )
                })
                .collect(),
            follow_optional: !omit.contains(&Omit::Optional),
            follow_peer: !omit.contains(&Omit::Peer),
            visited: BTreeSet::new(),
            queue: VecDeque::new(),
        }
    }

    /// Seed from the root entry (the only entry that contributes dev edges,
    /// unless omitted), drain the frontier, and return the reachable keys.
    fn run(mut self, include_root_dev: bool) -> BTreeSet<InstallPath> {
        if self.packages.contains_key("") {
            self.follow("", include_root_dev);
        }
        while let Some(key) = self.queue.pop_front() {
            self.follow(&key, false);
        }
        self.visited.into_iter().map(InstallPath::new).collect()
    }

    /// Follow `from_key`'s selected edge maps: resolve each dep name by hoisting
    /// and enqueue any platform-compatible, not-yet-visited target.
    fn follow(&mut self, from_key: &str, include_dev: bool) {
        let Some(entry) = self.packages.get(from_key) else {
            return;
        };
        // A link is a reachable leaf: its target is local source whose own
        // dependencies are not the linking project's to install. arborist does
        // the same — `#resolveLinks` skips an external target ("somebody else's
        // problem"). npm writes a link entry with no edge maps, so this only
        // matters for a hand-edited one, but the leaf is the semantics. Every
        // link is a leaf here; for an in-tree workspace target arborist does
        // follow the target's edges, but fuzi refuses those links, so the
        // difference is unobservable.
        if entry.link == Some(true) {
            return;
        }
        for name in edge_names(entry, include_dev, self.follow_optional, self.follow_peer) {
            let Some(target) = resolve_dep(self.packages, from_key, name) else {
                continue; // dangling edge — npm never placed this dep (e.g. a pruned optional)
            };
            if self.platform_ok.get(target).copied().unwrap_or(false)
                && self.visited.insert(target.to_string())
            {
                self.queue.push_back(target.to_string());
            }
        }
    }
}

/// The dependency names `entry` contributes, across its selected edge maps.
fn edge_names<'a>(
    entry: &'a RawPackageEntry,
    include_dev: bool,
    follow_optional: bool,
    follow_peer: bool,
) -> impl Iterator<Item = &'a str> {
    let names = |map: Option<&'a BTreeMap<String, String>>, on: bool| {
        on.then_some(map)
            .flatten()
            .into_iter()
            .flat_map(BTreeMap::keys)
            .map(String::as_str)
    };
    names(entry.dependencies.as_ref(), true)
        .chain(names(entry.dev_dependencies.as_ref(), include_dev))
        .chain(names(entry.optional_dependencies.as_ref(), follow_optional))
        .chain(names(entry.peer_dependencies.as_ref(), follow_peer))
}

/// npm hoisting: resolve dependency `name` requested from the entry at `from_key`
/// to the nearest existing `…/node_modules/<name>` key, walking up `from_key`'s
/// `node_modules` ancestors to the top level.
///
/// Tries `from_key/node_modules/<name>` first (a copy nested inside the
/// requester), then strips the last `/node_modules/…` segment and retries one
/// scope up, ending at the top-level `node_modules/<name>`. Returns the first
/// existing key, or `None` if no copy exists (a dangling edge — e.g. an optional
/// dep npm reachability-pruned). The `packages` map guarantees at most one match per
/// scope, so the nearest is unambiguous.
fn resolve_dep<'a>(
    packages: &'a BTreeMap<String, RawPackageEntry>,
    from_key: &str,
    name: &str,
) -> Option<&'a str> {
    let mut prefix = from_key.to_string();
    loop {
        let candidate = if prefix.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{prefix}/node_modules/{name}")
        };
        if let Some((key, _)) = packages.get_key_value(&candidate) {
            return Some(key.as_str());
        }
        if prefix.is_empty() {
            return None;
        }
        match prefix.rfind("/node_modules/") {
            Some(i) => prefix.truncate(i),
            None => prefix.clear(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::host_linux_x64_glibc;
    use serde_json::{Value, json};

    /// Parse a `package-lock.json` JSON literal into a `RawLockfile`.
    fn lock(value: Value) -> RawLockfile {
        serde_json::from_value(value).unwrap()
    }

    /// The reachable set as a sorted `Vec<String>` of keys, for ergonomic asserts.
    fn keys(set: &BTreeSet<InstallPath>) -> Vec<String> {
        set.iter().map(|p| p.as_str().to_string()).collect()
    }

    /// `reachable_set` on the canonical linux/x64/glibc host with no omit.
    fn prune(value: Value) -> BTreeSet<InstallPath> {
        reachable_set(&lock(value), &host_linux_x64_glibc(), &[])
    }

    // --- reachability ---

    #[test]
    fn empty_and_root_only_are_empty() {
        assert!(prune(json!({"lockfileVersion": 3, "packages": {}})).is_empty());
        assert!(
            prune(json!({"lockfileVersion": 3, "packages": {"": {"name": "solo"}}})).is_empty()
        );
    }

    #[test]
    fn simple_chain_excludes_unreachable() {
        // root → a → b ; c sits in the lockfile but nothing reaches it.
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"dependencies": {"b": "1"}},
                "node_modules/b": {},
                "node_modules/c": {}
            }
        }));
        assert_eq!(keys(&set), ["node_modules/a", "node_modules/b"]);
    }

    #[test]
    fn root_is_seed_never_a_member() {
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {}
            }
        }));
        assert!(!set.contains(&InstallPath::new("")));
    }

    #[test]
    fn cycle_terminates() {
        // a ↔ b mutual dep: the visited guard prevents infinite recursion.
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"dependencies": {"b": "1"}},
                "node_modules/b": {"dependencies": {"a": "1"}}
            }
        }));
        assert_eq!(keys(&set), ["node_modules/a", "node_modules/b"]);
    }

    #[test]
    fn dangling_edge_ignored() {
        // root depends on a name npm never placed — no key, no crash, not added.
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {"": {"dependencies": {"ghost": "1"}}}
        }));
        assert!(set.is_empty());
    }

    // --- hoisting ---

    #[test]
    fn hoisting_walks_up_to_root_copy() {
        // A nested package depends on `shared`, which exists only at the top
        // level — resolves up to the root copy.
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"dependencies": {"shared": "1"}},
                "node_modules/shared": {}
            }
        }));
        assert!(set.contains(&InstallPath::new("node_modules/shared")));
    }

    #[test]
    fn hoisting_nearest_copy_wins() {
        // `a` has its own nested `shared`; the edge resolves to the nested copy,
        // not the (also-present) root copy. The root copy is still reachable via
        // root's own dependency on it.
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1", "shared": "2"}},
                "node_modules/a": {"dependencies": {"shared": "1"}},
                "node_modules/a/node_modules/shared": {},
                "node_modules/shared": {}
            }
        }));
        assert!(set.contains(&InstallPath::new("node_modules/a/node_modules/shared")));
        assert!(set.contains(&InstallPath::new("node_modules/shared")));
    }

    #[test]
    fn hoisting_nested_copy_reachable_only_via_nested_parent() {
        // The nested `shared` is reached only through `a`; root does not depend on
        // `shared` directly, so the top-level copy is absent here.
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"dependencies": {"shared": "1"}},
                "node_modules/a/node_modules/shared": {}
            }
        }));
        assert_eq!(
            keys(&set),
            ["node_modules/a", "node_modules/a/node_modules/shared"]
        );
    }

    // --- platform prune ---

    #[test]
    fn off_host_optional_and_its_exclusive_subtree_pruned() {
        // root → wasm-pkg (cpu wasm32, off-host) → only-wasm-dep. Both dropped on
        // x64; the host-matching binary is kept.
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"optionalDependencies": {"native": "1"}},
                "node_modules/native": {"optionalDependencies": {
                    "native-linux-x64": "1", "native-wasm32": "1"
                }},
                "node_modules/native-linux-x64": {"os": ["linux"], "cpu": ["x64"]},
                "node_modules/native-wasm32": {"cpu": ["wasm32"], "dependencies": {"only-wasm-dep": "1"}},
                "node_modules/only-wasm-dep": {}
            }
        }));
        assert!(set.contains(&InstallPath::new("node_modules/native")));
        assert!(set.contains(&InstallPath::new("node_modules/native-linux-x64")));
        assert!(!set.contains(&InstallPath::new("node_modules/native-wasm32")));
        // only-wasm-dep is platform-unconstrained but reachable *only* through the
        // pruned wasm32 package — so it drops too. This is the orphan mechanism.
        assert!(!set.contains(&InstallPath::new("node_modules/only-wasm-dep")));
    }

    // --- peer edges ---

    #[test]
    fn peer_edges_followed_from_root_and_transitively() {
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"peerDependencies": {"a": "1"}},
                "node_modules/a": {"peerDependencies": {"b": "1"}},
                "node_modules/b": {}
            }
        }));
        assert_eq!(keys(&set), ["node_modules/a", "node_modules/b"]);
    }

    // --- omit (seed-set model; surveyed only at omit == []) ---

    #[test]
    fn omit_dev_drops_root_dev_subtree() {
        let value = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"prod": "1"}, "devDependencies": {"devtool": "1"}},
                "node_modules/prod": {},
                "node_modules/devtool": {}
            }
        });
        let host = host_linux_x64_glibc();
        let all = reachable_set(&lock(value.clone()), &host, &[]);
        assert!(all.contains(&InstallPath::new("node_modules/devtool")));
        let no_dev = reachable_set(&lock(value), &host, &[Omit::Dev]);
        assert!(!no_dev.contains(&InstallPath::new("node_modules/devtool")));
        assert!(no_dev.contains(&InstallPath::new("node_modules/prod")));
    }

    #[test]
    fn omit_dev_keeps_package_also_reached_via_prod() {
        // `shared` is both a root devDependency and pulled by a prod dep. Dropping
        // the dev seed must not drop it — reachability via prod keeps it.
        let value = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"prod": "1"}, "devDependencies": {"shared": "1"}},
                "node_modules/prod": {"dependencies": {"shared": "1"}},
                "node_modules/shared": {}
            }
        });
        let no_dev = reachable_set(&lock(value), &host_linux_x64_glibc(), &[Omit::Dev]);
        assert!(no_dev.contains(&InstallPath::new("node_modules/shared")));
    }

    #[test]
    fn omit_optional_drops_optional_only_subtree() {
        let value = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"optionalDependencies": {"maybe": "1"}},
                "node_modules/maybe": {}
            }
        });
        let host = host_linux_x64_glibc();
        assert!(
            reachable_set(&lock(value.clone()), &host, &[])
                .contains(&InstallPath::new("node_modules/maybe"))
        );
        assert!(
            !reachable_set(&lock(value), &host, &[Omit::Optional])
                .contains(&InstallPath::new("node_modules/maybe"))
        );
    }

    #[test]
    fn omit_peer_drops_peer_only_subtree() {
        let value = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"peerDependencies": {"p": "1"}},
                "node_modules/p": {}
            }
        });
        let host = host_linux_x64_glibc();
        assert!(
            reachable_set(&lock(value.clone()), &host, &[])
                .contains(&InstallPath::new("node_modules/p"))
        );
        assert!(reachable_set(&lock(value), &host, &[Omit::Peer]).is_empty());
    }

    // --- the deliberate npm divergence (fuz_app @napi-rs/wasm-runtime → @emnapi) ---

    /// A faithful reduction of `fuz_app`'s real subtree: two platform packages
    /// (`@node-rs/argon2-wasm32-wasi`, `@oxc-parser/binding-wasm32-wasi`, both
    /// `cpu: ["wasm32"]`) each pull a *different major* of `@napi-rs/wasm-runtime`
    /// (`^0.2` hoisted at root, `^1` nested under the oxc binding), and both
    /// runtimes pull the platform-unconstrained `@emnapi/*` + `@tybys/wasm-util`
    /// chain. On a linux/x64 host both wasm32 packages are platform-pruned, so
    /// every runtime/emnapi/wasm-util entry becomes unreachable.
    ///
    /// npm leaves `@emnapi/core`, `@emnapi/runtime`, `@emnapi/wasi-threads`, and
    /// `@tybys/wasm-util` installed at the root — its own `npm explain` calls them
    /// `extraneous` (an incomplete prune cascade). fuzi's clean prune drops them.
    /// This test pins that deliberate divergence: matching npm's tree would mean
    /// reproducing npm's bug.
    fn fuz_app_divergence_lock() -> Value {
        json!({
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {"@node-rs/argon2": "2"},
                    "devDependencies": {"oxc-parser": "0.99"}
                },
                "node_modules/@node-rs/argon2": {"optionalDependencies": {
                    "@node-rs/argon2-linux-x64-gnu": "2",
                    "@node-rs/argon2-wasm32-wasi": "2"
                }},
                "node_modules/@node-rs/argon2-linux-x64-gnu": {"os": ["linux"], "cpu": ["x64"], "optional": true},
                "node_modules/@node-rs/argon2-wasm32-wasi": {
                    "cpu": ["wasm32"], "optional": true,
                    "dependencies": {"@napi-rs/wasm-runtime": "^0.2.5"}
                },
                "node_modules/@napi-rs/wasm-runtime": {
                    "optional": true,
                    "dependencies": {"@emnapi/core": "^1.4.3", "@emnapi/runtime": "^1.4.3", "@tybys/wasm-util": "^0.10.0"}
                },
                "node_modules/oxc-parser": {
                    "dev": true,
                    "dependencies": {"@oxc-project/types": "0.99"},
                    "optionalDependencies": {
                        "@oxc-parser/binding-linux-x64-gnu": "0.99",
                        "@oxc-parser/binding-wasm32-wasi": "0.99"
                    }
                },
                "node_modules/@oxc-project/types": {"dev": true},
                "node_modules/@oxc-parser/binding-linux-x64-gnu": {"os": ["linux"], "cpu": ["x64"], "dev": true, "optional": true},
                "node_modules/@oxc-parser/binding-wasm32-wasi": {
                    "cpu": ["wasm32"], "dev": true, "optional": true,
                    "dependencies": {"@napi-rs/wasm-runtime": "^1.0.7"}
                },
                "node_modules/@oxc-parser/binding-wasm32-wasi/node_modules/@napi-rs/wasm-runtime": {
                    "dev": true, "optional": true,
                    "dependencies": {"@emnapi/core": "^1.7.1", "@emnapi/runtime": "^1.7.1", "@tybys/wasm-util": "^0.10.1"}
                },
                "node_modules/@emnapi/core": {"optional": true, "dependencies": {"@emnapi/wasi-threads": "1", "tslib": "2"}},
                "node_modules/@emnapi/runtime": {"optional": true, "dependencies": {"tslib": "2"}},
                "node_modules/@emnapi/wasi-threads": {"optional": true, "dependencies": {"tslib": "2"}},
                "node_modules/@tybys/wasm-util": {"optional": true, "dependencies": {"tslib": "2"}},
                "node_modules/tslib": {"optional": true}
            }
        })
    }

    #[test]
    fn divergence_keeps_host_packages() {
        let set = prune(fuz_app_divergence_lock());
        for kept in [
            "node_modules/@node-rs/argon2",
            "node_modules/@node-rs/argon2-linux-x64-gnu",
            "node_modules/oxc-parser",
            "node_modules/@oxc-project/types",
            "node_modules/@oxc-parser/binding-linux-x64-gnu",
        ] {
            assert!(
                set.contains(&InstallPath::new(kept)),
                "expected to keep {kept}"
            );
        }
    }

    #[test]
    fn divergence_drops_the_extraneous_orphans() {
        let set = prune(fuz_app_divergence_lock());
        // The exact set npm leaves `extraneous` — fuzi's clean prune drops them.
        for orphan in [
            "node_modules/@emnapi/core",
            "node_modules/@emnapi/runtime",
            "node_modules/@emnapi/wasi-threads",
            "node_modules/@tybys/wasm-util",
        ] {
            assert!(
                !set.contains(&InstallPath::new(orphan)),
                "expected to drop {orphan}"
            );
        }
        // And the off-host wasm32 packages + both unreachable wasm-runtime copies.
        for dropped in [
            "node_modules/@node-rs/argon2-wasm32-wasi",
            "node_modules/@oxc-parser/binding-wasm32-wasi",
            "node_modules/@napi-rs/wasm-runtime",
            "node_modules/@oxc-parser/binding-wasm32-wasi/node_modules/@napi-rs/wasm-runtime",
            "node_modules/tslib", // pulled only by the dropped emnapi chain
        ] {
            assert!(
                !set.contains(&InstallPath::new(dropped)),
                "expected to drop {dropped}"
            );
        }
    }

    #[test]
    fn link_is_reachable_leaf() {
        // The link key is reachable; its target entry is never a member; and a
        // package reachable only through the target's (or a tampered link
        // entry's own) edges is not reached through the link.
        let set = prune(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"devDependencies": {"lib": "file:../lib"}},
                "node_modules/lib": {
                    "resolved": "../lib", "link": true,
                    "dependencies": {"only-via-lib": "^1"}
                },
                "../lib": {"name": "lib", "dependencies": {"only-via-lib": "^1"}},
                "node_modules/only-via-lib": {"version": "1.0.0"}
            }
        }));
        assert_eq!(keys(&set), vec!["node_modules/lib"]);
    }
}
