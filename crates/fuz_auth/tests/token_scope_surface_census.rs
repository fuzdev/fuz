//! The **surface census** — every site in the spine that reads a request at the
//! front door ([`fuz_auth::AuthGate`]), with where its origin check happens and
//! whether it consults [`TokenScope`] or is exempt with a stated reason.
//!
//! ## The front door
//!
//! Every entry point goes through a gate: the origin check, then the
//! credential walk, which nothing outside the gate calls
//! ([`the_credential_walk_is_reached_only_through_the_gate`]). The census
//! counts each file's origin checks exactly
//! ([`every_entry_point_checks_the_origin_through_the_gate`]), so an entry
//! point that skips its check fails here even when a sibling handler in the
//! same file keeps one.
//!
//! The order within an entry point is a type rule, not this census's: a
//! credential read takes the `fuz_auth::OriginChecked` witness that only the
//! origin check makes, so a resolve without a check does not compile. What
//! the type cannot see is a surface that reads no credential (login, signup,
//! bootstrap) and so needs no witness, or one that never calls the gate at
//! all — the counts here are what catch those.
//!
//! ## Why this test exists
//!
//! An unenforced scope is the failure this guards against: a `scope` column
//! that stores `full` / `read` / `write` with nothing enforcing them is a false
//! security promise, worse than no promise.
//! That failure is not a bad vocabulary — it is a column with no
//! consumer, and nothing making that visible.
//!
//! The check itself lives at each surface, so the realistic way to reach that
//! failure is not to delete a check: it is to **add a surface and forget one**.
//! A new bearer-reachable route that resolves a credential and never asks what
//! the credential may do is a silent hole in exactly that shape — and it would
//! be invisible without a grep.
//!
//! So this test makes the set of resolution sites an assertion. It is a source
//! scan, which is crude, and deliberately so: the property it pins ("no
//! *unreviewed* call site exists") is about code that has not been written yet,
//! which no type can express. The technique is the one `fuzi_core` already uses
//! for its exec-free guard.
//!
//! **This is the proportionate control, not the strongest one.** The strongest
//! is a typestate: make the scope-consulting `authorize` call the only
//! constructor for a usable `ResolvedAuth`, so a forgetful surface fails to
//! compile. That was costed and declined — it changes every call site and the
//! WS path needs the scope to survive the upgrade rather than be consumed by it.
//! **If a surface ever does slip past this census, the typestate is the named
//! escalation**, the same way `CredentialType`'s struct-of-bools is the named
//! escalation behind `CredentialGate::Any`.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Where a census site's origin check happens.
#[derive(Clone, Copy)]
enum OriginCheck {
    /// In this file, through the gate: exactly this many `.check_origin(` /
    /// `.preflight(` calls — one per entry point the file serves.
    InFile(usize),
    /// In the named census file, which calls this one after checking.
    ByCaller(&'static str),
    /// Nowhere: the credential walk itself, reached only through a gate whose
    /// caller checks first.
    Walk,
}

/// A reviewed site that reads a request through the [`fuz_auth::AuthGate`].
struct CensusEntry {
    /// Path relative to `crates/`.
    file: &'static str,
    /// Where the origin check for this site's entry points happens.
    origin: OriginCheck,
    /// Does this site consult the credential's scope?
    consults_scope: bool,
    /// The source the consult is *made of* — every string must still appear in
    /// the file. Empty for an exempt site.
    ///
    /// Without this, `consults_scope` is a claim about the code that only the
    /// census makes: deleting the gate out of a listed file changes neither the
    /// discovered set nor the declared one, so every assertion below stays green
    /// while the surface goes ungated. Pinning the source is what makes the flag
    /// *reconciled* rather than asserted — the technique a consumer's own
    /// census uses for its gate sites.
    ///
    /// A site takes as many pins as it has distinct halves: the WS upgrade both
    /// refuses at the boundary and retains the scope for the per-message gate,
    /// and losing either is a different hole.
    markers: &'static [&'static str],
    /// Why — required in both directions, so an exemption is an argument
    /// someone wrote down rather than an omission someone didn't notice.
    reason: &'static str,
}

/// Every site in the spine that reads a request at the front door — checks its
/// origin or turns its headers into a credential.
///
/// Adding a row here is the review. A new surface must say how many entry
/// points it checks the origin for, and decide which side of the scope rule it
/// is on **and say why**, which is the whole point.
const CENSUS: &[CensusEntry] = &[
    // --- Consults scope ---
    CensusEntry {
        file: "fuz_actions/src/rpc_dispatch.rs",
        origin: OriginCheck::InFile(2),
        consults_scope: true,
        markers: &[
            // Hands the resolved credential, its scope with it, to the
            // dispatcher, which runs the gate.
            "auth: resolved.as_ref(),",
        ],
        reason: "HTTP JSON-RPC entry (POST and GET, an origin check each) — threads the \
                 scope into `perform_action`, which runs the per-method gate between the \
                 credential and role gates",
    },
    CensusEntry {
        file: "fuz_actions/src/register_action_ws.rs",
        origin: OriginCheck::InFile(1),
        consults_scope: true,
        markers: &[
            "if !resolved.scope().admits_non_rpc_surface() {",
            // Retained on the connection for the per-message gate.
            "auth: resolved,",
        ],
        reason: "WS upgrade — rule 3 rejects a narrowed token at the boundary \
                 (server-initiated pushes have no per-recipient filter), and the \
                 socket's scope is retained for the per-message gate",
    },
    CensusEntry {
        file: "fuz_auth/src/resolve.rs",
        origin: OriginCheck::Walk,
        consults_scope: true,
        markers: &["if !resolved.scope().admits_non_rpc_surface() {"],
        reason: "the credential walk and `build_public_request_context`, the resolver \
                 behind every pure-public route (today: the cell-scoped fact read) — it \
                 *downgrades to anonymous* rather than refusing, because on a route with \
                 an anonymous reading a 403 enforces nothing against a holder who drops \
                 the header",
    },
    CensusEntry {
        file: "fuz_auth/src/account_status.rs",
        origin: OriginCheck::InFile(1),
        consults_scope: true,
        markers: &["resolved.filter(|r| r.scope().admits_non_rpc_surface())"],
        reason: "account detail (email, its verification, the acting actor's role \
                 grants) — a non-RPC surface, so a narrowed token is answered as the \
                 anonymous caller (401 plus the bootstrap flag): the route answers \
                 anonymous callers, so a 403 would add nothing to that",
    },
    CensusEntry {
        file: "fuz_db_admin/src/route_auth.rs",
        origin: OriginCheck::ByCaller("fuz_db_admin/src/lib.rs"),
        consults_scope: true,
        markers: &["if !auth.scope().admits_non_rpc_surface() {"],
        reason: "the widest surface in the spine — any `public` table's rows plus \
                 row DELETE, gated only on a global role a bearer satisfies",
    },
    CensusEntry {
        file: "fuz_fact_serving/src/serve.rs",
        origin: OriginCheck::InFile(2),
        consults_scope: true,
        markers: &[
            "if !auth.scope().admits_non_rpc_surface() {",
            // The cell-scoped route's own resolution, whose gate lives in the
            // builder — pinned here so swapping it back for a cookie-only
            // resolver fails, which is the shape of the defect this closed.
            ".public_request_context(",
        ],
        reason: "two resolutions in one file, an origin check each — the admin-only \
                 bare-hash read (403s a narrowed token: it serves any stored fact with no \
                 per-reference cell check), and the pure-public cell-scoped read, which \
                 delegates to the gate's `public_request_context` and takes that \
                 resolver's downgrade-to-anonymous disposition",
    },
    CensusEntry {
        file: "fuz_realtime/src/audit_stream.rs",
        origin: OriginCheck::InFile(1),
        consults_scope: true,
        markers: &["if !auth.scope().admits_non_rpc_surface() {"],
        reason: "long-lived admin SSE feed — no point after open at which a \
                 narrowing could be applied. The sibling `credential_gate` is \
                 what actually keeps a bearer off a stock mount (rule 3 refuses \
                 a *narrowed* token; a full-scope one satisfies it), so this \
                 gate is unreachable there and load-bearing for a consumer that \
                 widens the channel",
    },
    // --- Exempt, with reasons ---
    CensusEntry {
        file: "fuz_db_admin/src/lib.rs",
        origin: OriginCheck::InFile(4),
        consults_scope: false,
        markers: &[],
        reason: "the four db-admin handlers (health, table list, table detail, row \
                 DELETE) — each checks the origin first, then resolves through \
                 `route_auth::require_role`, which carries the scope gate",
    },
    CensusEntry {
        file: "fuz_auth/src/account_login.rs",
        origin: OriginCheck::InFile(1),
        consults_scope: false,
        markers: &[],
        reason: "resolves no credential — it verifies a password and mints a session, \
                 so there is no presented token whose scope could apply",
    },
    CensusEntry {
        file: "fuz_auth/src/account_logout.rs",
        origin: OriginCheck::InFile(1),
        consults_scope: false,
        markers: &[],
        reason: "tears access down and confers nothing; already session-gated, so \
                 no bearer credential reaches it",
    },
    CensusEntry {
        file: "fuz_auth/src/account_password.rs",
        origin: OriginCheck::InFile(1),
        consults_scope: false,
        markers: &[],
        reason: "already credential-gated to the session channel; a narrowed \
                 bearer never arrives",
    },
    CensusEntry {
        file: "fuz_auth/src/bootstrap_routes.rs",
        origin: OriginCheck::InFile(1),
        consults_scope: false,
        markers: &[],
        reason: "resolves no credential — the bootstrap token is a one-time file \
                 secret checked by the handler, never an `api_token`",
    },
    CensusEntry {
        file: "fuz_auth/src/signup_routes.rs",
        origin: OriginCheck::InFile(1),
        consults_scope: false,
        markers: &[],
        reason: "resolves no credential — signup creates an account and mints its \
                 first session; no presented token is read",
    },
];

/// Files the scan sees but that are not production surfaces: the gate's own
/// definition (its fused `preflight` calls its two halves), the suites that
/// call the gate only to obtain a credential to re-check, to dispatch as, or
/// to read the deadline of (a `ResolvedAuth` has no other origin), the test
/// harness helper that resolves one for those suites (`fuz_testing`'s
/// `resolve_test_credential`, mounted by no server), and this
/// census (whose scan strings
/// name the methods without calling them — prose about them is already
/// handled by [`strip_comment_lines`]). Kept as an explicit list rather than a
/// path filter in the walker so the exclusions are as reviewable as the
/// inclusions.
const NON_SURFACE_SITES: &[&str] = &[
    "fuz_actions/tests/testing_reset_keeper_cache.rs",
    "fuz_actions/tests/ws_upgrade_admission.rs",
    "fuz_auth/src/auth_gate.rs",
    "fuz_auth/tests/credential_deadline.rs",
    "fuz_auth/tests/public_request_context.rs",
    "fuz_auth/tests/resolve_auth.rs",
    "fuz_auth/tests/revalidate_auth.rs",
    "fuz_auth/tests/token_scope_surface_census.rs",
    "fuz_testing/src/credentials.rs",
];

/// The gate's methods — the calls a front-door site is made of.
const GATE_CALLS: &[&str] = &[
    ".check_origin(",
    ".preflight(",
    ".resolve_credential(",
    ".public_request_context(",
];

/// The gate's origin-checking methods.
const ORIGIN_CALLS: &[&str] = &[".check_origin(", ".preflight("];

/// The credential walk's own entry points, which only the gate may call.
const WALK_CALLS: &[&str] = &[
    "resolve_auth_from_headers(",
    "build_public_request_context(",
];

/// The files allowed to call [`WALK_CALLS`]: the walk itself
/// (`build_public_request_context` delegates to `resolve_auth_from_headers`)
/// and the gate.
const WALK_SITES: &[&str] = &["fuz_auth/src/auth_gate.rs", "fuz_auth/src/resolve.rs"];

fn crates_dir() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `<repo>/crates/fuz_auth`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .to_path_buf()
}

/// Blank whole-line `//` comments, keeping the line structure.
///
/// Discovery asks "does this file reach a credential", and without this a file
/// that merely *writes about* the rule — a doc comment naming
/// `admits_non_rpc_surface`, a `//` note on why a gate lives elsewhere — reads
/// exactly like one that implements it. The answer is then a census row demanded
/// of prose, or a file parked in an exclusion list because of a sentence.
///
/// **Line-leading only, and deliberately not the TS twin's regex.** That one
/// also strips `/* … */`, which is unsafe over Rust source here: a route-glob
/// string literal (`"no /api/*"` in a router) opens a block comment
/// the scanner then runs to the end of the file, dropping a *real* gate site out
/// of discovery — the one failure direction this census cannot tolerate. A
/// trailing `// see admits_non_rpc_surface()` survives instead and merely
/// demands a census row, which is the direction that fails loud. The TS twin
/// carries the same hazard on its own `'/api/*'` literals and runs the same
/// line-oriented shape, keyed off `//`, `/*`, and the ` * ` continuation a doc
/// block carries there.
fn strip_comment_lines(source: &str) -> String {
    source
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Walk `crates/` for `.rs` files whose **code** matches a predicate, by path
/// relative to `crates/`.
fn discover_rs_files(matches: impl Fn(&str) -> bool) -> BTreeSet<String> {
    let root = crates_dir();
    let mut found = BTreeSet::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip build output; it contains generated copies.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                if !matches(&strip_comment_lines(&text)) {
                    continue;
                }
                found.insert(
                    path.strip_prefix(&root)
                        .expect("under crates/")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    found
}

/// Files that call a gate method or the credential walk.
///
/// `fuz_auth/src/resolve.rs` is discovered though it calls no gate method:
/// `build_public_request_context` lives beside the walk and calls it, so the
/// file is a genuine consumer, and it is the consumer carrying the spine's only
/// downgrade-instead-of-refuse disposition. Leaving it out would leave that one
/// uncensused — the exact "a surface resolves a credential and nobody decided
/// about its scope" shape this test exists to make visible.
fn discover_gate_sites() -> BTreeSet<String> {
    discover_rs_files(|text| {
        GATE_CALLS
            .iter()
            .chain(WALK_CALLS)
            .any(|call| text.contains(call))
    })
}

/// How many origin-checking gate calls `text` makes.
fn origin_call_count(text: &str) -> usize {
    ORIGIN_CALLS
        .iter()
        .map(|call| text.matches(call).count())
        .sum()
}

/// A census file's source with its comment lines blanked.
fn census_source(file: &str) -> String {
    strip_comment_lines(
        &std::fs::read_to_string(crates_dir().join(file))
            .unwrap_or_else(|_| panic!("census names a file that isn't there: {file}")),
    )
}

/// Every front-door site is reviewed.
///
/// Failing here means a surface was added that reads a request through the
/// gate without anyone deciding how many entry points it checks the origin for
/// or whether the credential's scope applies. Add a [`CensusEntry`] — and if
/// the answer is "exempt", write the reason, because that reason is the
/// artifact this test exists to produce.
#[test]
fn every_gate_site_is_reviewed() {
    let discovered = discover_gate_sites();
    let reviewed: BTreeSet<String> = CENSUS
        .iter()
        .map(|e| e.file.to_owned())
        .chain(NON_SURFACE_SITES.iter().map(|s| (*s).to_owned()))
        .collect();

    let unreviewed: Vec<&String> = discovered.difference(&reviewed).collect();
    assert!(
        unreviewed.is_empty(),
        "unreviewed front-door sites — each must say where its origin check is and \
         whether the token scope applies, and why (see this test's module docs): \
         {unreviewed:#?}",
    );

    let vanished: Vec<&String> = reviewed.difference(&discovered).collect();
    assert!(
        vanished.is_empty(),
        "census names sites that no longer read a request through the gate — a stale \
         entry makes the census read as covering more than it does: {vanished:#?}",
    );
}

/// **The credential walk is reached only through the gate.**
///
/// `resolve_auth_from_headers` and `build_public_request_context` are
/// `pub(crate)`, so no other crate can call them; this pins the same inside
/// `fuz_auth`, where visibility does not reach. A route that called the walk
/// directly would hold no allowlist, so nothing would put an origin check
/// beside its credential read.
#[test]
fn the_credential_walk_is_reached_only_through_the_gate() {
    let callers = discover_rs_files(|text| WALK_CALLS.iter().any(|call| text.contains(call)));
    let callers: Vec<&str> = callers
        .iter()
        .map(String::as_str)
        // this census names the walk's entry points in its scan strings
        .filter(|file| *file != "fuz_auth/tests/token_scope_surface_census.rs")
        .collect();
    assert_eq!(callers, WALK_SITES);
}

/// **Every entry point checks the origin through the gate.**
///
/// The count is exact — one origin call per entry point a file serves — so a
/// handler that drops its check fails here even beside a sibling that keeps
/// one, the case a presence check would miss. A site that checks in its
/// caller names the caller, which must itself check; only the walk checks
/// nowhere, since every route to it passes through a gate held by a checking
/// caller.
#[test]
fn every_entry_point_checks_the_origin_through_the_gate() {
    for entry in CENSUS {
        let count = origin_call_count(&census_source(entry.file));
        match entry.origin {
            OriginCheck::InFile(expected) => {
                assert!(
                    expected > 0,
                    "{}: an in-file check counts at least one",
                    entry.file
                );
                assert_eq!(
                    count, expected,
                    "{} makes {count} origin checks through the gate, the census says \
                     {expected} — an entry point gained or lost its check",
                    entry.file,
                );
            }
            OriginCheck::ByCaller(caller) => {
                assert_eq!(
                    count, 0,
                    "{}: checks in its caller, not in-file",
                    entry.file
                );
                let checks_in_caller = CENSUS.iter().any(|e| {
                    e.file == caller && matches!(e.origin, OriginCheck::InFile(n) if n > 0)
                });
                assert!(
                    checks_in_caller,
                    "{}: its caller {caller} must be a census site that checks in-file",
                    entry.file,
                );
                assert!(
                    census_source(caller).contains(&format!(
                        "{}::",
                        Path::new(entry.file)
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            .expect("a file stem")
                    )),
                    "{}: {caller} no longer calls into it",
                    entry.file,
                );
            }
            OriginCheck::Walk => {
                assert!(
                    WALK_SITES.contains(&entry.file),
                    "{}: only the walk itself checks no origin",
                    entry.file,
                );
                assert_eq!(count, 0, "{}: the walk makes no origin check", entry.file);
            }
        }
    }
}

/// A site declared as consulting the scope still contains the consult.
///
/// `consults_scope` on its own is a claim the census makes about code it never
/// reads: delete the gate out of `fuz_db_admin/src/route_auth.rs` and the file
/// still resolves a credential, still appears in the census, still reads
/// `true` — every other assertion in this suite stays green while the widest
/// surface in the spine goes ungated. Reconciling the flag against the file is
/// what closes that.
///
/// Brittle to reformatting, on purpose and in the same spirit as the walk
/// above: a marker that stops matching is either a gate that moved — re-pin it,
/// having looked at it — or a gate that left.
///
/// Reads through [`strip_comment_lines`], so commenting a gate out reads the
/// same as deleting it — as does the TS twin's own source pin.
#[test]
fn every_scope_consulting_site_still_contains_its_gate() {
    for entry in CENSUS {
        assert_eq!(
            entry.consults_scope,
            !entry.markers.is_empty(),
            "{}: a scope-consulting site names the source its gate is made of, an exempt \
             one names none",
            entry.file,
        );
        let text = census_source(entry.file);
        for marker in entry.markers {
            assert!(
                text.contains(marker),
                "{} no longer contains its pinned scope gate `{marker}` — if the gate moved, \
                 re-pin it; if it left, the surface is ungated",
                entry.file,
            );
        }
        // The reverse staleness: an exemption whose file quietly grew a gate is
        // a reason that no longer describes the code it excuses.
        assert!(
            entry.consults_scope || !text.contains("admits_non_rpc_surface("),
            "{} is listed exempt but now consults the scope — its stated reason is stale",
            entry.file,
        );
    }
}

/// Every census entry carries a reason, in both directions.
///
/// An exemption without an argument is indistinguishable from an oversight;
/// this is what keeps the exempt list from becoming a place to park things.
#[test]
fn every_census_entry_states_its_reasoning() {
    for entry in CENSUS {
        assert!(
            entry.reason.len() > 20,
            "{} needs a real reason, not a placeholder",
            entry.file,
        );
    }
}

/// The scope-consulting set is exactly the non-RPC surfaces, the two RPC
/// transports, and the pure-public resolver — pinned as an exact list so
/// *narrowing* the census (dropping a site to the exempt list, or out of it)
/// fails here too, not just widening it.
///
/// Deleting the gate itself while leaving the row is the other half, and it is
/// [`every_scope_consulting_site_still_contains_its_gate`] that catches it.
#[test]
fn the_scope_consulting_set_is_the_expected_one() {
    let mut consulting: Vec<&str> = CENSUS
        .iter()
        .filter(|e| e.consults_scope)
        .map(|e| e.file)
        .collect();
    consulting.sort_unstable();
    assert_eq!(
        consulting,
        [
            "fuz_actions/src/register_action_ws.rs",
            "fuz_actions/src/rpc_dispatch.rs",
            "fuz_auth/src/account_status.rs",
            "fuz_auth/src/resolve.rs",
            "fuz_db_admin/src/route_auth.rs",
            "fuz_fact_serving/src/serve.rs",
            "fuz_realtime/src/audit_stream.rs",
        ],
    );
}

/// Files whose own text names the denial helper without calling it for a
/// surface: its definition (plus the `TokenSurface::ALL` loop that exercises
/// every shape) and this census, which quotes the call in the scan below.
/// Each entry must still name the helper — a stale one would silently exempt
/// any denial later added to its file.
const NON_DENIAL_SITES: &[&str] = &[
    "fuz_auth/src/route_response.rs",
    "fuz_auth/tests/token_scope_surface_census.rs",
];

/// **The spine names its surfaces through the enum.**
///
/// `token_scope_surface_denied_response` takes a capability *string* so a
/// consumer crate can name a surface [`fuz_auth::TokenSurface`] has no variant
/// for. That deliberately stops binding the identifier — the name decides
/// nothing, rule 3 is all-or-nothing — and the cost lands here: inside this
/// workspace, `TokenSurface::WsUpgrde.capability()` does not compile, while
/// `"surface:ws_upgrde"` compiles and ships a denial naming a surface that does
/// not exist. Nothing else would catch it; the census checks that a gate is
/// *present*, never what it calls the thing it refused.
///
/// So the spine keeps by assertion the rule a string parameter cannot give
/// it: a surface capability comes from the enum, whose `ALL` the exhaustive
/// review above pins. The check stops exactly where the string is for — at
/// the workspace boundary, since a consumer's own constant is the case the
/// string argument exists to serve.
///
/// Twin of `fuz_app`'s `the spine declares only surfaces it mounts`, which scans
/// its `'surface:<name>'` literals for the same reason.
#[test]
fn the_spine_names_its_surfaces_through_the_enum() {
    const CALL: &str = "token_scope_surface_denied_response(";

    let root = crates_dir();
    let discovered = discover_rs_files(|text| text.contains(CALL));
    let stale: Vec<&&str> = NON_DENIAL_SITES
        .iter()
        .filter(|site| !discovered.contains(**site))
        .collect();
    assert!(
        stale.is_empty(),
        "NON_DENIAL_SITES exempts files that no longer name the denial helper — a stale \
         entry would exempt a denial added there later: {stale:#?}",
    );
    let mut checked = 0_usize;
    for file in discovered {
        if NON_DENIAL_SITES.contains(&file.as_str()) {
            continue;
        }
        let text =
            strip_comment_lines(&std::fs::read_to_string(root.join(&file)).expect("read a file"));
        for (offset, _) in text.match_indices(CALL) {
            // The argument expression ends at the statement's `;`.
            let call = text[offset..].split(';').next().unwrap_or_default();
            assert!(
                call.contains("TokenSurface::"),
                "{file} denies with a hand-spelled surface capability — pass \
                 `TokenSurface::X.capability()` so the name comes from the enum: {call}",
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, 4,
        "expected the spine's four non-RPC surface denials — a vanished call site is a \
         surface that stopped denying, not a scan that has less to do",
    );
}

/// The stripper drops prose and keeps code — including code that only *looks*
/// like a comment opener.
///
/// Pinned because the failure it exists to prevent is silent in the worst
/// direction. A `/* … */`-aware stripper ran a route-glob string literal to the
/// end of its file, and a real gate site left the discovered set with nothing to
/// show for it — the census cannot review what it cannot see.
#[test]
fn the_stripper_drops_prose_and_keeps_code() {
    let stripped = strip_comment_lines(concat!(
        "/// a doc comment naming require_auth(\n",
        "    // a leading note naming require_auth(\n",
        "    let msg = \"boot-only mode (no /api/*)\";\n",
        "    require_auth(&headers); // a trailing note\n",
    ));
    assert_eq!(
        stripped.matches("require_auth(").count(),
        1,
        "prose about a marker must not read as the marker, but the call must survive",
    );
    assert!(
        stripped.contains("no /api/*"),
        "a route-glob literal must survive intact — reading its `/*` as a comment \
         opener is what silently swallowed a whole file",
    );
}
