//! Bootstrap — one-shot first-admin account creation.
//!
//! Mirrors `fuz_app`'s `bootstrap_account.ts` + `bootstrap_routes.ts`.
//! Reads a one-shot token from disk, creates account + keeper + admin
//! grants atomically, sets the session cookie, deletes the token file.
//!
//! ## `BootstrapOptions` callback
//!
//! The "set `daemon_token_state.keeper_account_id`" side effect is
//! consumer-specific — consumers without daemon-token state (headless
//! CLIs, future no-daemon-token deployments) skip it. The
//! [`BootstrapOptions::on_keeper_resolved`] callback lets consumers
//! plug in their daemon-token wiring without `fuz_auth` depending on
//! `SharedDaemonTokenState` directly; the canonical wiring is
//! [`crate::DaemonTokenKeeperResolved`]. Consumers without daemon-token
//! state leave it `None`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use deadpool_postgres::Pool;
use fuz_db::commit_checked;
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::account_queries::query_create_account;
use crate::account_schema::AccountRow;
use crate::actor_queries::{query_create_actor, query_create_role_grant};
use crate::actor_schema::ActorRow;
use crate::audit_emitter::{AuditEmitter, AuditLogInput};
use crate::audit_event_type::AuditEventType;
use crate::bootstrap_keeper_resolved::BootstrapKeeperResolved;
use crate::bootstrap_token_store::{BootstrapTokenStore, read_bootstrap_token_file};
use crate::error::{BootstrapError, BootstrapErrorKind};
use crate::password_hasher::PasswordHasher;
use crate::role::{ROLE_ADMIN, ROLE_KEEPER};
use crate::session_queries::create_capped_session;

// -- Input ----------------------------------------------------------------

/// `POST /bootstrap` body.
///
/// `deny_unknown_fields` mirrors the TS `BootstrapInput`, a strict
/// `fuz_schema` `object` (the canonical twin): an extra body key on this — the
/// highest-privilege, first-admin endpoint — fails deserialization rather than
/// being silently ignored, matching `SignupInput` / `LoginInput` and closing
/// the mass-assignment surface on future fields.
///
/// `Debug` redacts the token and the password.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BootstrapInput {
    pub token: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for BootstrapInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapInput")
            .field("token", &"<redacted>")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Strip exactly one trailing `\n` from operator-written token bytes before the
/// constant-time compare.
///
/// NOT `trim()`: trimming is length-dependent (variable work) and would
/// undermine the `ct_eq` it precedes, and it would widen the set of accepted
/// token bytes. Tolerates the single trailing newline a POSIX editor appends;
/// anything else (a second newline, a trailing space, a leading newline) is
/// preserved and therefore fails the comparison — operators must write the
/// token bytes exactly.
fn strip_one_trailing_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

/// The fewest bytes a bootstrap token holds, counted after its one optional
/// trailing newline.
///
/// A shorter file reads as unreadable: an empty or `"\n"` file would
/// otherwise leave bootstrap advertised as open while nothing can ever match
/// it, and a short token is guessable. Every generator writes more (32 random
/// bytes as 64 lowercase hex characters); the readers accept any bytes that
/// clear this floor. Twin of `fuz_app`'s `BOOTSTRAP_TOKEN_MIN_BYTES`.
pub const BOOTSTRAP_TOKEN_MIN_BYTES: usize = 32;

/// The longest `token` the body takes, in UTF-16 code units.
///
/// Twin of `fuz_app`'s `BOOTSTRAP_TOKEN_LENGTH_MAX`, a `max_length`, which
/// counts `String.length`: the token file's cap, `fuz_sys`'s
/// `MAX_SECURE_FILE_SIZE` bytes. A token that can match the file is at most
/// that many bytes, and no more code units than bytes, so the bound refuses
/// none that could match. A longer one is a malformed body:
/// [`BootstrapErrorKind::InvalidInput`], refused before the window or the
/// token file is read, with no audit row.
pub const BOOTSTRAP_TOKEN_LENGTH_MAX: usize = 4096;

/// The token a file's bytes hold — less one trailing newline — or `None`
/// (logged as an error) when it is under [`BOOTSTRAP_TOKEN_MIN_BYTES`].
///
/// Shared by [`is_bootstrap_available`] and [`bootstrap_handler`], so the
/// availability check is exactly as strict as the request-time read. Twin of
/// `fuz_app`'s `read_bootstrap_token`.
fn bootstrap_token_from_file(bytes: Vec<u8>) -> Option<Vec<u8>> {
    let token = strip_one_trailing_newline(bytes);
    if token.len() < BOOTSTRAP_TOKEN_MIN_BYTES {
        tracing::error!(
            len = token.len(),
            min = BOOTSTRAP_TOKEN_MIN_BYTES,
            "bootstrap token rejected: shorter than the minimum — regenerate it"
        );
        return None;
    }
    Some(token)
}

/// Return value of [`bootstrap_handler`].
///
/// Carries the raw session token and the created account/actor rows;
/// the HTTP wrapper (`bootstrap_routes.rs`) builds the wire response
/// shape and the `Set-Cookie` header from these. `Debug` redacts the
/// session token.
pub struct BootstrapSuccess {
    /// Signed session cookie value (Set-Cookie header is built by the
    /// HTTP wrapper).
    pub session_token: String,
    pub account: AccountRow,
    pub actor: ActorRow,
}

impl std::fmt::Debug for BootstrapSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapSuccess")
            .field("session_token", &"<redacted>")
            .field("account", &self.account)
            .field("actor", &self.actor)
            .finish()
    }
}

// -- Options --------------------------------------------------------------

/// Capabilities required by [`bootstrap_handler`].
///
/// Carries no rate limiter, and deliberately so — `fuz_app`'s twin
/// (`BootstrapRouteOptions.bootstrap_ip_rate_limiter`) does, which is the one
/// place the two bootstrap surfaces diverge. The token is 32 bytes of CSPRNG
/// compared in constant time, so guessing is not what a limiter would bound;
/// what it would bound is unauthenticated `audit_log` writes, and every leg
/// that could produce those unbounded closes its window instead (see
/// [`bootstrap_handler`]). Bootstrap is also the one auth operation with no
/// retry path — a 429 here refuses first-admin creation on a deployment that
/// has no admin to appeal to.
pub struct BootstrapOptions {
    /// `pool` for the bootstrap transaction.
    pub pool: Pool,
    /// Password hasher (Argon2id in production).
    pub password_hasher: Arc<dyn PasswordHasher>,
    /// Audit emitter. Only the legs reachable while the bootstrap window is
    /// open write a row — refusals outside it are deliberately silent, see
    /// [`bootstrap_handler`].
    pub audit: Arc<AuditEmitter>,
    /// Atomic flag flipped from `true` to `false` once the window closes —
    /// after the first successful bootstrap, or when the token file turns out
    /// to be unreadable and bootstrap therefore can't succeed. Read by
    /// `/api/account/status` so the frontend knows whether to show the
    /// bootstrap UI.
    pub bootstrap_available: Arc<AtomicBool>,
    /// One-shot bootstrap token store. `None` → bootstrap disabled; the
    /// handler answers `already_bootstrapped`, as the twin does with no token
    /// path, and writes no audit row. Production wires
    /// [`crate::FileBootstrapTokenStore`]; tests can supply an
    /// in-memory impl.
    pub token_store: Option<Arc<dyn BootstrapTokenStore>>,
    /// Optional callback fired after the keeper account is created.
    /// Consumers wire daemon-token state here.
    pub on_keeper_resolved: Option<Arc<dyn BootstrapKeeperResolved>>,
}

impl std::fmt::Debug for BootstrapOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapOptions")
            .field("has_token_store", &self.token_store.is_some())
            .field("has_keeper_callback", &self.on_keeper_resolved.is_some())
            .finish_non_exhaustive()
    }
}

// -- Handler --------------------------------------------------------------

/// Resolve whether bootstrap is currently available: the bootstrap
/// token file exists **and** the `bootstrap_lock` row isn't yet marked
/// bootstrapped.
///
/// Consumers call this once at startup to seed the shared
/// `bootstrap_available` flag (returned on `/status` 401 + gating
/// `/bootstrap`). `token_path: None` (no bootstrap token configured)
/// resolves to `false`. Fail-closed: any I/O or DB error resolves to
/// `false` so a transient failure can't accidentally re-open bootstrap.
pub async fn is_bootstrap_available(pool: &Pool, token_path: Option<&str>) -> bool {
    let Some(path) = token_path else {
        return false;
    };
    // Validate with the *same* secure read the handler will perform, not a
    // bare `metadata` existence probe: an availability check laxer than the
    // read it gates reports green at boot and then fails every bootstrap
    // attempt. `read_bootstrap_token_file` logs the specific reason (symlink,
    // group/other-accessible mode, oversize) before we fail closed here.
    let Ok(bytes) = read_bootstrap_token_file(PathBuf::from(path)).await else {
        tracing::info!("bootstrap unavailable: token file missing or not owner-only");
        return false;
    };
    if bootstrap_token_from_file(bytes).is_none() {
        tracing::info!(path = %path, "bootstrap unavailable: token file under the minimum length");
        return false;
    }
    let Ok(client) = pool.get().await else {
        return false;
    };
    let Ok(row) = client
        .query_opt("SELECT bootstrapped FROM bootstrap_lock WHERE id = 1", &[])
        .await
    else {
        return false;
    };
    if let Some(row) = row {
        let bootstrapped: bool = row.get(0);
        if bootstrapped {
            tracing::info!("bootstrap unavailable: already bootstrapped");
            return false;
        }
    }
    tracing::info!(path = %path, "bootstrap token available");
    true
}

/// Run the bootstrap pipeline.
///
/// Transport-agnostic — REST handlers (`bootstrap_routes`) and future
/// CLI tooling share this core. The body is validated first, as on the
/// twin, so a malformed body answers `400` whatever the window's state.
/// Failures *inside the open bootstrap window*
/// emit typed audit rows matching `fuz_app`'s wire shape; refusals outside it
/// are silent, so a permanently-mounted route can't be turned into an
/// unauthenticated `audit_log` write channel.
///
/// # Errors
///
/// Returns [`BootstrapError::Classified`] with a [`BootstrapErrorKind`]
/// discriminant for the failure cases the operator-facing layer maps
/// to HTTP status codes.
pub async fn bootstrap_handler(
    options: &BootstrapOptions,
    client_ip: Option<String>,
    input: BootstrapInput,
) -> Result<BootstrapSuccess, BootstrapError> {
    // The body is validated first, as the twin's route schema (`BootstrapInput`)
    // refuses it before its handler runs: a malformed body answers `400` whether
    // or not the window is open, and costs no audit row. The username is the
    // raw value, validated and then lowercased — a padded name is refused,
    // never trimmed into a legal one.
    let Some(canonical_username) = bootstrap_input_canonical_username(&input) else {
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::InvalidInput,
        });
    };

    // The check below refuses *outside* the open bootstrap window — bootstrap
    // was never configured, or it already completed — and deliberately writes
    // no audit row. The route stays mounted for the life of the process
    // and the origin gate admits any caller sending no `Origin`, so an emit here
    // is an unauthenticated, unbounded `audit_log` write channel: one INSERT per
    // request, forever, from anyone who can reach the host. Nothing is learned
    // from the rows either — they record that a closed door stayed closed.
    //
    // The emits this handler does make (`token_file_missing`, `invalid_token`)
    // fire only while the window is genuinely open, which is the short-lived
    // interval where a failed attempt is forensically interesting — and
    // `token_file_missing` closes the window on its way out, so it fires once
    // rather than once per request. Don't add an emit to this check; a rate
    // limiter is not the fix, since it would bound the channel without closing
    // it.
    //
    // Both cases answer the twin's `403 already_bootstrapped`, which refuses a
    // missing token path and a closed window in one check, so an unconfigured
    // deployment reads exactly as a bootstrapped one.
    let Some(token_store) = options
        .token_store
        .as_ref()
        .filter(|_| options.bootstrap_available.load(Ordering::Relaxed))
    else {
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped,
        });
    };

    // Read raw bytes — trim() is length-dependent (variable work)
    // and would undermine the ct_eq below. Bootstrap token files are
    // operator-written and may contain a trailing newline; we tolerate
    // exactly one trailing `\n` (POSIX convention) before the
    // constant-time comparison runs over the full bytes. Anything else
    // is rejected; operators must write the bytes exactly.
    // A token under the minimum length reads as unreadable, like a missing
    // file — it can never match (empty) or is guessable (short).
    let Some(expected_token) = token_store
        .read_token()
        .await
        .ok()
        .and_then(bootstrap_token_from_file)
    else {
        // Close the window. Bootstrap cannot succeed without a readable token,
        // and `is_bootstrap_available` already reads an unreadable file as
        // closed at boot — so leaving the flag set means the two disagree, and
        // every later request takes this leg and writes another audit row. That
        // is the unbounded unauthenticated write channel the short-circuits
        // above exist to close, reachable here by an operator deleting the
        // token or narrowing its permissions after boot. This emit stays: it is
        // the one that records the transition, and it fires once.
        options.bootstrap_available.store(false, Ordering::Relaxed);
        emit_failure(&options.audit, client_ip.as_deref(), "token_file_missing").await;
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::TokenFileMissing,
        });
    };

    if !bool::from(input.token.as_bytes().ct_eq(&expected_token)) {
        emit_failure(&options.audit, client_ip.as_deref(), "invalid_token").await;
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::InvalidToken,
        });
    }

    let password_hash = options
        .password_hasher
        .hash(input.password)
        .await
        .map_err(BootstrapError::PasswordHash)?;

    let mut client = options.pool.get().await?;

    let tx = client.transaction().await?;

    // Acquire the bootstrap lock atomically.
    let lock_row = tx
        .query_opt(
            "UPDATE bootstrap_lock SET bootstrapped = true
             WHERE id = 1 AND bootstrapped = false RETURNING id",
            &[],
        )
        .await?;
    if lock_row.is_none() {
        // Verify-write race loser — pre-check passed, UPDATE failed. Roll back
        // and flag bootstrap_available false so the early check catches the
        // next caller. No audit row: this is reachable only by a concurrent
        // legitimate attempt during the open window, and folding it into the
        // same silent refusal as the steady-state case is what keeps the
        // post-bootstrap probe channel write-free (see the note above).
        tx.rollback().await.ok();
        options.bootstrap_available.store(false, Ordering::Relaxed);
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped,
        });
    }

    let account = query_create_account(&tx, &canonical_username, password_hash.as_str()).await?;
    let actor = query_create_actor(&tx, &account.id, &canonical_username).await?;
    query_create_role_grant(&tx, &actor.id, ROLE_KEEPER, None, None, None, None).await?;
    query_create_role_grant(&tx, &actor.id, ROLE_ADMIN, None, None, None, None).await?;

    // The account was created three statements above, so the cap evicts
    // nothing. Routed through the shared minter anyway: the cap is a property
    // of session creation, not of the login route.
    let session_token = create_capped_session(&tx, &account.id)
        .await?
        .into_token_for_new_account();

    commit_checked(tx).await.map_err(BootstrapError::Commit)?;

    options.bootstrap_available.store(false, Ordering::Relaxed);

    if let Some(ref cb) = options.on_keeper_resolved {
        cb.on_keeper_resolved(account.id).await;
    }

    // Best-effort: delete the bootstrap token post-commit. The
    // configured location was logged at wiring time, so this log
    // line doesn't need to thread the path through the trait.
    if let Err(e) = token_store.delete_token().await {
        tracing::error!(
            error = %fuz_sys::cli::format_error_chain(&e),
            "CRITICAL: failed to delete bootstrap token"
        );
    }

    let _ = options
        .audit
        .emit(
            AuditLogInput::for_event(AuditEventType::Bootstrap)
                .actor(actor.id)
                .account(account.id)
                .ip(client_ip),
        )
        .await;

    Ok(BootstrapSuccess {
        session_token,
        account,
        actor,
    })
}

/// The first-admin body's shape gate, the twin's `BootstrapInput` bounds: a
/// token of 1 to [`BOOTSTRAP_TOKEN_LENGTH_MAX`] UTF-16 code units, the
/// canonical username under the creation grammar, and the password under the
/// twin's `Password` (12 to 300 units). Lengths count UTF-16 code units the way
/// `String.length` — and so the twin's `max_length` and `bounded_string` —
/// counts them. Returns the canonical username when all three hold.
fn bootstrap_input_canonical_username(input: &BootstrapInput) -> Option<String> {
    let password_ok = (crate::password::PASSWORD_LENGTH_MIN..=crate::password::PASSWORD_LENGTH_MAX)
        .contains(&crate::password_length(&input.password));
    let token_ok = (1..=BOOTSTRAP_TOKEN_LENGTH_MAX).contains(&input.token.encode_utf16().count());
    if !token_ok || !password_ok {
        return None;
    }
    crate::primitive_schemas::canonical_username_for_creation(&input.username)
}

async fn emit_failure(audit: &Arc<AuditEmitter>, client_ip: Option<&str>, error: &str) {
    let _ = audit
        .emit(
            AuditLogInput::for_event(AuditEventType::Bootstrap)
                .failure()
                .ip(client_ip.map(str::to_owned))
                .metadata(json!({"error": error})),
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_input_debug_redacts_token_and_password() {
        let input = BootstrapInput {
            token: "bootstrap-token-Hd3kR8".to_owned(),
            username: "first_admin".to_owned(),
            password: "bootstrap-password-Lm2tW5".to_owned(),
        };
        let rendered = format!("{input:?}");
        assert!(!rendered.contains("bootstrap-token-Hd3kR8"), "{rendered}");
        assert!(
            !rendered.contains("bootstrap-password-Lm2tW5"),
            "{rendered}"
        );
        assert!(rendered.contains("first_admin"), "{rendered}");
    }

    #[test]
    fn bootstrap_success_debug_redacts_the_session_token() {
        let account_id = uuid::Uuid::nil();
        let success = BootstrapSuccess {
            session_token: "bootstrap-session-Qx6yN1".to_owned(),
            account: AccountRow {
                id: account_id,
                username: "first_admin".to_owned(),
            },
            actor: ActorRow {
                id: account_id,
                account_id,
                name: "first_admin".to_owned(),
            },
        };
        let rendered = format!("{success:?}");
        assert!(!rendered.contains("bootstrap-session-Qx6yN1"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("first_admin"), "{rendered}");
    }

    #[test]
    fn bootstrap_input_rejects_unknown_field() {
        // `deny_unknown_fields` converges to the canonical TS strict `object`:
        // an extra key on the first-admin body must fail deserialization, not be
        // silently ignored. The DB suite builds `BootstrapInput` structurally
        // (bypassing serde), so this is the only guard on the attribute.
        assert!(
            serde_json::from_str::<BootstrapInput>(
                r#"{"token":"t","username":"a","password":"p"}"#
            )
            .is_ok(),
            "a well-formed body must deserialize"
        );
        assert!(
            serde_json::from_str::<BootstrapInput>(
                r#"{"token":"t","username":"a","password":"p","is_admin":true}"#
            )
            .is_err(),
            "an unknown field must fail deserialization (mass-assignment guard)"
        );
    }

    /// The first-admin body's password bound is the twin's `Password`
    /// (`.min(12).max(300)`), counted in UTF-16 code units. The two rows a
    /// byte count got backwards: eight `\u{00FC}` is 16 bytes, so a byte
    /// count admitted a password the twin refuses, and 151 of them is 302
    /// bytes, so a byte count refused one the twin admits.
    #[test]
    fn bootstrap_password_is_bounded_in_the_twins_units() {
        let admits = |password: &str| input_admits("t", "keeper", password);
        let eight = "\u{00FC}".repeat(8);
        assert_eq!(eight.len(), 16, "bytes");
        assert!(!admits(&eight), "8 code units is under the floor");
        let long = "\u{00FC}".repeat(151);
        assert_eq!(long.len(), 302, "bytes");
        assert!(admits(&long), "151 code units is under the ceiling");
    }

    /// The token's bound is the twin's `max_length(BOOTSTRAP_TOKEN_LENGTH_MAX)`,
    /// counted in UTF-16 code units: a two-byte token at the cap is twice the
    /// cap in bytes and admitted, and an astral one is half the cap in scalar
    /// values and refused one character past it.
    #[test]
    fn bootstrap_token_is_bounded_in_the_twins_units() {
        let admits = |token: &str| input_admits(token, "keeper", "a-long-enough-password");
        let max = BOOTSTRAP_TOKEN_LENGTH_MAX;
        assert!(admits(&"x".repeat(max)), "ASCII at the cap");
        assert!(!admits(&"x".repeat(max + 1)), "ASCII past the cap");
        let two_byte = "\u{00E9}".repeat(max);
        assert_eq!(two_byte.len(), max * 2, "bytes");
        assert!(
            admits(&two_byte),
            "a two-byte token at the cap in code units"
        );
        assert!(
            !admits(&"\u{00E9}".repeat(max + 1)),
            "two-byte past the cap"
        );
        let astral = "\u{1F600}".repeat(max / 2);
        assert_eq!(astral.chars().count(), max / 2, "scalar values");
        assert!(admits(&astral), "an astral token at the cap in code units");
        assert!(!admits(&format!("{astral}a")), "one unit past the cap");
        assert!(
            !admits(&"\u{1F600}".repeat(max / 2 + 1)),
            "one astral character, two units, past the cap"
        );
    }

    fn input_admits(token: &str, username: &str, password: &str) -> bool {
        bootstrap_input_canonical_username(&BootstrapInput {
            token: token.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
        })
        .is_some()
    }

    /// The username is the twin's `Username`: validated raw, then lowercased.
    /// Padding is refused, not trimmed away, and the token must be non-empty.
    #[test]
    fn bootstrap_username_is_validated_raw() {
        let password = "a-long-enough-password";
        let canonical = |username: &str| {
            bootstrap_input_canonical_username(&BootstrapInput {
                token: "t".to_owned(),
                username: username.to_owned(),
                password: password.to_owned(),
            })
        };
        assert_eq!(canonical("Keeper").as_deref(), Some("keeper"));
        for padded in [
            " keeper",
            "keeper ",
            "\tkeeper",
            "keeper\n",
            "\u{85}keeper",
            "\u{FEFF}keeper",
        ] {
            assert_eq!(canonical(padded), None, "{padded:?}");
        }
        assert!(
            !input_admits("", "keeper", password),
            "an empty token is refused"
        );
    }

    #[test]
    fn strip_one_trailing_newline_strips_exactly_one() {
        // Tolerate the single POSIX trailing newline; reject everything else so
        // the byte set the ct_eq accepts stays exact.
        assert_eq!(strip_one_trailing_newline(b"token\n".to_vec()), b"token");
        // Exactly one — a second newline survives (and so fails the compare).
        assert_eq!(
            strip_one_trailing_newline(b"token\n\n".to_vec()),
            b"token\n"
        );
        // No trailing newline: unchanged.
        assert_eq!(strip_one_trailing_newline(b"token".to_vec()), b"token");
        // A trailing space is NOT a newline — preserved (must fail the compare).
        assert_eq!(strip_one_trailing_newline(b"token ".to_vec()), b"token ");
        // CRLF: only the LF goes, so a token file written with Windows line
        // endings fails the compare rather than matching.
        assert_eq!(
            strip_one_trailing_newline(b"token\r\n".to_vec()),
            b"token\r"
        );
        assert_eq!(
            strip_one_trailing_newline(b"token  \n".to_vec()),
            b"token  "
        );
        // A leading newline is not trailing — preserved.
        assert_eq!(strip_one_trailing_newline(b"\ntoken".to_vec()), b"\ntoken");
        // Empty stays empty (no panic on `last()`).
        assert_eq!(strip_one_trailing_newline(Vec::new()), b"");
    }
}
