//! Test-mode Argon2id hasher implementing [`fuz_auth::PasswordHasher`].
//!
//! Parameters are the RFC 9106 floor (`m_cost: 8 KiB, t_cost: 1,
//! p_cost: 1`). Cannot go lower: argon2 enforces `m_cost >= 8 * p_cost`
//! and `p_cost >= 1`. Per-call cost drops from production's ~30-50 ms
//! to ~1-5 ms, which is the whole reason the test binary exists.
//!
//! The cross-verify property — a hash minted here verifies with
//! [`fuz_auth::Argon2idHasher`] and vice versa — is the load-bearing
//! claim of the test-binary pattern. argon2 PHC strings encode params,
//! and `Argon2::default().verify_password` reads the params off the
//! parsed hash rather than from the `Argon2` instance, so the property
//! holds. Codified by `tests/cross_verify.rs`.

use argon2::password_hash::{
    PasswordHash, PasswordHasher as ArgonHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use futures::future::{BoxFuture, FutureExt};

use fuz_auth::{HashedPassword, PasswordHashError, PasswordHasher};

/// Argon2id parameters: RFC 9106 floor. `m_cost` in KiB.
const TEST_M_COST: u32 = 8;
const TEST_T_COST: u32 = 1;
const TEST_P_COST: u32 = 1;

/// Dummy argon2id PHC string with **test params** for
/// enumeration-prevention timing equalization on the login-miss path.
///
/// Same shape as `fuz_auth::password_argon2::DUMMY_HASH`: a parseable
/// PHC string with a zero salt and zero hash bytes. Not a real argon2
/// output — the verifier reads the params off the string, runs argon2
/// against the input password, and constant-time compares the result
/// to the zero bytes. The comparison always fails (effectively no
/// input maps to a zero hash), but the call pays the full argon2 cost,
/// which is the whole point.
///
/// Test params (`m=8,t=1,p=1`) drop the cost to ~1-5 ms vs production's
/// ~30-50 ms, matching the cost of real test-mode hashes minted by
/// [`TestingArgon2idHasher::hash`]. Production fidelity for
/// login-miss timing is deliberately lost inside the test binary.
pub const TESTING_DUMMY_HASH: &str =
    "$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Construct an [`Argon2`] configured with the test params.
fn testing_argon2() -> Result<Argon2<'static>, PasswordHashError> {
    let params = Params::new(TEST_M_COST, TEST_T_COST, TEST_P_COST, None)
        .map_err(PasswordHashError::Params)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Test-only Argon2id hasher with weakened parameters
/// (`m=8 KiB, t=1, p=1`).
///
/// **NEVER WIRE INTO A PRODUCTION BINARY.** Production binary crates
/// don't list `fuz_testing` as a dep, making this symbol unreachable
/// in their build graph — that's the load-bearing safety mechanism.
/// The naming (`Testing*` prefix, not infix or suffix, not `Fast*`)
/// is deliberately high-friction at every use site: the
/// safety-critical word must be the first thing readers see.
///
/// Construction emits one `WARN: test-mode argon2 hasher active` log
/// line per process via [`std::sync::Once`] so log scraping in CI can
/// alert on accidental shipping to production deployments.
///
/// Cross-verify property: hashes mint+verify across this hasher and
/// [`fuz_auth::Argon2idHasher`] because argon2 PHC strings encode
/// params and `Argon2::default().verify_password` reads them off the
/// parsed hash. Codified by `tests/cross_verify.rs`.
#[derive(Debug, Clone, Default)]
pub struct TestingArgon2idHasher;

impl TestingArgon2idHasher {
    /// Construct a test-mode hasher.
    ///
    /// Logs a single `WARN` line on first construction in the process.
    #[must_use]
    pub fn new() -> Self {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                m_cost = TEST_M_COST,
                t_cost = TEST_T_COST,
                p_cost = TEST_P_COST,
                "test-mode argon2 hasher active — fuz_testing must NEVER link from a production binary",
            );
        });
        Self
    }
}

impl PasswordHasher for TestingArgon2idHasher {
    fn hash(
        &self,
        password: String,
    ) -> BoxFuture<'static, Result<HashedPassword, PasswordHashError>> {
        async move {
            tokio::task::spawn_blocking(move || {
                let mut salt_bytes = [0u8; 16];
                getrandom::fill(&mut salt_bytes).map_err(PasswordHashError::Salt)?;
                let salt =
                    SaltString::encode_b64(&salt_bytes).map_err(PasswordHashError::Argon2)?;
                let argon2 = testing_argon2()?;
                let hash = argon2
                    .hash_password(password.as_bytes(), &salt)
                    .map_err(PasswordHashError::Argon2)?;
                Ok(HashedPassword::new(hash.to_string()))
            })
            .await
            .map_err(PasswordHashError::Task)?
        }
        .boxed()
    }

    fn verify(&self, password: String, hash: String) -> BoxFuture<'static, bool> {
        async move {
            tokio::task::spawn_blocking(move || {
                let Ok(parsed) = PasswordHash::new(&hash) else {
                    return false;
                };
                // `Argon2::default()` here is fine: `verify_password`
                // reads the cost parameters off the parsed PHC string,
                // not from the `Argon2` instance — that's exactly why
                // the cross-verify property holds.
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            })
            .await
            .unwrap_or(false)
        }
        .boxed()
    }

    fn dummy_hash(&self) -> &'static str {
        TESTING_DUMMY_HASH
    }
}
