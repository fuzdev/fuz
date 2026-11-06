//! Cross-verify: hashes mint with one [`PasswordHasher`] and verify
//! with the other.
//!
//! Documents the PHC params-encoding property the test-binary pattern
//! depends on: argon2 stores cost parameters inside the hash itself,
//! so `Argon2::default().verify_password` reads them off the parsed
//! hash regardless of which hasher minted it. If this test ever fails,
//! someone "optimized" one of the hashers into a divergent output
//! format and broke the test-binary pattern's load-bearing assumption.

use argon2::password_hash::PasswordHash;

use fuz_auth::{Argon2idHasher, PasswordHasher};
use fuz_testing::{TestingArgon2idHasher, password_argon2::TESTING_DUMMY_HASH};

const PASSWORD: &str = "correct-horse-battery-staple";
const WRONG_PASSWORD: &str = "tr0ub4dor&3";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn testing_mints_prod_verifies() {
    let testing = TestingArgon2idHasher::new();
    let prod = Argon2idHasher::new();

    let hash = testing
        .hash(PASSWORD.to_owned())
        .await
        .expect("testing hasher mints");

    assert!(
        prod.verify(PASSWORD.to_owned(), hash.as_str().to_owned())
            .await,
        "production hasher must verify a hash minted by the testing hasher",
    );
    assert!(
        !prod
            .verify(WRONG_PASSWORD.to_owned(), hash.as_str().to_owned())
            .await,
        "production hasher must reject a wrong password against the testing-minted hash",
    );
}

/// An unparseable stored hash verifies `false`, never errors — the contract
/// `fuz_testing::seed`'s `'x'` fixture literal leans on to keep seeded
/// accounts un-loginable. Pins the parse-error leg on both hashers (the
/// dummy-hash tests only exercise the parseable-mismatch leg).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unparseable_stored_hash_verifies_false_on_both_hashers() {
    let testing = TestingArgon2idHasher::new();
    let prod = Argon2idHasher::new();
    assert!(!testing.verify(PASSWORD.to_owned(), "x".to_owned()).await);
    assert!(!prod.verify(PASSWORD.to_owned(), "x".to_owned()).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prod_mints_testing_verifies() {
    let testing = TestingArgon2idHasher::new();
    let prod = Argon2idHasher::new();

    let hash = prod
        .hash(PASSWORD.to_owned())
        .await
        .expect("production hasher mints");

    assert!(
        testing
            .verify(PASSWORD.to_owned(), hash.as_str().to_owned())
            .await,
        "testing hasher must verify a hash minted by the production hasher",
    );
    assert!(
        !testing
            .verify(WRONG_PASSWORD.to_owned(), hash.as_str().to_owned())
            .await,
        "testing hasher must reject a wrong password against the production-minted hash",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn testing_self_round_trip() {
    let testing = TestingArgon2idHasher::new();

    let hash = testing
        .hash(PASSWORD.to_owned())
        .await
        .expect("testing hasher mints");

    assert!(
        testing
            .verify(PASSWORD.to_owned(), hash.as_str().to_owned())
            .await,
        "testing hasher must verify its own hashes",
    );
}

#[test]
fn dummy_hash_parses_as_a_valid_argon2id_phc_string() {
    // The testing dummy hash is the timing-equalization target on the
    // login-miss path. Both `TestingArgon2idHasher::verify` and
    // production `Argon2idHasher::verify` early-return `false` on
    // parse failure — without running the argon2 work that
    // timing-equalization depends on. A purely-behavioral test
    // (`verify(any_password, dummy) → false`) can't distinguish
    // "argon2 ran and rejected" from "parse failed and short-circuited",
    // so we assert PHC parsing succeeds directly here. If the argon2
    // crate ever tightens its PHC parser to reject our zero-bytes
    // shape, this test fails loud rather than the login-miss path
    // silently dropping its timing-equalization cost.
    PasswordHash::new(TESTING_DUMMY_HASH)
        .expect("TESTING_DUMMY_HASH must parse as a valid argon2id PHC string");

    // Belt-and-suspenders: also assert dummy_hash() returns the constant.
    let testing = TestingArgon2idHasher::new();
    assert_eq!(testing.dummy_hash(), TESTING_DUMMY_HASH);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_against_dummy_hash_runs_argon2_and_returns_false() {
    // Companion to the parse test above: assert the verify path
    // completes (returns false) rather than producing an unrecoverable
    // error. Doesn't distinguish short-circuit vs argon2-ran; the
    // parse test does. Both together cover the contract.
    let testing = TestingArgon2idHasher::new();
    let prod = Argon2idHasher::new();
    let dummy = testing.dummy_hash().to_owned();

    assert!(
        !prod.verify(PASSWORD.to_owned(), dummy.clone()).await,
        "production verifier must reject a non-empty password against the testing dummy hash",
    );
    assert!(
        !testing.verify(PASSWORD.to_owned(), dummy).await,
        "testing verifier must reject a non-empty password against its own dummy hash",
    );
}
