//! `PasswordHasher` capability trait.
//!
//! Cold-path capability (Argon2id is ~50 ms per call by design — vtable
//! cost is invisible). The trait exists so unit tests can swap in a
//! fast no-op hasher; production binds [`crate::password_argon2::Argon2idHasher`].
//!
//! Held as `Arc<dyn PasswordHasher>` on the consumer's auth state.

/// Hashed password bytes. Newtype so call sites can't confuse a hash
/// with a raw password. `Debug` redacts it — an argon2 hash is an offline
/// guessing target.
#[derive(Clone)]
pub struct HashedPassword(String);

impl std::fmt::Debug for HashedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HashedPassword")
            .field(&"<redacted>")
            .finish()
    }
}

impl HashedPassword {
    #[must_use]
    pub const fn new(hash: String) -> Self {
        Self(hash)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Password hashing capability.
///
/// Implementations must run on a blocking-friendly executor — Argon2id
/// is CPU-bound (~50 ms / call) and would block the async runtime if
/// invoked synchronously on the request thread. The contract is:
/// implementations spawn onto `tokio::task::spawn_blocking` (or
/// equivalent) internally before doing CPU work.
///
/// **Object-safe** — consumed as `Arc<dyn PasswordHasher>`. Methods
/// return `BoxFuture` because RPITIT doesn't yet support `dyn` on
/// stable Rust; the boxing cost is invisible against the ~50ms Argon2
/// hash.
pub trait PasswordHasher: Send + Sync {
    /// Hash a raw password. Boxed future for `dyn`-trait compatibility.
    fn hash(
        &self,
        password: String,
    ) -> futures::future::BoxFuture<'static, Result<HashedPassword, String>>;

    /// Verify a raw password against a stored hash. Boxed future for
    /// `dyn`-trait compatibility.
    ///
    /// Returns `true` on match, `false` on any failure (parse error,
    /// wrong password, executor panic).
    fn verify(&self, password: String, hash: String) -> futures::future::BoxFuture<'static, bool>;

    /// A pre-computed dummy hash used for timing-equalization on the
    /// login enumeration-prevention path (matches `fuz_app`'s
    /// `DUMMY_HASH`).
    fn dummy_hash(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_password_debug_redacts_the_hash() {
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaC1Ld3o5";
        let rendered = format!("{:?}", HashedPassword::new(hash.to_owned()));
        assert!(!rendered.contains("aGFzaC1Ld3o5"), "{rendered}");
        assert_eq!(rendered, r#"HashedPassword("<redacted>")"#);
    }
}
