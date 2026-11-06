//! Account row shapes.

/// Row from the `account` table — fields needed for the request context.
#[derive(Debug, Clone)]
pub struct AccountRow {
    pub id: uuid::Uuid,
    pub username: String,
}

/// Account fields needed for `account_verify` / `SessionAccountJson`.
///
/// Mirrors `fuz_app`'s `to_session_account()` output. The full account
/// row carries audit/password fields the verify response must not leak.
#[derive(Debug, Clone)]
pub struct AccountSummaryRow {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: String,
}

/// Account row with password hash, for login + password change paths.
///
/// `Debug` redacts the hash — an argon2 hash is an offline guessing target.
#[derive(Clone)]
pub struct AccountWithPasswordHash {
    pub id: uuid::Uuid,
    pub username: String,
    pub password_hash: String,
}

impl std::fmt::Debug for AccountWithPasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountWithPasswordHash")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_with_password_hash_debug_redacts_the_hash() {
        let account = AccountWithPasswordHash {
            id: uuid::Uuid::nil(),
            username: "hash_holder".to_owned(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaC1Ld3o5".to_owned(),
        };
        let rendered = format!("{account:?}");
        assert!(!rendered.contains("aGFzaC1Ld3o5"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("hash_holder"), "{rendered}");
    }
}
