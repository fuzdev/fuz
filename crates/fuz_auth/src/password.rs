//! Password length constants + newtype wrappers.
//!
//! `Password` represents a password value the spine has accepted (e.g.
//! when constructing a new account); `PasswordProvided` represents a
//! value the caller submitted (e.g. on login) that has not been
//! validated. Both are newtypes around `String` so the type system
//! distinguishes intent.

/// Minimum length of a password the spine accepts at a creation site
/// (signup, bootstrap, password change). Mirrors `fuz_app`'s
/// `PASSWORD_LENGTH_MIN`, the `.min()` on its `Password` schema.
pub const PASSWORD_LENGTH_MIN: usize = 12;

/// Minimum length of a *submitted* password (login, verification).
///
/// Mirrors the `.min(1)` on `fuz_app`'s `PasswordProvided` schema, which is
/// deliberately looser than [`PASSWORD_LENGTH_MIN`]: an account minted under
/// an earlier policy must still be able to authenticate, so the submit sites
/// bound only emptiness. Rejecting a short submission here would refuse a
/// valid credential rather than let the hash comparison answer.
pub const PASSWORD_PROVIDED_LENGTH_MIN: usize = 1;

/// Maximum password length.
///
/// Mirrors `fuz_app`'s `PASSWORD_LENGTH_MAX`. Bounds Argon2's input, so a
/// request can't hand the hasher an arbitrarily large password. Comfortably
/// above NIST 800-63B's ≥64 recommendation.
pub const PASSWORD_LENGTH_MAX: usize = 300;

/// Length of `value` in the unit the twin's `bounded_string` bounds measure.
///
/// `String.length` — and so the twin's `bounded_string` bounds — counts UTF-16
/// code units, while `str::len` counts UTF-8 bytes. The two disagree on every
/// non-ASCII password: eight `\u{00FC}` is 16 bytes and 8 units, so a byte
/// count admits a password the twin refuses, and 151 of them is 302 bytes and
/// 151 units, so a byte count refuses one the twin admits.
#[must_use]
pub fn password_length(value: &str) -> usize {
    value.encode_utf16().count()
}

/// Length-validation failure shape.
///
/// Carries only the failing length — **never** the raw password —
/// because a logged `Err` value must not leak credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordLengthError {
    #[error("password too short: {len} < {min}")]
    TooShort { len: usize, min: usize },
    #[error("password too long: {len} > {max}")]
    TooLong { len: usize, max: usize },
}

/// A password the spine has minted (e.g. a new account's password as
/// supplied to bootstrap). Newtype over `String`; `Debug` redacts it.
#[derive(Clone)]
pub struct Password(String);

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"<redacted>").finish()
    }
}

impl Password {
    /// Construct after length validation.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordLengthError`] when the length is outside
    /// `[PASSWORD_LENGTH_MIN, PASSWORD_LENGTH_MAX]`. The raw input is
    /// dropped to avoid credential leakage via logged `Err` values.
    pub fn try_new(value: String) -> Result<Self, PasswordLengthError> {
        let len = password_length(&value);
        if len < PASSWORD_LENGTH_MIN {
            return Err(PasswordLengthError::TooShort {
                len,
                min: PASSWORD_LENGTH_MIN,
            });
        }
        if len > PASSWORD_LENGTH_MAX {
            return Err(PasswordLengthError::TooLong {
                len,
                max: PASSWORD_LENGTH_MAX,
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// A password the caller submitted on the wire (login, change password,
/// bootstrap). Length is bounded but the value has not been verified
/// against any stored hash. `Debug` redacts it.
#[derive(Clone)]
pub struct PasswordProvided(String);

impl std::fmt::Debug for PasswordProvided {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PasswordProvided")
            .field(&"<redacted>")
            .finish()
    }
}

impl PasswordProvided {
    /// Construct without length validation.
    ///
    /// Use [`PasswordProvided::try_new`] when the caller-facing length
    /// gates must apply.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// Construct after length validation.
    ///
    /// The bounds are the twin's `PasswordProvided`
    /// (`.min(1).max(PASSWORD_LENGTH_MAX)`), not `Password`'s: a submit site
    /// bounds only emptiness at the bottom, so an account minted under an
    /// earlier policy still authenticates.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordLengthError`] when outside the supported range.
    /// The raw input is dropped to avoid credential leakage.
    pub fn try_new(value: String) -> Result<Self, PasswordLengthError> {
        let len = password_length(&value);
        if len < PASSWORD_PROVIDED_LENGTH_MIN {
            return Err(PasswordLengthError::TooShort {
                len,
                min: PASSWORD_PROVIDED_LENGTH_MIN,
            });
        }
        if len > PASSWORD_LENGTH_MAX {
            return Err(PasswordLengthError::TooLong {
                len,
                max: PASSWORD_LENGTH_MAX,
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PASSWORD_LENGTH_MAX, PASSWORD_LENGTH_MIN, Password, PasswordProvided, password_length,
    };

    /// One `ü` is two UTF-8 bytes and one UTF-16 code unit, so a byte count
    /// and the twin's `String.length` disagree by a factor of two on it.
    const U_UMLAUT: &str = "\u{00FC}";

    /// One U+1F600 is four UTF-8 bytes, one `char`, and **two** UTF-16 code
    /// units — the surrogate pair the twin counts twice.
    const ASTRAL: &str = "\u{1F600}";

    #[test]
    fn password_debug_redacts_the_value() {
        let secret = "minted-password-Rc4vX8";
        let rendered = format!("{:?}", Password::try_new(secret.to_owned()).unwrap());
        assert!(!rendered.contains(secret), "{rendered}");
        assert_eq!(rendered, r#"Password("<redacted>")"#);
    }

    #[test]
    fn password_provided_debug_redacts_the_value() {
        let secret = "submitted-password-Nw7sG2";
        let rendered = format!("{:?}", PasswordProvided::new(secret.to_owned()));
        assert!(!rendered.contains(secret), "{rendered}");
        assert_eq!(rendered, r#"PasswordProvided("<redacted>")"#);
    }

    #[test]
    fn length_counts_utf16_code_units() {
        let eight = U_UMLAUT.repeat(8);
        assert_eq!(eight.len(), 16, "bytes");
        assert_eq!(password_length(&eight), 8, "utf-16 code units");

        assert_eq!(password_length(ASTRAL), 2);
        assert_eq!(ASTRAL.chars().count(), 1, "one char, two code units");
    }

    /// The two rows the byte count got backwards: eight `ü` is 16 bytes and so
    /// passed a byte-counted floor the twin refuses, and 151 of them is 302
    /// bytes and so failed a byte-counted ceiling the twin admits.
    #[test]
    fn a_creation_password_is_bounded_in_the_twins_units() {
        let eight = U_UMLAUT.repeat(8);
        assert!(
            Password::try_new(eight).is_err(),
            "8 code units is under the {PASSWORD_LENGTH_MIN} floor"
        );

        let at_max = U_UMLAUT.repeat(PASSWORD_LENGTH_MAX);
        assert_eq!(password_length(&at_max), PASSWORD_LENGTH_MAX);
        assert!(
            Password::try_new(at_max).is_ok(),
            "the ceiling is inclusive"
        );

        let over_max = U_UMLAUT.repeat(PASSWORD_LENGTH_MAX + 1);
        assert!(Password::try_new(over_max).is_err());

        // Half the ceiling in astral pairs is exactly the ceiling.
        let astral_at_max = ASTRAL.repeat(PASSWORD_LENGTH_MAX / 2);
        assert_eq!(password_length(&astral_at_max), PASSWORD_LENGTH_MAX);
        assert!(Password::try_new(astral_at_max).is_ok());
        let astral_over = ASTRAL.repeat(PASSWORD_LENGTH_MAX / 2 + 1);
        assert!(Password::try_new(astral_over).is_err());
    }

    /// A submitted password bounds only emptiness at the bottom — the twin's
    /// `PasswordProvided` is `.min(1)`, so an account minted under an earlier
    /// policy still authenticates.
    #[test]
    fn a_submitted_password_bounds_only_emptiness_and_the_ceiling() {
        assert!(PasswordProvided::try_new(String::new()).is_err());
        assert!(PasswordProvided::try_new("a".to_owned()).is_ok());
        assert!(PasswordProvided::try_new(U_UMLAUT.repeat(8)).is_ok());
        assert!(PasswordProvided::try_new(U_UMLAUT.repeat(PASSWORD_LENGTH_MAX)).is_ok());
        assert!(PasswordProvided::try_new(U_UMLAUT.repeat(PASSWORD_LENGTH_MAX + 1)).is_err());
    }
}
