//! The name grammar the auth vocabularies share: runs of lowercase ASCII
//! letters joined by single underscores, at most [`NAME_LENGTH_MAX`] long.
//!
//! Role names ([`RoleRegistry`](crate::RoleRegistry) and the `role` inputs),
//! scope kinds (the `scope_kind` of a grant input) and a token's `surface:`
//! name ([`SurfaceCapability`](crate::token_scope::SurfaceCapability)) hold
//! it, and the audit event type
//! ([`is_valid_audit_event_type_name`](crate::is_valid_audit_event_type_name))
//! takes its length cap over a grammar of its own. Twin of `fuz_app`'s
//! `auth/name_schema.ts` (`NAME_REGEX`, `NAME_LENGTH_MAX`, `is_valid_name`).
//! Grant paths and credential types, which `fuz_app` also holds to it, are
//! closed enums here ([`GrantPath`](crate::GrantPath),
//! [`CredentialType`](crate::credential_type::CredentialType)), so no name of
//! either is ever parsed.

/// The longest name the grammar admits.
///
/// Bytes, which for a name the grammar admits are its characters and its
/// UTF-16 code units, what `fuz_app` counts. Same value as `fuz_app`'s
/// `NAME_LENGTH_MAX`.
pub const NAME_LENGTH_MAX: usize = 64;

/// Whether `name` is on the shared name grammar: `^[a-z]+(?:_[a-z]+)*$`, so
/// no leading, trailing or consecutive underscores (a single letter is fine),
/// and at most [`NAME_LENGTH_MAX`] long.
///
/// Hand-rolled to match `fuz_app`'s `is_valid_name` — the regex and its
/// length cap — without pulling in a regex dependency. A `const fn` so
/// [`SurfaceCapability::new`](crate::token_scope::SurfaceCapability::new) can
/// refuse an off-grammar surface declared as a `const` at compile time.
#[must_use]
pub const fn is_valid_name(name: &str) -> bool {
    is_valid_name_bytes(name.as_bytes())
}

/// [`is_valid_name`] over bytes, for a caller holding a slice of a longer
/// string in `const` context.
#[must_use]
pub(crate) const fn is_valid_name_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > NAME_LENGTH_MAX {
        return false;
    }
    let last = bytes.len() - 1;
    let mut i = 0;
    while i <= last {
        let b = bytes[i];
        let ok = if i == 0 || i == last {
            b.is_ascii_lowercase()
        } else {
            b.is_ascii_lowercase() || (b == b'_' && bytes[i - 1] != b'_')
        };
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{NAME_LENGTH_MAX, is_valid_name};

    /// The grammar, row for row: `fuz_app`'s `name_schema.test.ts` corpus.
    #[test]
    fn the_name_grammar_and_its_cap() {
        assert_eq!(NAME_LENGTH_MAX, 64);
        let at_max = "a".repeat(NAME_LENGTH_MAX);
        let at_max_with_underscores = format!("{}aa", "a_".repeat(NAME_LENGTH_MAX / 2 - 1));
        assert_eq!(at_max_with_underscores.len(), NAME_LENGTH_MAX);
        for good in [
            "a",
            "admin",
            "a_b_c",
            "classroom_teacher",
            at_max.as_str(),
            at_max_with_underscores.as_str(),
        ] {
            assert!(is_valid_name(good), "{good:?} should be valid");
        }
        let past_max = format!("{at_max}a");
        let past_max_with_underscores = format!("{}a", "a_".repeat(NAME_LENGTH_MAX / 2));
        for bad in [
            past_max.as_str(),
            past_max_with_underscores.as_str(),
            "",
            "_",
            "__",
            "_a",
            "a_",
            "a__b",
            "a___b",
            "a_b__c",
            "A",
            "GLOBAL",
            "a1",
            "a-b",
            "a.b",
            "a b",
            "r\u{f4}le",
            "\u{1F600}",
        ] {
            assert!(!is_valid_name(bad), "{bad:?} should be invalid");
        }
        // off the grammar is the partial unique indexes' token for a global
        // grant, so a scope kind held to it never shares a global grant's key
        assert!(!is_valid_name(
            crate::ROLE_GRANT_OFFER_SCOPE_KIND_GLOBAL_TOKEN
        ));
    }

    /// The grammar evaluates in `const` context — what lets
    /// `SurfaceCapability::new` refuse an off-grammar surface at compile time.
    #[test]
    fn the_name_grammar_is_const() {
        const { assert!(is_valid_name("db_admin")) };
        const { assert!(!is_valid_name("db__admin")) };
    }
}
