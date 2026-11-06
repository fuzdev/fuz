//! Serde adapter: a JSON object read into a map, refusing a repeated key.
//!
//! A plain map deserialize keeps the last of two equal keys and discards the
//! first without a trace. In a signed document that is a second reading of the
//! same bytes: the signature still verifies, since it covers the value as
//! re-serialized, while a reader that keeps the *first* key — another JSON
//! library, or a `grep` of the file — takes its value from the entry the parse
//! discarded. Every map in a signed document is read through
//! [`deserialize`], directly (`#[serde(deserialize_with =
//! "fuz_crypto::unique_map::deserialize")]`) or under an adapter such as
//! [`blake3_hex_map`](crate::blake3_hex_map) that reads through it.
//!
//! A repeated key is refused by refusing the document, so an honest document,
//! which never repeats one, reads as it always has.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};

/// Most bytes of a repeated key the refusal repeats.
const MAX_KEY_EXCERPT_LEN: usize = 128;

/// Deserialize a JSON object into a map, refusing a repeated key.
///
/// The refusal's message is `duplicate key "<key>"`. The key is cut to
/// `MAX_KEY_EXCERPT_LEN` bytes on a character boundary (`...` appended when
/// cut) and is otherwise as given: it is from a document whose signature has
/// not been checked, and the parser error that carries it is escaped whole
/// where it is rendered, so escaping it here too would escape it twice.
///
/// # Errors
///
/// The deserializer's error for a repeated key, or for a key or value that
/// does not deserialize.
pub fn deserialize<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct UniqueMap<V>(PhantomData<V>);

    impl<'de, V: Deserialize<'de>> Visitor<'de> for UniqueMap<V> {
        type Value = BTreeMap<String, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map with unique keys")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, V>()? {
                match map.entry(key) {
                    Entry::Vacant(slot) => {
                        slot.insert(value);
                    }
                    Entry::Occupied(slot) => {
                        return Err(A::Error::custom(format_args!(
                            "duplicate key \"{}\"",
                            key_excerpt(slot.key())
                        )));
                    }
                }
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(UniqueMap(PhantomData))
}

/// `key` cut to `MAX_KEY_EXCERPT_LEN` bytes on a character boundary, with
/// `...` appended when cut.
fn key_excerpt(key: &str) -> String {
    if key.len() <= MAX_KEY_EXCERPT_LEN {
        return key.to_string();
    }
    let mut end = MAX_KEY_EXCERPT_LEN;
    while !key.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &key[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Wrap {
        #[serde(deserialize_with = "super::deserialize")]
        m: BTreeMap<String, u32>,
    }

    fn parse(json: &str) -> Result<BTreeMap<String, u32>, String> {
        serde_json::from_str::<Wrap>(json)
            .map(|w| w.m)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn unique_keys_read_as_a_plain_map() {
        assert_eq!(
            parse(r#"{"m":{"b":2,"a":1}}"#).unwrap(),
            BTreeMap::from([("a".to_string(), 1), ("b".to_string(), 2)])
        );
        assert_eq!(parse(r#"{"m":{}}"#).unwrap(), BTreeMap::new());
    }

    #[test]
    fn a_repeated_key_is_refused_wherever_it_repeats() {
        for json in [
            r#"{"m":{"a":1,"a":2}}"#,
            r#"{"m":{"a":1,"b":2,"a":1}}"#,
            r#"{"m":{"b":2,"a":1,"a":1}}"#,
        ] {
            let error = parse(json).unwrap_err();
            assert!(error.starts_with("duplicate key \"a\""), "{json}: {error}");
        }
    }

    #[test]
    fn a_key_differing_only_in_case_is_not_a_repeat() {
        assert_eq!(parse(r#"{"m":{"a":1,"A":2}}"#).unwrap().len(), 2);
    }

    #[test]
    fn a_long_repeated_key_is_named_by_a_bounded_excerpt() {
        // A two-byte character straddles the bound; the cut backs up before it.
        let key = format!(
            "{}\u{e9}{}",
            "k".repeat(MAX_KEY_EXCERPT_LEN - 1),
            "z".repeat(100_000)
        );
        let error = parse(&format!(r#"{{"m":{{"{key}":1,"{key}":2}}}}"#)).unwrap_err();
        assert!(
            error.starts_with(&format!(
                "duplicate key \"{}...\"",
                "k".repeat(MAX_KEY_EXCERPT_LEN - 1)
            )),
            "{}",
            &error[..200]
        );
        assert!(error.len() < 300, "{} bytes", error.len());
    }
}
