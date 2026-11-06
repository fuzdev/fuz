//! Fractional indexing — generate ordered keys that admit insertion between
//! any two existing positions without rebalancing.
//!
//! Rust twin of `@fuzdev/fuz_util/fractional_index.js`, function-for-function:
//! `fractional_index_between` / `fractional_indices_between` are the same names
//! computing the same keys. A `cell_item.position` gives parent → child
//! membership a stable, lex-sortable order — lex order over keys equals numeric
//! order over the keys read as base62 fractions.
//!
//! `fuz_cell` consumes [`FRACTIONAL_INDEX_LENGTH_MAX`] from here for its wire
//! validation, so the cap is declared once per language rather than once per
//! crate.
//!
//! **Deterministic core; jitter is a client-side policy.** The TS side layers an
//! optional random base62 suffix on every emitted key — a best-effort collision
//! avoider for concurrent inserts racing on the same `(prev, next)` view,
//! backstopped by the server's `cell_item_position_taken` error. That layer is
//! opt-in there (`{jitter: false}` turns it off) and absent here: the callers on
//! this side are servers and seeders that want reproducible keys, and omitting
//! it keeps this crate free of a base62 sampler with no consumer. Bare keys from
//! the two languages are byte-identical for the same bounds, which is what makes
//! cross-language conformance testable.
//!
//! **Alphabet**: base62 (`0`-`9`, `A`-`Z`, `a`-`z`), monotonic in lex order.
//! `'0'` is the least digit; `'z'` the greatest.
//!
//! **Invariants emitted by this generator**:
//! - No emitted key ends in `'0'` (so `key + '0'` can't lex-equal `key`).
//! - Every emitted key is non-empty.
//! - Every emitted key matches `FRACTIONAL_INDEX_REGEX`.
//!
//! **Unsupported bracket shapes** (both surface as [`FractionalIndexError`]):
//! - Unbounded prepend below `'0…'`.
//! - Brackets shaped `(a, a + '0…0')` for any non-empty zero tail.

/// Base62 alphabet, monotonic in lex order: digits, then upper, then lower.
pub const FRACTIONAL_INDEX_ALPHABET: &[u8] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Alphabet length (`62`).
const ALPHABET_LEN: usize = FRACTIONAL_INDEX_ALPHABET.len();

/// Least digit (`'0'`).
const FIRST_DIGIT: u8 = FRACTIONAL_INDEX_ALPHABET[0];

/// Alphabet midpoint digit (`'V'` while the alphabet stays base62). Recomputed
/// from [`ALPHABET_LEN`] so the literal stays downstream of the constant.
const MID_DIGIT: u8 = FRACTIONAL_INDEX_ALPHABET[ALPHABET_LEN / 2];

/// Soft length cap on positions, mirrored at the wire.
///
/// DOS protection; the algorithm has no inherent length limit, but realistic UX
/// bounds keep emitted keys well under this even after thousands of consecutive
/// inserts.
pub const FRACTIONAL_INDEX_LENGTH_MAX: usize = 200;

/// Failures from the fractional-index generator.
///
/// Mirrors the TS generator's `throw` sites: a malformed / out-of-bounds bound,
/// an inverted bracket, and the two structurally-too-tight gap shapes the
/// generator doesn't support.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FractionalIndexError {
    /// A bound carried a non-alphabet byte (fails `FRACTIONAL_INDEX_REGEX`).
    #[error("fractional_index: {label} must match alphabet (got {value:?})")]
    InvalidDigit {
        /// Which bound (`"a"` / `"b"`) was malformed.
        label: &'static str,
        /// The offending bound value.
        value: String,
    },

    /// A bound exceeded [`FRACTIONAL_INDEX_LENGTH_MAX`].
    #[error("fractional_index: {label} exceeds length cap ({len} > {FRACTIONAL_INDEX_LENGTH_MAX})")]
    LengthCap {
        /// Which bound (`"a"` / `"b"`) was over-length.
        label: &'static str,
        /// The bound's length.
        len: usize,
    },

    /// The generated key itself exceeded [`FRACTIONAL_INDEX_LENGTH_MAX`].
    ///
    /// Distinct from [`Self::LengthCap`], which rejects an over-length *bound*.
    /// Bounds within a few digits of the cap can push a generated key over it,
    /// so the cap is enforced on output as well as input — failing here with a
    /// clear cause rather than emitting a key the wire would later reject.
    #[error(
        "fractional_index: generated key exceeds length cap ({len} > {FRACTIONAL_INDEX_LENGTH_MAX}); bounds too long to fit a key under it"
    )]
    GeneratedLengthCap {
        /// The generated key's length.
        len: usize,
    },

    /// `a >= b` lex-wise — the bracket admits no key.
    #[error("fractional_index: bracket invalid ({a:?} >= {b:?})")]
    InvertedBracket {
        /// The lower bound.
        a: String,
        /// The upper bound.
        b: String,
    },

    /// The gap below `b` is all-`'0'` — needs unbounded-prepend support.
    #[error("fractional_index: gap below {0:?} requires unbounded-prepend support")]
    UnboundedPrepend(String),

    /// The bracket is shaped `(a, a + '0…0')` — no key fits under the
    /// no-trailing-`'0'` invariant.
    #[error("fractional_index: gap between {a:?} and {b:?} too tight")]
    GapTooTight {
        /// The lower bound.
        a: String,
        /// The upper bound.
        b: String,
    },
}

/// Whether `value` matches the wire grammar (at least one base62 digit) —
/// the regex-free twin of the TS `FRACTIONAL_INDEX_REGEX` (`^[0-9A-Za-z]+$`).
#[must_use]
pub fn matches_fractional_index(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| FRACTIONAL_INDEX_ALPHABET.contains(&b))
}

/// Index of a base62 digit byte in [`FRACTIONAL_INDEX_ALPHABET`].
///
/// Caller guarantees `ch` is a valid alphabet byte (every call site flows from
/// a validated bound), so this can't fail in practice; it returns an error
/// rather than panicking to keep the no-`unwrap`/`expect` posture.
fn digit_index(ch: u8) -> Result<usize, FractionalIndexError> {
    FRACTIONAL_INDEX_ALPHABET
        .iter()
        .position(|&b| b == ch)
        .ok_or_else(|| FractionalIndexError::InvalidDigit {
            label: "digit",
            value: (ch as char).to_string(),
        })
}

/// Validate one bound: non-empty, in-alphabet, under the length cap.
fn validate_bound(label: &'static str, value: &str) -> Result<(), FractionalIndexError> {
    if !matches_fractional_index(value) {
        return Err(FractionalIndexError::InvalidDigit {
            label,
            value: value.to_owned(),
        });
    }
    if value.len() > FRACTIONAL_INDEX_LENGTH_MAX {
        return Err(FractionalIndexError::LengthCap {
            label,
            len: value.len(),
        });
    }
    Ok(())
}

/// Validate the `(a, b)` bracket: each present bound is well-formed, and `a < b`
/// when both are present.
fn validate_bracket(a: Option<&str>, b: Option<&str>) -> Result<(), FractionalIndexError> {
    if let Some(a) = a {
        validate_bound("a", a)?;
    }
    if let Some(b) = b {
        validate_bound("b", b)?;
    }
    if let (Some(a), Some(b)) = (a, b)
        && a >= b
    {
        return Err(FractionalIndexError::InvertedBracket {
            a: a.to_owned(),
            b: b.to_owned(),
        });
    }
    Ok(())
}

/// A non-trailing-`'0'` key strictly less than `b`, modifying only positions
/// `>= start_j`. `Ok(None)` when `b[start_j..]` is all `'0'`s — too tight under
/// the no-trailing-`'0'` invariant; the caller maps `None` to a context error.
fn step_below(b: &str, start_j: usize) -> Result<Option<String>, FractionalIndexError> {
    let bytes = b.as_bytes();
    let mut j = start_j;
    while j < bytes.len() && bytes[j] == FIRST_DIGIT {
        j += 1;
    }
    if j == bytes.len() {
        return Ok(None);
    }
    let idx = digit_index(bytes[j])?;
    if idx > 1 {
        let mut out = b[..j].to_owned();
        out.push(FRACTIONAL_INDEX_ALPHABET[idx - 1] as char);
        return Ok(Some(out));
    }
    // idx === 1 — extend with '0' + mid digit.
    let mut out = b[..j].to_owned();
    out.push(FIRST_DIGIT as char);
    out.push(MID_DIGIT as char);
    Ok(Some(out))
}

/// A non-trailing-`'0'` key strictly less than `b`, via single-step decrement of
/// `b`'s leading non-`'0'` digit. Errors when `b` is all-`'0'` (unbounded
/// prepend).
fn smaller_than(b: &str) -> Result<String, FractionalIndexError> {
    step_below(b, 0)?.ok_or_else(|| FractionalIndexError::UnboundedPrepend(b.to_owned()))
}

/// Smallest non-trailing-`'0'` key strictly greater than `a`.
///
/// Walks `a` left-to-right for the first non-`'z'` to increment, truncating the
/// tail; if `a` is all `'z'`s, extends with the mid digit.
fn larger_than(a: &str) -> Result<String, FractionalIndexError> {
    let bytes = a.as_bytes();
    for (i, &ch) in bytes.iter().enumerate() {
        let idx = digit_index(ch)?;
        if idx < ALPHABET_LEN - 1 {
            let mut out = a[..i].to_owned();
            out.push(FRACTIONAL_INDEX_ALPHABET[idx + 1] as char);
            return Ok(out);
        }
    }
    let mut out = a.to_owned();
    out.push(MID_DIGIT as char);
    Ok(out)
}

/// `a` is a strict prefix of `b` (with `i = a.len()`). Returns `step_below(b, i)`
/// — a key `a < k < b` — or [`FractionalIndexError::GapTooTight`] when `b` is
/// `a + '0'^k`.
fn between_prefix_and_extension(
    a: &str,
    b: &str,
    i: usize,
) -> Result<String, FractionalIndexError> {
    step_below(b, i)?.ok_or_else(|| FractionalIndexError::GapTooTight {
        a: a.to_owned(),
        b: b.to_owned(),
    })
}

/// Deterministic key strictly between `a` and `b` (precondition: `a < b`, both
/// non-empty). Walks the shared prefix, picks a gap digit or extends.
fn strict_between(a: &str, b: &str) -> Result<String, FractionalIndexError> {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut i = 0;
    while i < a_bytes.len() && i < b_bytes.len() && a_bytes[i] == b_bytes[i] {
        i += 1;
    }

    if i == a_bytes.len() {
        // `a` is a strict prefix of `b` — extend `a` toward `b`.
        return between_prefix_and_extension(a, b, i);
    }

    let a_idx = digit_index(a_bytes[i])?;
    let b_idx = digit_index(b_bytes[i])?;
    if b_idx - a_idx > 1 {
        let mid_idx = usize::midpoint(a_idx, b_idx);
        let mut out = a[..i].to_owned();
        out.push(FRACTIONAL_INDEX_ALPHABET[mid_idx] as char);
        return Ok(out);
    }
    // Gap === 1 (b_idx - a_idx === 1). Keep `a[i]` (the smaller divergent digit)
    // and extend `a`'s tail past i. Any extension keeps result < b and > a.
    let mut out = a[..=i].to_owned();
    out.push_str(&larger_than(&a[i + 1..])?);
    Ok(out)
}

/// Deterministic midpoint between `a` and `b`, no jitter.
///
/// - `(None, None)` → `'V'` (alphabet midpoint).
/// - `(Some(a), None)` → a non-trailing-`'0'` key strictly greater than `a`.
/// - `(None, Some(b))` → a non-trailing-`'0'` key strictly less than `b`.
/// - `(Some(a), Some(b))` → a key strictly between.
fn mid_between(a: Option<&str>, b: Option<&str>) -> Result<String, FractionalIndexError> {
    match (a, b) {
        (None, None) => Ok((MID_DIGIT as char).to_string()),
        (None, Some(b)) => smaller_than(b),
        (Some(a), None) => larger_than(a),
        (Some(a), Some(b)) => strict_between(a, b),
    }
}

/// A key strictly between `a` and `b` in lex order (the bare deterministic mid;
/// jitter dropped — see the module docstring).
///
/// Either bound may be `None` (open).
///
/// # Errors
///
/// [`FractionalIndexError`] when the bracket is invalid (`a >= b`), a bound is
/// malformed / over-length, the gap is structurally too tight under the
/// no-trailing-`'0'` invariant, or the bounds are so long the generated key
/// would itself exceed [`FRACTIONAL_INDEX_LENGTH_MAX`].
pub fn fractional_index_between(
    a: Option<&str>,
    b: Option<&str>,
) -> Result<String, FractionalIndexError> {
    validate_bracket(a, b)?;
    let key = mid_between(a, b)?;
    // Enforce the cap on output, not just inputs: bounds within a few digits of
    // the cap can push a generated key over it. `emit_n` routes through here, so
    // the recursive path is covered too.
    if key.len() > FRACTIONAL_INDEX_LENGTH_MAX {
        return Err(FractionalIndexError::GeneratedLengthCap { len: key.len() });
    }
    Ok(key)
}

/// Generate `n` strictly-ordered keys between `a` and `b`.
///
/// Output is monotonically increasing; equal spacing is not guaranteed. Atomic
/// on failure — a structurally-too-tight bracket throws and returns no partial
/// vector.
///
/// # Errors
///
/// [`FractionalIndexError`] for an invalid bracket, a malformed bound, or a
/// too-tight gap at any recursion depth.
pub fn fractional_indices_between(
    a: Option<&str>,
    b: Option<&str>,
    n: usize,
) -> Result<Vec<String>, FractionalIndexError> {
    // Validate the bracket regardless of `n`, so a structurally invalid bracket
    // is always an error rather than being silently accepted at `n == 0` —
    // matching `fractional_index_between`. A too-tight *gap* is feasibility,
    // not structure, so it only surfaces once keys are actually generated.
    validate_bracket(a, b)?;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(n);
    emit_n(a, b, n, &mut out)?;
    Ok(out)
}

/// Recursive bisection: deterministic mid of `(a, b)`, `floor(n/2)` keys in
/// `(a, mid)`, the mid, then the rest in `(mid, b)`.
fn emit_n(
    a: Option<&str>,
    b: Option<&str>,
    n: usize,
    out: &mut Vec<String>,
) -> Result<(), FractionalIndexError> {
    if n == 0 {
        return Ok(());
    }
    let mid = fractional_index_between(a, b)?;
    if n == 1 {
        out.push(mid);
        return Ok(());
    }
    let left = n / 2;
    emit_n(a, Some(&mid), left, out)?;
    // `mid` is borrowed by both recursive halves; push a clone so the second
    // half can still reference it as the lower bound.
    let mid_owned = mid.clone();
    out.push(mid);
    emit_n(Some(&mid_owned), b, n - left - 1, out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use super::*;

    /// Every key in `keys` matches the wire grammar and the sequence is
    /// strictly lexicographically increasing.
    fn assert_strictly_increasing_and_valid(keys: &[String]) {
        for key in keys {
            assert!(
                matches_fractional_index(key),
                "key {key:?} fails the base62 grammar"
            );
        }
        for window in keys.windows(2) {
            assert!(
                window[0] < window[1],
                "keys not strictly increasing: {:?} >= {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn open_open_range_is_monotonic_and_valid() {
        for n in [1_usize, 2, 3, 5, 8, 20] {
            let keys = fractional_indices_between(None, None, n).unwrap();
            assert_eq!(keys.len(), n);
            assert_strictly_increasing_and_valid(&keys);
        }
    }

    #[test]
    fn open_open_single_is_mid_digit() {
        let keys = fractional_indices_between(None, None, 1).unwrap();
        assert_eq!(keys, vec!["V".to_string()]);
    }

    #[test]
    fn append_above_lower_bound_sorts_greater() {
        // The seeder's main shape: append into the open-above range after the
        // last existing item.
        let keys = fractional_indices_between(Some("a0"), None, 3).unwrap();
        assert_eq!(keys.len(), 3);
        assert_strictly_increasing_and_valid(&keys);
        for key in &keys {
            assert!(
                key.as_str() > "a0",
                "appended key {key:?} does not sort after the anchor \"a0\""
            );
        }
    }

    #[test]
    fn append_after_existing_position_is_monotonic() {
        for anchor in ["V", "W", "a0", "zzz", "0V"] {
            for n in [1_usize, 3, 7] {
                let keys = fractional_indices_between(Some(anchor), None, n).unwrap();
                assert_eq!(keys.len(), n);
                assert_strictly_increasing_and_valid(&keys);
                assert!(
                    keys[0].as_str() > anchor,
                    "first appended key {:?} not > anchor {anchor:?}",
                    keys[0]
                );
            }
        }
    }

    #[test]
    fn no_emitted_key_ends_in_zero() {
        let mut all = fractional_indices_between(None, None, 30).unwrap();
        all.extend(fractional_indices_between(Some("V"), None, 30).unwrap());
        for key in &all {
            assert_ne!(
                key.bytes().last(),
                Some(FIRST_DIGIT),
                "key {key:?} ends in a trailing '0'"
            );
        }
    }

    #[test]
    fn bounded_bracket_keys_stay_inside() {
        let keys = fractional_indices_between(Some("A"), Some("z"), 10).unwrap();
        assert_strictly_increasing_and_valid(&keys);
        for key in &keys {
            assert!(
                key.as_str() > "A" && key.as_str() < "z",
                "key {key:?} escaped (A, z)"
            );
        }
    }

    #[test]
    fn n_zero_is_empty() {
        assert!(
            fractional_indices_between(None, None, 0)
                .unwrap()
                .is_empty()
        );
        assert!(
            fractional_indices_between(Some("a0"), None, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn n_zero_still_validates_the_bracket() {
        // A structurally invalid bracket errors regardless of `n`, matching
        // `fractional_index_between` rather than being accepted at `n == 0`.
        let err = fractional_indices_between(Some("z"), Some("a"), 0).unwrap_err();
        assert!(matches!(err, FractionalIndexError::InvertedBracket { .. }));
        let err = fractional_indices_between(Some("a-b"), None, 0).unwrap_err();
        assert!(matches!(err, FractionalIndexError::InvalidDigit { .. }));
    }

    #[test]
    fn generated_key_over_cap_errors() {
        // Both bounds sit at the cap and differ only in the final digit, so any
        // key between them needs one more digit than the cap allows.
        let a = "a".repeat(FRACTIONAL_INDEX_LENGTH_MAX);
        let b = format!("{}b", "a".repeat(FRACTIONAL_INDEX_LENGTH_MAX - 1));
        let err = fractional_index_between(Some(&a), Some(&b)).unwrap_err();
        assert!(
            matches!(err, FractionalIndexError::GeneratedLengthCap { len } if len > FRACTIONAL_INDEX_LENGTH_MAX),
            "expected GeneratedLengthCap, got {err:?}"
        );
    }

    #[test]
    fn inverted_bracket_errors() {
        let err = fractional_indices_between(Some("z"), Some("a"), 1).unwrap_err();
        assert!(matches!(err, FractionalIndexError::InvertedBracket { .. }));
    }

    #[test]
    fn malformed_bound_errors() {
        let err = fractional_indices_between(Some("a-b"), None, 1).unwrap_err();
        assert!(matches!(err, FractionalIndexError::InvalidDigit { .. }));
    }

    #[test]
    fn too_tight_gap_errors() {
        // `(a, a + '0')` admits no key under the no-trailing-'0' invariant.
        let err = fractional_index_between(Some("a"), Some("a0")).unwrap_err();
        assert!(matches!(err, FractionalIndexError::GapTooTight { .. }));
    }

    #[test]
    fn prepend_below_zero_errors() {
        let err = fractional_index_between(None, Some("0")).unwrap_err();
        assert!(matches!(err, FractionalIndexError::UnboundedPrepend(_)));
    }

    /// Cross-language conformance vectors, duplicated byte-for-byte into
    /// `fuz_util`'s `src/test/` and asserted there the same way.
    ///
    /// This is the only check that catches the two implementations each passing
    /// their own unit suite while emitting *different* keys — the alphabet
    /// midpoint, the bisection split, and the step-compactness choices are
    /// arbitrary-but-must-match, and nothing else pins them together. A failure
    /// here means the implementation drifted, not the vectors.
    mod conformance {
        use super::*;

        const VECTORS: &str = include_str!("fractional_index_vectors.json");

        fn bound(v: &serde_json::Value) -> Option<&str> {
            v.as_str()
        }

        #[test]
        fn bare_keys_match_the_shared_vectors() {
            let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
            let cases = doc["between"].as_array().unwrap();
            assert!(
                !cases.is_empty(),
                "vectors file parsed but carried no cases"
            );
            for case in cases {
                let (a, b) = (bound(&case["a"]), bound(&case["b"]));
                let expected = case["key"].as_str().unwrap();
                let got = fractional_index_between(a, b).unwrap();
                assert_eq!(got, expected, "between({a:?}, {b:?})");
            }
        }

        #[test]
        fn bare_key_runs_match_the_shared_vectors() {
            let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
            let cases = doc["indices"].as_array().unwrap();
            assert!(
                !cases.is_empty(),
                "vectors file parsed but carried no cases"
            );
            for case in cases {
                let (a, b) = (bound(&case["a"]), bound(&case["b"]));
                let n = usize::try_from(case["n"].as_u64().unwrap()).unwrap();
                let expected: Vec<&str> = case["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| k.as_str().unwrap())
                    .collect();
                let got = fractional_indices_between(a, b, n).unwrap();
                assert_eq!(got, expected, "indices({a:?}, {b:?}, {n})");
            }
        }
    }
}
