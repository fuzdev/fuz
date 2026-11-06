//! [`ActionOutput`] — a handler's successful result, rendered once into the
//! JSON-RPC success envelope by the transport.
//!
//! Most handlers return a `serde_json::Value` (wrapped via `From<Value>`).
//! A handler whose output is large — a snapshot of file contents, say — can
//! instead hand over its typed output with [`ActionOutput::serialize`]: the
//! transport serializes it straight into the response buffer, so the output
//! is never copied into an intermediate `Value` tree first. Sharing the
//! large parts of that output (behind an `Arc`) with the state they came
//! from keeps the handler's own copy out of the picture too, leaving the
//! rendered response as the one large allocation.
//!
//! [`write_success_response`] writes the envelope `serde_json` would derive
//! for `fuz_http::JsonrpcResponse`. A typed output renders the same JSON its
//! `Value` would, with its keys in declaration order rather than sorted.

use serde::Serialize;
use serde_json::Value;

/// Initial response-buffer capacity for an output with no size hint —
/// `axum::Json`'s starting capacity.
const DEFAULT_CAPACITY: usize = 128;

/// The envelope bytes around `id` and `result`, budgeted on top of an
/// output's size hint.
const ENVELOPE_CAPACITY: usize = 64;

/// A handler's successful result.
///
/// Built from a `Value` (`ActionOutput::from(value)`) or from any owned
/// `Serialize` value ([`ActionOutput::serialize`]). See the module docs.
pub struct ActionOutput {
    repr: OutputRepr,
}

enum OutputRepr {
    Value(Value),
    Serialize {
        value: Box<dyn WriteJson>,
        capacity: usize,
    },
}

/// Object-safe "serialize me as compact JSON" — the one operation the
/// transports need from a typed output.
trait WriteJson: Send + Sync {
    fn write_json(&self, out: &mut Vec<u8>) -> serde_json::Result<()>;
}

impl<T: Serialize + Send + Sync> WriteJson for T {
    fn write_json(&self, out: &mut Vec<u8>) -> serde_json::Result<()> {
        serde_json::to_writer(out, self)
    }
}

impl ActionOutput {
    /// Wrap an owned `Serialize` value, rendered by the transport straight
    /// into the response — no intermediate `Value`.
    ///
    /// Serialization runs after the handler returns (after its transaction
    /// commits), so `value` must own its data; share large parts with
    /// `Arc` rather than cloning them.
    #[must_use]
    pub fn serialize<T: Serialize + Send + Sync + 'static>(value: T) -> Self {
        Self {
            repr: OutputRepr::Serialize {
                value: Box::new(value),
                capacity: DEFAULT_CAPACITY,
            },
        }
    }

    /// Hint the rendered size in bytes, so the response buffer is allocated
    /// once instead of grown by doubling. An underestimate only costs the
    /// growth it would have anyway; a `Value` output ignores it.
    #[must_use]
    pub const fn with_size_hint(mut self, bytes: usize) -> Self {
        if let OutputRepr::Serialize { capacity, .. } = &mut self.repr {
            *capacity = bytes;
        }
        self
    }

    /// Append this output's compact JSON to `out`.
    ///
    /// # Errors
    ///
    /// Returns the `serde_json` error if the output fails to serialize — a
    /// `Value` never does; a typed output can only through a failing
    /// `Serialize` impl (a map with non-string keys, say).
    pub fn write_json(&self, out: &mut Vec<u8>) -> serde_json::Result<()> {
        match &self.repr {
            OutputRepr::Value(value) => serde_json::to_writer(out, value),
            OutputRepr::Serialize { value, .. } => value.write_json(out),
        }
    }

    /// This output as a `Value` — for tests and in-process callers; the
    /// transports render with [`write_success_response`] instead.
    ///
    /// # Errors
    ///
    /// As [`Self::write_json`].
    pub fn to_value(&self) -> serde_json::Result<Value> {
        match &self.repr {
            OutputRepr::Value(value) => Ok(value.clone()),
            OutputRepr::Serialize { .. } => {
                let mut out = Vec::new();
                self.write_json(&mut out)?;
                serde_json::from_slice(&out)
            }
        }
    }

    /// The response-buffer capacity to start with.
    const fn capacity(&self) -> usize {
        match &self.repr {
            OutputRepr::Value(_) => DEFAULT_CAPACITY,
            OutputRepr::Serialize { capacity, .. } => *capacity,
        }
    }
}

impl From<Value> for ActionOutput {
    fn from(value: Value) -> Self {
        Self {
            repr: OutputRepr::Value(value),
        }
    }
}

impl std::fmt::Debug for ActionOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.repr {
            OutputRepr::Value(value) => f.debug_tuple("ActionOutput").field(value).finish(),
            OutputRepr::Serialize { capacity, .. } => f
                .debug_struct("ActionOutput")
                .field("size_hint", capacity)
                .finish_non_exhaustive(),
        }
    }
}

/// Render the JSON-RPC success envelope `{"jsonrpc":"2.0","id":…,"result":…}`
/// in one pass — the bytes `serde_json::to_vec` gives for
/// `fuz_http::success_response(id, result)`, without building it.
///
/// # Errors
///
/// As [`ActionOutput::write_json`].
pub fn write_success_response(id: &Value, output: &ActionOutput) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(output.capacity().saturating_add(ENVELOPE_CAPACITY));
    out.extend_from_slice(br#"{"jsonrpc":""#);
    out.extend_from_slice(fuz_http::JSONRPC_VERSION.as_bytes());
    out.extend_from_slice(br#"","id":"#);
    serde_json::to_writer(&mut out, id)?;
    out.extend_from_slice(br#","result":"#);
    output.write_json(&mut out)?;
    out.push(b'}');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use serde_json::{Value, json};

    use super::{ActionOutput, write_success_response};

    #[derive(Serialize)]
    struct Sample {
        contents: Option<String>,
        id: String,
        mtime: f64,
        tags: Vec<&'static str>,
    }

    fn sample() -> Sample {
        Sample {
            contents: Some(String::from("line \"one\"\n\u{1F600}\u{0007}")),
            id: "/a/b".to_owned(),
            mtime: 1.5,
            tags: vec!["x", "y"],
        }
    }

    fn envelope(id: &Value, result: Value) -> Vec<u8> {
        serde_json::to_vec(&fuz_http::success_response(id.clone(), result))
            .expect("derived envelope")
    }

    #[test]
    fn value_output_renders_the_derived_envelope() {
        for id in [json!(1), json!("req-7"), json!(-2.5), Value::Null] {
            let result = json!({"b": [1, 2], "a": null, "c": {"z": "é", "y": true}});
            let rendered =
                write_success_response(&id, &ActionOutput::from(result.clone())).expect("render");
            assert_eq!(rendered, envelope(&id, result));
        }
    }

    #[test]
    fn typed_output_renders_the_json_its_value_would() {
        let id = json!(42);
        let rendered =
            write_success_response(&id, &ActionOutput::serialize(sample())).expect("render");
        let parsed: Value = serde_json::from_slice(&rendered).expect("valid JSON");
        assert_eq!(
            parsed,
            json!({
                "jsonrpc": "2.0",
                "id": 42,
                "result": serde_json::to_value(sample()).expect("to_value"),
            })
        );
        // the envelope keys lead, in the derived order
        assert!(rendered.starts_with(br#"{"jsonrpc":"2.0","id":42,"result":{"#));
    }

    #[test]
    fn size_hint_changes_capacity_not_bytes() {
        let id = json!(1);
        let plain = write_success_response(&id, &ActionOutput::serialize(sample())).expect("plain");
        let hinted = write_success_response(
            &id,
            &ActionOutput::serialize(sample()).with_size_hint(1 << 16),
        )
        .expect("hinted");
        assert_eq!(plain, hinted);
        assert!(hinted.capacity() >= 1 << 16);
    }

    #[test]
    fn to_value_round_trips_both_forms() {
        let expected = serde_json::to_value(sample()).expect("to_value");
        assert_eq!(
            ActionOutput::serialize(sample()).to_value().expect("typed"),
            expected
        );
        assert_eq!(
            ActionOutput::from(expected.clone())
                .to_value()
                .expect("value"),
            expected
        );
    }

    #[test]
    fn a_failing_serialize_is_an_error_not_a_panic() {
        // a map with non-string keys can't be JSON
        let mut map = std::collections::BTreeMap::new();
        map.insert(vec![1u8], 1);
        assert!(write_success_response(&json!(1), &ActionOutput::serialize(map)).is_err());
    }
}
