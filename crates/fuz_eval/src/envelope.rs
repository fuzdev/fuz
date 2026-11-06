//! The reader of `fgro eval`'s stdout: typed mirrors of the envelope
//! (`eval_protocol` 2) and its graph dump (`graph_version` 1), and the
//! fail-closed checks that turn one envelope and its exit code into a value, an
//! eval failure, or a [`ProtocolViolation`] (crate docs § The envelope).
//!
//! Every mirror denies unknown fields, so a field this reader doesn't know
//! refuses the envelope instead of being skipped: a new field is a new
//! protocol or graph version.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

/// The envelope version this reader knows.
const EVAL_PROTOCOL: u64 = 2;

/// The graph dump version this reader knows.
const GRAPH_VERSION: u64 = 1;

/// How many bytes of a value `fgro` wrote are quoted in a violation's message.
const SHOWN_MAX: usize = 200;

/// The kind of an eval failure, as `fgro eval`'s envelope names it: the
/// contract a consumer branches on, derived by `fgro` from the phase that
/// failed, never from a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalErrorKind {
    /// The config didn't resolve, isn't a project's own module (inside
    /// `node_modules`, or with no project root), or a static import didn't
    /// resolve.
    Resolve,
    /// The graph didn't form: a syntax error, a missing export binding,
    /// TypeScript the strip refuses, import attributes, or a module over the
    /// source cap.
    Link,
    /// A module's evaluation, or the driver's call, threw, rejected, or left a
    /// top-level `await` unsettled.
    ModuleThrew,
    /// The driver has no `default` function, or an `after_drain` that isn't
    /// one.
    ExportMissing,
    /// The value isn't data by `fgro`'s serializer rules, or its envelope would
    /// pass `fgro`'s envelope cap.
    Serialize,
    /// After the value was taken, the remaining work threw or rejected, or the
    /// driver's `after_drain` threw.
    LateRejection,
    /// The heap reached its cap.
    Heap,
    /// The process reached `fgro`'s memory cap (or a lower limit the process
    /// inherited) outside the heap's cap: an allocation outside the heap, such
    /// as an `ArrayBuffer`'s, failed.
    Memory,
    /// The run passed the timeout passed to `fgro` and was stopped.
    Timeout,
    /// The host can't hold the eval: a time zone other than UTC, inherited
    /// descriptors it can't close, or a kernel without the box it needs.
    Environment,
    /// `fgro` itself failed: a module changed on disk during the run, a read
    /// failed or was refused outside the box's roots, the build has no startup
    /// snapshot, or a host invariant broke.
    Internal,
}

impl EvalErrorKind {
    /// The kind as the envelope writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Link => "link",
            Self::ModuleThrew => "module_threw",
            Self::ExportMissing => "export_missing",
            Self::Serialize => "serialize",
            Self::LateRejection => "late_rejection",
            Self::Heap => "heap",
            Self::Memory => "memory",
            Self::Timeout => "timeout",
            Self::Environment => "environment",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for EvalErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The module graph an eval loaded (`graph_version` 1).
///
/// Each module it resolved, each `package.json` a resolution read, each path a
/// resolution went past finding nothing, and the absolute paths behind the ids.
/// Ids are location-independent (`project:<path>` under the project root,
/// `linked:<path>` outside it); absolute paths are only in
/// [`local`](Self::local). Every array is sorted as `fgro` wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphDump {
    /// The dump's version, `1`.
    pub graph_version: u32,
    /// The module the graph loads from: the entry alone.
    pub roots: Vec<String>,
    /// Each module the run resolved, by id.
    pub modules: Vec<DumpModule>,
    /// Each `package.json` a resolution read, by id, then role.
    pub consulted: Vec<DumpConsulted>,
    /// Each path a resolution went past finding nothing of the kind it looked
    /// for, by id.
    pub absent: Vec<String>,
    /// The absolute paths behind the ids.
    pub local: DumpLocal,
}

/// A module the run resolved.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DumpModule {
    /// Its id, with its URL's query and fragment.
    pub id: String,
    /// The blake3 of the bytes read for it, in hex; `None` when it didn't load,
    /// which only a failed run leaves: the reader refuses an `ok: true` graph
    /// with one.
    #[serde(deserialize_with = "nullable")]
    pub blake3: Option<String>,
    /// Where it comes from.
    pub origin: DumpOrigin,
    /// How its source became the JS that ran; `None` when it didn't load, as
    /// with [`blake3`](Self::blake3).
    #[serde(deserialize_with = "nullable")]
    pub format: Option<DumpFormat>,
    /// Each import of it that resolved.
    pub imports: Vec<DumpImport>,
}

/// Where a module comes from.
///
/// Read through a wire struct of its own, since serde lets an internally tagged unit
/// variant carry any other field: `{"kind": "project"}` with anything more is
/// refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", try_from = "OriginWire")]
pub enum DumpOrigin {
    /// The project's own files.
    Project,
    /// An installed or linked package.
    Package {
        /// The name it was first imported by.
        name: String,
        /// Its `package.json` `"version"`, `None` when that isn't a string.
        version: Option<String>,
        /// Whether its real root is outside every `node_modules`.
        linked: bool,
    },
}

/// [`DumpOrigin`] as written, every field but `kind` optional, so the
/// variant's fields are checked exactly.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginWire {
    kind: OriginKind,
    #[serde(default, deserialize_with = "present")]
    name: Field<String>,
    #[serde(default, deserialize_with = "present")]
    version: Field<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    linked: Field<bool>,
}

/// [`DumpOrigin`]'s tag.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum OriginKind {
    Project,
    Package,
}

impl TryFrom<OriginWire> for DumpOrigin {
    type Error = &'static str;

    fn try_from(wire: OriginWire) -> Result<Self, Self::Error> {
        match (wire.kind, wire.name, wire.version, wire.linked) {
            (OriginKind::Project, Field::Missing, Field::Missing, Field::Missing) => {
                Ok(Self::Project)
            }
            (
                OriginKind::Package,
                Field::Present(name),
                Field::Present(version),
                Field::Present(linked),
            ) => Ok(Self::Package {
                name,
                version,
                linked,
            }),
            (OriginKind::Project, ..) => {
                Err("a project origin has a field other than `kind` (unknown field)")
            }
            (OriginKind::Package, ..) => {
                Err("a package origin lacks `name`, `version`, or `linked`")
            }
        }
    }
}

/// How a module's source became the JS that ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpFormat {
    /// Run as written.
    Javascript,
    /// Stripped of its types.
    Typescript,
}

/// An import that resolved.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DumpImport {
    /// The specifier as written.
    pub specifier: String,
    /// The id of the module it resolved to.
    pub resolved: String,
    /// How it was reached.
    pub reach: DumpReach,
}

/// How an import was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpReach {
    /// A static import.
    Static,
    /// Through an `import()`, which eval refuses before resolving, so none
    /// appears yet.
    Dynamic,
}

/// A `package.json` a resolution read.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DumpConsulted {
    /// Its id.
    pub id: String,
    /// The blake3 of the bytes of its one read in the run, in hex.
    pub blake3: String,
    /// What it was read for.
    pub role: DumpRole,
}

/// What a `package.json` was read for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpRole {
    /// A package's, for its `"exports"`.
    Exports,
    /// The nearest above a module, for its `"type"`, or above an importer, for
    /// a self-reference.
    PackageScope,
    /// One on the walk up for the project root.
    SearchBound,
    /// The package's an entry inside `node_modules` is in.
    Version,
}

/// The absolute paths behind a dump's ids.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DumpLocal {
    /// The project root `fgro` found, every id's base. The reader has checked
    /// it is the trust root (crate docs § The envelope).
    pub project: String,
    /// The roots of the box the run was confined to: the project root first,
    /// then the link closure.
    #[serde(rename = "box")]
    pub box_roots: Vec<String>,
    /// Each id's absolute path; a module's under its id cut at the first `?`
    /// or `#`.
    pub paths: BTreeMap<String, String>,
}

/// Why `fgro`'s stdout and exit code were refused as an envelope: the reader
/// fails closed on anything it doesn't know ([`crate::EvalError::Protocol`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolViolation {
    /// Exit `0`, `1`, or `2` with nothing on stdout.
    NoEnvelope,
    /// Stdout isn't one JSON object on one line followed by at most a newline.
    NotOneObject,
    /// The envelope isn't the shape of protocol 2: an unknown or missing field,
    /// a field of the wrong type, or a duplicate. `reason` is the parser's.
    Shape {
        /// What the parser refused.
        reason: String,
    },
    /// `eval_protocol` isn't `2` (`None` when it is missing or not a number).
    ProtocolVersion {
        /// The version found.
        found: Option<u64>,
    },
    /// `graph.graph_version` isn't `1` (`None` when it is missing or not a
    /// number).
    GraphVersion {
        /// The version found.
        found: Option<u64>,
    },
    /// The exit code doesn't agree with `ok`: `0` must be `ok: true`, and `1`
    /// or `2` `ok: false`.
    ExitMismatch {
        /// The exit code.
        code: i32,
        /// The envelope's `ok`.
        ok: bool,
    },
    /// `ok: true` without a `value`, or with an `error` (`null` included); or
    /// `ok: false` without an `error`, or with a `value`.
    ResultMismatch {
        /// The envelope's `ok`.
        ok: bool,
    },
    /// `access` is missing.
    AccessMissing,
    /// `entry.id` isn't the canonical config path that was evaluated.
    EntryId {
        /// The id found.
        found: String,
    },
    /// `entry.export` isn't null, though a driver was sent. (A failure before
    /// fgro read the driver names `default` with no driver hash, and is
    /// accepted as the failure it reports.)
    EntryExport {
        /// The export found.
        found: String,
    },
    /// `entry.driver_blake3` isn't the blake3 of the driver that was sent.
    DriverBlake3 {
        /// The blake3 of the driver sent.
        expected: String,
        /// The blake3 found, `None` when null.
        found: Option<String>,
    },
    /// `graph` is missing, though `--graph` was passed.
    GraphMissing,
    /// `graph` is null under `ok: true`: a value with no graph to describe it.
    GraphNullOnSuccess,
    /// `graph.local.project` isn't the trust root this crate settled: `fgro`
    /// bounded the eval by another project than the one the walk found, which
    /// the disk changing between the two walks can do.
    ProjectMismatch {
        /// The trust root.
        trust_root: PathBuf,
        /// The project `fgro` reported.
        project: String,
    },
    /// An `ok: true` graph lists a module with no `blake3` or no `format`, which
    /// only a failed run leaves: a value whose inputs aren't all named.
    ModuleNotLoaded {
        /// The module's id.
        id: String,
    },
}

impl std::fmt::Display for ProtocolViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shown = |text: &str| fuz_sys::text::quoted(&fuz_sys::text::truncate(text, SHOWN_MAX));
        match self {
            Self::NoEnvelope => f.write_str("it wrote no envelope"),
            Self::NotOneObject => f.write_str("its stdout is not one JSON object on one line"),
            Self::Shape { reason } => write!(
                f,
                "its envelope is not the shape of eval protocol {EVAL_PROTOCOL}: {}",
                fuz_sys::text::escape_untrusted(&fuz_sys::text::truncate(reason, SHOWN_MAX))
            ),
            Self::ProtocolVersion { found } => write!(
                f,
                "its envelope is eval protocol {}, not {EVAL_PROTOCOL}",
                version_shown(*found)
            ),
            Self::GraphVersion { found } => write!(
                f,
                "its graph is graph version {}, not {GRAPH_VERSION}",
                version_shown(*found)
            ),
            Self::ExitMismatch { code, ok } => {
                write!(f, "it exited {code} with an envelope whose ok is {ok}")
            }
            Self::ResultMismatch { ok: true } => {
                f.write_str("its envelope is ok but holds no value, or holds an error")
            }
            Self::ResultMismatch { ok: false } => {
                f.write_str("its envelope failed but holds no error, or holds a value")
            }
            Self::AccessMissing => f.write_str("its envelope has no access field"),
            Self::EntryId { found } => {
                write!(f, "its envelope evaluated {}, not the config", shown(found))
            }
            Self::EntryExport { found } => write!(
                f,
                "its envelope read the export {} though a driver was sent",
                shown(found)
            ),
            Self::DriverBlake3 { expected, found } => write!(
                f,
                "its envelope names the driver {}, not the driver sent ({expected})",
                found.as_deref().map_or_else(|| "null".to_owned(), shown)
            ),
            Self::GraphMissing => {
                f.write_str("its envelope has no graph, though one was asked for")
            }
            Self::GraphNullOnSuccess => {
                f.write_str("its envelope holds a value but no graph to describe it")
            }
            Self::ProjectMismatch {
                trust_root,
                project,
            } => write!(
                f,
                "it bounded the eval by the project {}, not the trust root {}",
                shown(project),
                shown(&trust_root.display().to_string())
            ),
            Self::ModuleNotLoaded { id } => write!(
                f,
                "its envelope holds a value but its graph names the module {} as not loaded",
                shown(id)
            ),
        }
    }
}

/// A version for a message: the number, or `unknown`.
fn version_shown(found: Option<u64>) -> String {
    found.map_or_else(|| "unknown".to_owned(), |version| version.to_string())
}

/// What the reader checks an envelope against.
pub struct Expected<'a> {
    /// The canonical config path passed to `fgro`, as UTF-8.
    pub config_id: &'a str,
    /// The blake3 of the driver written to `fgro`'s stdin, in lowercase hex.
    pub driver_blake3: &'a str,
    /// The trust root `fgro` must report as its project.
    pub trust_root: &'a Path,
}

/// What an envelope said, once it passed every check.
#[derive(Debug)]
pub enum Outcome {
    /// `ok: true`: the value, re-serialized with sorted keys, and its graph.
    Value {
        value_json: String,
        graph: Box<GraphDump>,
    },
    /// `ok: false`: the failure.
    Failed(EvalFailure),
}

/// An eval failure `fgro` reported (`ok: false`): the envelope's `error`.
///
/// `at`, `specifier`, `importer`, and `hint` are left out of the envelope when
/// fgro has none, never written as `null`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalFailure {
    /// The kind of failure, the contract to branch on.
    pub kind: EvalErrorKind,
    /// What failed, for a person: an uncaught error's report with its frames,
    /// or fgro's own message.
    pub message: String,
    /// The JS path to a value that didn't serialize (`$.a[2].b`), or the
    /// `url:line:column` of a load failure.
    #[serde(default, deserialize_with = "some")]
    pub at: Option<String>,
    /// The specifier of an import that failed: as written for a resolution,
    /// the resolved URL for a load.
    #[serde(default, deserialize_with = "some")]
    pub specifier: Option<String>,
    /// The URL of the module that imported it; for a config that didn't
    /// resolve, the working directory it was resolved from.
    #[serde(default, deserialize_with = "some")]
    pub importer: Option<String>,
    /// A fix fgro could tell, apart from the message.
    #[serde(default, deserialize_with = "some")]
    pub hint: Option<String>,
}

/// The envelope, protocol 2.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[expect(dead_code, reason = "checked by the version probe before this parse")]
    eval_protocol: u64,
    ok: bool,
    #[expect(dead_code, reason = "for display; the pin identifies the binary")]
    runtime: RuntimeInfo,
    entry: Entry,
    #[serde(default, deserialize_with = "present")]
    value: Field<serde_json::Value>,
    #[serde(default, deserialize_with = "present")]
    error: Field<EvalFailure>,
    #[serde(default, deserialize_with = "present")]
    access: Field<Option<Access>>,
    #[serde(default, deserialize_with = "present")]
    graph: Field<Option<GraphDump>>,
}

/// The runtime that evaluated, for display only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "parsed to hold the shape; not read")]
struct RuntimeInfo {
    fgro_version: String,
    #[serde(deserialize_with = "nullable")]
    commit: Option<String>,
    #[serde(deserialize_with = "nullable")]
    dirty: Option<bool>,
    v8: String,
    deno_core: String,
    tsv_rev: String,
}

/// What was evaluated.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    #[serde(deserialize_with = "nullable")]
    export: Option<String>,
    #[serde(deserialize_with = "nullable")]
    driver_blake3: Option<String>,
}

/// The export an envelope names when fgro failed before it read the driver:
/// its default, as though there were none.
const DEFAULT_EXPORT: &str = "default";

/// What the run tried to reach and was refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    #[expect(dead_code, reason = "parsed to hold the shape; not read")]
    dynamic: Vec<DynamicImport>,
}

/// A refused `import()`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "parsed to hold the shape; not read")]
struct DynamicImport {
    specifier: String,
    importer: String,
}

/// The versions alone, read before the full parse so a newer version is named
/// as one rather than as an unknown field.
#[derive(Deserialize)]
struct VersionProbe {
    #[serde(default)]
    eval_protocol: Option<IgnoredOrNumber>,
    #[serde(default)]
    graph: Option<GraphProbe>,
}

/// A graph's version alone.
#[derive(Deserialize)]
struct GraphProbe {
    #[serde(default)]
    graph_version: Option<IgnoredOrNumber>,
}

/// A field that should be a number: the number, or `None` for anything else.
struct IgnoredOrNumber(Option<u64>);

impl<'de> Deserialize<'de> for IgnoredOrNumber {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(Self(value.as_u64()))
    }
}

/// A field that may be missing, kept apart from one that is present as `null`.
#[derive(Default)]
enum Field<T> {
    /// Not in the object.
    #[default]
    Missing,
    /// In the object, with this value (`null` included, for an `Option`).
    Present(T),
}

impl<T> Field<T> {
    fn into_option(self) -> Option<T> {
        match self {
            Self::Missing => None,
            Self::Present(value) => Some(value),
        }
    }
}

/// [`Field::Present`] of a field's value, whatever it is, `null` included;
/// with `#[serde(default)]`, a missing field stays [`Field::Missing`].
fn present<'de, D, T>(deserializer: D) -> Result<Field<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Field::Present)
}

/// A field that must be present, its value `null` or not: without
/// `#[serde(default)]`, a missing one is an error, where serde reads a missing
/// `Option` as `None`.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// A field that may be left out but is never `null`: with `#[serde(default)]`,
/// missing is `None`, and `null` is an error.
fn some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Read `fgro eval`'s stdout as an envelope, given the code it exited with
/// (`0`, `1`, or `2`; any other is a crash, decided by the caller), and check
/// it against `expected`.
pub fn read_envelope(
    stdout: &[u8],
    code: i32,
    expected: &Expected<'_>,
) -> Result<Outcome, ProtocolViolation> {
    if stdout.is_empty() {
        return Err(ProtocolViolation::NoEnvelope);
    }
    let body = stdout.strip_suffix(b"\n").unwrap_or(stdout);
    // One object, compact, on one line: no whitespace around it, no line break
    // inside it (JSON strings escape theirs).
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.contains(&b'\n') {
        return Err(ProtocolViolation::NotOneObject);
    }

    let probe: VersionProbe =
        serde_json::from_slice(body).map_err(|_| ProtocolViolation::NotOneObject)?;
    let protocol = probe.eval_protocol.and_then(|version| version.0);
    if protocol != Some(EVAL_PROTOCOL) {
        return Err(ProtocolViolation::ProtocolVersion { found: protocol });
    }
    if let Some(graph) = probe.graph {
        let version = graph.graph_version.and_then(|version| version.0);
        if version != Some(GRAPH_VERSION) {
            return Err(ProtocolViolation::GraphVersion { found: version });
        }
    }

    let envelope: Envelope =
        serde_json::from_slice(body).map_err(|error| ProtocolViolation::Shape {
            reason: error.to_string(),
        })?;
    let value = envelope.value.into_option();
    let error = envelope.error.into_option();

    // the caller sorts any code but `0`, `1`, and `2` out as a crash
    if (code == 0) != envelope.ok {
        return Err(ProtocolViolation::ExitMismatch {
            code,
            ok: envelope.ok,
        });
    }
    match (&value, &error, envelope.ok) {
        (Some(_), None, true) | (None, Some(_), false) => {}
        _ => return Err(ProtocolViolation::ResultMismatch { ok: envelope.ok }),
    }
    if matches!(envelope.access, Field::Missing) {
        return Err(ProtocolViolation::AccessMissing);
    }
    if envelope.entry.id != expected.config_id {
        return Err(ProtocolViolation::EntryId {
            found: envelope.entry.id,
        });
    }
    // fgro names the default export and no driver hash when it failed before
    // reading the driver (an inherited descriptor it couldn't close, say): a
    // failure, which carries no value, so it is taken as the one it reports
    let driver_unread = !envelope.ok
        && envelope.entry.driver_blake3.is_none()
        && envelope.entry.export.as_deref() == Some(DEFAULT_EXPORT);
    if !driver_unread {
        if let Some(found) = envelope.entry.export {
            return Err(ProtocolViolation::EntryExport { found });
        }
        if envelope.entry.driver_blake3.as_deref() != Some(expected.driver_blake3) {
            return Err(ProtocolViolation::DriverBlake3 {
                expected: expected.driver_blake3.to_owned(),
                found: envelope.entry.driver_blake3,
            });
        }
    }
    let graph = envelope
        .graph
        .into_option()
        .ok_or(ProtocolViolation::GraphMissing)?;
    if let Some(graph) = &graph
        && Path::new(&graph.local.project) != expected.trust_root
    {
        return Err(ProtocolViolation::ProjectMismatch {
            trust_root: expected.trust_root.to_path_buf(),
            project: graph.local.project.clone(),
        });
    }

    match (value, error) {
        (Some(mut value), None) => {
            let graph = graph.ok_or(ProtocolViolation::GraphNullOnSuccess)?;
            // a value's cache is keyed on every module's bytes and format
            if let Some(module) = graph
                .modules
                .iter()
                .find(|module| module.blake3.is_none() || module.format.is_none())
            {
                return Err(ProtocolViolation::ModuleNotLoaded {
                    id: module.id.clone(),
                });
            }
            // sorted whatever `serde_json`'s map is compiled as, so the text is a
            // function of the value alone
            value.sort_all_objects();
            let value_json =
                serde_json::to_string(&value).map_err(|error| ProtocolViolation::Shape {
                    reason: error.to_string(),
                })?;
            Ok(Outcome::Value {
                value_json,
                graph: Box::new(graph),
            })
        }
        (None, Some(failure)) => Ok(Outcome::Failed(failure)),
        // checked above
        _ => Err(ProtocolViolation::ResultMismatch { ok: envelope.ok }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/p";
    const CONFIG: &str = "/p/zap.ts";

    fn driver_blake3() -> String {
        blake3::hash(b"driver").to_hex().to_string()
    }

    fn graph(project: &str) -> serde_json::Value {
        serde_json::json!({
            "graph_version": 1,
            "roots": ["project:zap.ts"],
            "modules": [{
                "id": "project:zap.ts",
                "blake3": "00",
                "origin": {"kind": "project"},
                "format": "typescript",
                "imports": [{"specifier": "@x/lib", "resolved": "linked:../lib/index.js", "reach": "static"}]
            }, {
                "id": "linked:../lib/index.js",
                "blake3": "22",
                "origin": {"kind": "package", "name": "@x/lib", "version": null, "linked": true},
                "format": "javascript",
                "imports": []
            }],
            "consulted": [{"id": "project:package.json", "blake3": "11", "role": "search_bound"}],
            "absent": ["project:node_modules/@x/lib"],
            "local": {"project": project, "box": [project, "/lib"], "paths": {"project:zap.ts": "/p/zap.ts"}}
        })
    }

    fn envelope() -> serde_json::Value {
        serde_json::json!({
            "eval_protocol": 2,
            "ok": true,
            "runtime": {"fgro_version": "0.0.0", "commit": null, "dirty": null, "v8": "x", "deno_core": "y", "tsv_rev": "z"},
            "entry": {"id": CONFIG, "export": null, "driver_blake3": driver_blake3()},
            "value": {"b": 1, "a": [{"d": null, "c": 2.5}]},
            "access": {"dynamic": []},
            "graph": graph(ROOT)
        })
    }

    fn failed(kind: &str) -> serde_json::Value {
        let mut envelope = envelope();
        let fields = envelope.as_object_mut().unwrap();
        fields.remove("value");
        fields.insert("ok".into(), false.into());
        fields.insert(
            "error".into(),
            serde_json::json!({"kind": kind, "message": "m", "hint": "h"}),
        );
        envelope
    }

    fn read(envelope: &serde_json::Value, code: i32) -> Result<Outcome, ProtocolViolation> {
        let mut bytes = serde_json::to_vec(envelope).unwrap();
        bytes.push(b'\n');
        read_bytes(&bytes, code)
    }

    fn read_bytes(bytes: &[u8], code: i32) -> Result<Outcome, ProtocolViolation> {
        let driver = driver_blake3();
        read_envelope(
            bytes,
            code,
            &Expected {
                config_id: CONFIG,
                driver_blake3: &driver,
                trust_root: Path::new(ROOT),
            },
        )
    }

    #[test]
    fn a_value_is_re_serialized_with_sorted_keys() {
        let Ok(Outcome::Value { value_json, graph }) = read(&envelope(), 0) else {
            panic!("expected a value");
        };
        assert_eq!(value_json, r#"{"a":[{"c":2.5,"d":null}],"b":1}"#);
        assert_eq!(graph.local.project, ROOT);
        assert_eq!(
            graph.modules[1].origin,
            DumpOrigin::Package {
                name: "@x/lib".into(),
                version: None,
                linked: true
            }
        );
        // with no trailing newline too
        let bytes = serde_json::to_vec(&envelope()).unwrap();
        assert!(matches!(read_bytes(&bytes, 0), Ok(Outcome::Value { .. })));
    }

    #[test]
    fn a_null_value_is_a_value() {
        let mut envelope = envelope();
        envelope["value"] = serde_json::Value::Null;
        let Ok(Outcome::Value { value_json, .. }) = read(&envelope, 0) else {
            panic!("expected a value");
        };
        assert_eq!(value_json, "null");
    }

    #[test]
    fn every_kind_is_read() {
        for kind in [
            EvalErrorKind::Resolve,
            EvalErrorKind::Link,
            EvalErrorKind::ModuleThrew,
            EvalErrorKind::ExportMissing,
            EvalErrorKind::Serialize,
            EvalErrorKind::LateRejection,
            EvalErrorKind::Heap,
            EvalErrorKind::Memory,
            EvalErrorKind::Timeout,
            EvalErrorKind::Environment,
            EvalErrorKind::Internal,
        ] {
            for code in [1, 2] {
                let Ok(Outcome::Failed(failure)) = read(&failed(kind.as_str()), code) else {
                    panic!("{kind}: expected a failure");
                };
                assert_eq!(failure.kind, kind);
                assert_eq!(failure.hint.as_deref(), Some("h"));
                assert_eq!(failure.at, None);
            }
        }
        assert!(matches!(
            read(&failed("grant_denied"), 1),
            Err(ProtocolViolation::Shape { .. })
        ));
    }

    #[test]
    fn a_failure_may_carry_a_null_graph() {
        let mut envelope = failed("resolve");
        envelope["graph"] = serde_json::Value::Null;
        assert!(matches!(read(&envelope, 2), Ok(Outcome::Failed(_))));
    }

    /// The envelopes fgro prepares before the run, for when the process runs
    /// out of memory, carry no `access` and a null graph.
    #[test]
    fn an_out_of_memory_envelope_is_the_failure_it_names() {
        for kind in [EvalErrorKind::Heap, EvalErrorKind::Memory] {
            let mut envelope = failed(kind.as_str());
            envelope["access"] = serde_json::Value::Null;
            envelope["graph"] = serde_json::Value::Null;
            let Ok(Outcome::Failed(failure)) = read(&envelope, 1) else {
                panic!("{kind}: expected a failure");
            };
            assert_eq!(failure.kind, kind);
        }
    }

    #[test]
    fn stdout_must_be_one_object_on_one_line() {
        let one = serde_json::to_string(&envelope()).unwrap();
        for bad in [
            String::new(),
            format!(" {one}"),
            format!("{one}\n\n"),
            format!("{one} "),
            format!("{one}\n{one}"),
            format!("{one}{one}"),
            "[]".to_owned(),
            serde_json::to_string_pretty(&envelope()).unwrap(),
        ] {
            let result = read_bytes(bad.as_bytes(), 0);
            assert!(
                matches!(
                    result,
                    Err(ProtocolViolation::NotOneObject | ProtocolViolation::NoEnvelope)
                ),
                "{bad:?}: {result:?}"
            );
        }
    }

    #[test]
    fn an_unknown_field_anywhere_is_refused() {
        let mut cases = Vec::new();
        for pointer in [
            "",
            "/runtime",
            "/entry",
            "/access",
            "/graph",
            "/graph/modules/0",
            "/graph/modules/0/origin",
            "/graph/modules/1/origin",
            "/graph/modules/0/imports/0",
            "/graph/consulted/0",
            "/graph/local",
        ] {
            let mut envelope = envelope();
            envelope
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), 1.into());
            cases.push((pointer.to_owned(), envelope));
        }
        let mut error = failed("link");
        error["error"]["extra"] = 1.into();
        cases.push(("/error".to_owned(), error));
        for (pointer, envelope) in cases {
            let code = i32::from(envelope["ok"] != true);
            let result = read(&envelope, code);
            assert!(
                matches!(&result, Err(ProtocolViolation::Shape { reason }) if reason.contains("extra")),
                "{pointer}: {result:?}"
            );
        }
    }

    /// Every field fgro always writes must be present, `null` or not; the
    /// failure's optional fields may be left out but are never `null`.
    #[test]
    fn a_field_fgro_always_writes_must_be_present() {
        for pointer in [
            "/entry/export",
            "/entry/driver_blake3",
            "/runtime/commit",
            "/runtime/dirty",
            "/graph/modules/0/blake3",
            "/graph/modules/0/format",
            "/graph/modules/1/origin/version",
        ] {
            let mut envelope = envelope();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            envelope
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                matches!(read(&envelope, 0), Err(ProtocolViolation::Shape { .. })),
                "{pointer}"
            );
        }
        let mut envelope = envelope();
        envelope["error"] = serde_json::Value::Null;
        assert!(
            matches!(read(&envelope, 0), Err(ProtocolViolation::Shape { .. })),
            "an ok envelope's null error"
        );
        for field in ["at", "specifier", "importer", "hint"] {
            let mut envelope = failed("link");
            envelope["error"][field] = serde_json::Value::Null;
            assert!(
                matches!(read(&envelope, 1), Err(ProtocolViolation::Shape { .. })),
                "{field}: null"
            );
        }
    }

    /// A value comes only with a graph whose every module loaded: a value's
    /// cache is keyed on each module's bytes and format.
    #[test]
    fn a_value_with_a_module_not_loaded_is_refused() {
        for field in ["blake3", "format"] {
            let mut envelope = envelope();
            envelope["graph"]["modules"][1][field] = serde_json::Value::Null;
            assert_eq!(
                read(&envelope, 0).unwrap_err(),
                ProtocolViolation::ModuleNotLoaded {
                    id: "linked:../lib/index.js".to_owned()
                },
                "{field}"
            );
            // a failure may name one: it says how far the run got
            let mut envelope = failed("link");
            envelope["graph"]["modules"][1][field] = serde_json::Value::Null;
            assert!(
                matches!(read(&envelope, 1), Ok(Outcome::Failed(_))),
                "{field}"
            );
        }
    }

    /// A failure before fgro read the driver names the default export and no
    /// driver hash, as gro's `failed()` writes it: taken as the failure it is,
    /// never as a value.
    #[test]
    fn a_failure_before_the_driver_was_read_is_the_failure() {
        let mut envelope = failed("environment");
        envelope["entry"]["export"] = "default".into();
        envelope["entry"]["driver_blake3"] = serde_json::Value::Null;
        envelope["graph"] = serde_json::Value::Null;
        let Ok(Outcome::Failed(failure)) = read(&envelope, 1) else {
            panic!("expected the failure");
        };
        assert_eq!(failure.kind, EvalErrorKind::Environment);
        // not with a hash, another export, or a value
        let mut hashed = envelope.clone();
        hashed["entry"]["driver_blake3"] = driver_blake3().into();
        assert!(matches!(
            read(&hashed, 1),
            Err(ProtocolViolation::EntryExport { .. })
        ));
        let mut other = envelope.clone();
        other["entry"]["export"] = "config".into();
        assert!(matches!(
            read(&other, 1),
            Err(ProtocolViolation::EntryExport { .. })
        ));
        let mut ok = self::envelope();
        ok["entry"]["export"] = "default".into();
        ok["entry"]["driver_blake3"] = serde_json::Value::Null;
        assert!(matches!(
            read(&ok, 0),
            Err(ProtocolViolation::EntryExport { .. })
        ));
    }

    #[test]
    fn an_origin_holds_exactly_its_variant_s_fields() {
        for origin in [
            serde_json::json!({"kind": "project", "name": "x"}),
            serde_json::json!({"kind": "package", "name": "x", "version": null}),
            serde_json::json!({"kind": "package", "name": "x", "linked": true}),
            serde_json::json!({"kind": "builtin"}),
            serde_json::json!({"name": "x"}),
        ] {
            let mut envelope = envelope();
            envelope["graph"]["modules"][0]["origin"] = origin.clone();
            assert!(
                matches!(read(&envelope, 0), Err(ProtocolViolation::Shape { .. })),
                "{origin}"
            );
        }
    }

    #[test]
    fn a_missing_field_is_refused() {
        for pointer in ["/runtime", "/entry", "/ok"] {
            let mut envelope = envelope();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            envelope
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                matches!(read(&envelope, 0), Err(ProtocolViolation::Shape { .. })),
                "{pointer}"
            );
        }
        let mut envelope = envelope();
        envelope.as_object_mut().unwrap().remove("access");
        assert_eq!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::AccessMissing
        );
        let mut envelope = self::envelope();
        envelope.as_object_mut().unwrap().remove("graph");
        assert_eq!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::GraphMissing
        );
        let mut envelope = self::envelope();
        envelope.as_object_mut().unwrap().remove("value");
        assert_eq!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::ResultMismatch { ok: true }
        );
    }

    #[test]
    fn versions_are_checked_before_the_shape() {
        let mut envelope = envelope();
        envelope["eval_protocol"] = 1.into();
        envelope["new_field"] = 1.into();
        assert_eq!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::ProtocolVersion { found: Some(1) }
        );
        envelope["eval_protocol"] = 3.into();
        assert_eq!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::ProtocolVersion { found: Some(3) }
        );
        envelope["eval_protocol"] = "2".into();
        assert_eq!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::ProtocolVersion { found: None }
        );
        let mut envelope = self::envelope();
        envelope["graph"]["graph_version"] = 2.into();
        envelope["graph"]["new_field"] = 1.into();
        assert_eq!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::GraphVersion { found: Some(2) }
        );
    }

    #[test]
    fn the_exit_code_must_agree_with_ok() {
        for code in [1, 2] {
            assert_eq!(
                read(&envelope(), code).unwrap_err(),
                ProtocolViolation::ExitMismatch { code, ok: true }
            );
        }
        assert_eq!(
            read(&failed("link"), 0).unwrap_err(),
            ProtocolViolation::ExitMismatch { code: 0, ok: false }
        );
        let mut both = envelope();
        both["error"] = serde_json::json!({"kind": "link", "message": "m"});
        assert_eq!(
            read(&both, 0).unwrap_err(),
            ProtocolViolation::ResultMismatch { ok: true }
        );
    }

    #[test]
    fn the_entry_must_be_the_one_sent() {
        let mut envelope = envelope();
        envelope["entry"]["id"] = "/p/other.ts".into();
        assert!(matches!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::EntryId { found } if found == "/p/other.ts"
        ));
        let mut envelope = self::envelope();
        envelope["entry"]["export"] = "default".into();
        assert!(matches!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::EntryExport { .. }
        ));
        for found in [serde_json::Value::Null, "ab".into()] {
            let mut envelope = self::envelope();
            envelope["entry"]["driver_blake3"] = found;
            assert!(matches!(
                read(&envelope, 0).unwrap_err(),
                ProtocolViolation::DriverBlake3 { .. }
            ));
        }
    }

    #[test]
    fn the_graph_must_be_the_trust_root_s() {
        let mut envelope = envelope();
        envelope["graph"] = graph("/");
        assert!(matches!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::ProjectMismatch { project, .. } if project == "/"
        ));
        let mut envelope = failed("module_threw");
        envelope["graph"] = graph("/elsewhere");
        assert!(matches!(
            read(&envelope, 1).unwrap_err(),
            ProtocolViolation::ProjectMismatch { .. }
        ));
        let mut envelope = self::envelope();
        envelope["graph"] = serde_json::Value::Null;
        assert_eq!(
            read(&envelope, 0).unwrap_err(),
            ProtocolViolation::GraphNullOnSuccess
        );
    }

    #[test]
    fn a_violation_quotes_what_fgro_wrote_escaped() {
        let message = ProtocolViolation::EntryId {
            found: "/p/\u{1b}[31mx\n".to_owned(),
        }
        .to_string();
        assert!(
            !message.contains('\u{1b}') && !message.contains('\n'),
            "{message}"
        );
    }
}
