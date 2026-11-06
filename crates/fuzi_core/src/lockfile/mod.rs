//! The `package-lock.json` reader: lenient raw deserialization plus the
//! version gate. Kept inline in `fuzi_core` until a pnpm reader exists — the
//! format seam is the `crate::plan::InstallPlan` output type, not a trait.

pub mod raw;
pub mod reader;

pub use raw::{KNOWN_INERT_ENTRY_FIELDS, RawLockfile, RawPackageEntry, unknown_entry_fields};
pub use reader::{parse_lockfile, read_lockfile};
