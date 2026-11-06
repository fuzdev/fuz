//! Storage-key layout for releases.
//!
//! Single source of truth for the on-storage wire layout shared by publish,
//! fetch, and per-tool install (and, ahead, the forge-serving half). Two
//! shapes share one scheme, differing only by key prefix:
//!
//! ```text
//! self (prefix "")                  tool (prefix "tools/<name>/")
//!   latest-<target>.json              tools/<name>/latest-<target>.json
//!   fuz-<ver>-<target>.manifest.json  tools/<name>/<name>-<ver>-<target>.manifest.json
//!   fuz-<ver>-<target>.tar.gz        tools/<name>/<name>-<ver>-<target>.tar.gz
//!   fuz-<ver>-<target>                (self only: the flat binary)
//!   fuz-latest-<target>               (self only: its moving copy)
//! ```
//!
//! Every key is per target, the `latest` pointer included: publishing one
//! target never moves another's.

/// Storage-key namer for one release stream.
#[derive(Debug, Clone)]
pub struct ReleaseLayout {
    prefix: String,
}

impl ReleaseLayout {
    /// Layout for the fuz *self* artifact: keys live at the storage root.
    #[must_use]
    pub const fn self_artifact() -> Self {
        Self {
            prefix: String::new(),
        }
    }

    /// Layout for a per-tool artifact under `tools/<name>/`.
    #[must_use]
    pub fn tool(name: &str) -> Self {
        Self {
            prefix: format!("tools/{name}/"),
        }
    }

    /// The storage-key prefix for this stream (`""` for self, `tools/<name>/`
    /// for a tool) — the list-prefix a producer sweeps to enumerate the stream's
    /// keys.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Key of the version pointer for `target`: `latest-<target>.json`.
    ///
    /// One per target, so a publish for one target moves only its own
    /// pointer, and a client resolves the latest release *for its own
    /// target* — never a version published for another one alone.
    #[must_use]
    pub fn latest_key(&self, target: &str) -> String {
        format!("{}latest-{target}.json", self.prefix)
    }

    /// The target a key names if it is one of this stream's version pointers
    /// (`<prefix>latest-<target>.json`), else `None`. The reverse of
    /// [`Self::latest_key`], for a producer that lists the stream.
    #[must_use]
    pub fn latest_key_target<'a>(&self, key: &'a str) -> Option<&'a str> {
        key.strip_prefix(self.prefix.as_str())?
            .strip_prefix("latest-")?
            .strip_suffix(".json")
            .filter(|target| !target.is_empty() && !target.contains('/'))
    }

    /// Key of the signed manifest for `name` at `version`/`target`.
    ///
    /// `name` is the binary basename embedded in the filename — `"fuz"` for the
    /// self artifact, the tool name for a tool.
    #[must_use]
    pub fn manifest_key(&self, name: &str, version: &str, target: &str) -> String {
        format!("{}{name}-{version}-{target}.manifest.json", self.prefix)
    }

    /// Key of a tarball, given its manifest-declared filename.
    #[must_use]
    pub fn tarball_key(&self, filename: &str) -> String {
        format!("{}{filename}", self.prefix)
    }

    /// The filename a publish gives the tarball of `name` at
    /// `version`/`target` (`<name>-<version>-<target>.tar.gz`), which its
    /// manifest's `tarball.path` names. A producer that deletes a release's
    /// tarball derives its key from this, never from the unsigned field.
    #[must_use]
    pub fn tarball_filename(name: &str, version: &str, target: &str) -> String {
        format!("{name}-{version}-{target}.tar.gz")
    }

    /// Key of the flat (untarred) binary for `name` at `version`/`target` —
    /// the file the shell installer downloads, and the filename its `.sha512`
    /// sidecar names. Only the self artifact publishes one.
    #[must_use]
    pub fn binary_key(&self, name: &str, version: &str, target: &str) -> String {
        format!("{}{name}-{version}-{target}", self.prefix)
    }

    /// Key of the flat binary's moving `latest` copy for `name`/`target`.
    #[must_use]
    pub fn latest_binary_key(&self, name: &str, target: &str) -> String {
        format!("{}{name}-latest-{target}", self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_layout_keys_at_root() {
        let layout = ReleaseLayout::self_artifact();
        assert_eq!(
            layout.latest_key("x86_64-unknown-linux-gnu"),
            "latest-x86_64-unknown-linux-gnu.json"
        );
        assert_eq!(
            layout.latest_key_target("latest-x86_64-unknown-linux-gnu.json"),
            Some("x86_64-unknown-linux-gnu")
        );
        for other in [
            "latest.json",
            "latest-.json",
            "tools/fuzf/latest-x86_64-unknown-linux-gnu.json",
            "fuz-latest-x86_64-unknown-linux-gnu",
        ] {
            assert_eq!(layout.latest_key_target(other), None, "{other}");
        }
        assert_eq!(
            layout.manifest_key("fuz", "0.2.0", "x86_64-unknown-linux-gnu"),
            "fuz-0.2.0-x86_64-unknown-linux-gnu.manifest.json"
        );
        assert_eq!(
            layout.tarball_key("fuz-0.2.0-x86_64-unknown-linux-gnu.tar.gz"),
            "fuz-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            layout.binary_key("fuz", "0.2.0", "x86_64-unknown-linux-gnu"),
            "fuz-0.2.0-x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            layout.latest_binary_key("fuz", "x86_64-unknown-linux-gnu"),
            "fuz-latest-x86_64-unknown-linux-gnu"
        );
    }

    #[test]
    fn tool_layout_keys_under_prefix() {
        let layout = ReleaseLayout::tool("fuzf");
        assert_eq!(
            layout.latest_key("aarch64-unknown-linux-musl"),
            "tools/fuzf/latest-aarch64-unknown-linux-musl.json"
        );
        assert_eq!(
            layout.latest_key_target("tools/fuzf/latest-aarch64-unknown-linux-musl.json"),
            Some("aarch64-unknown-linux-musl")
        );
        assert_eq!(
            layout.latest_key_target("tools/fuzd/latest-aarch64-unknown-linux-musl.json"),
            None
        );
        assert_eq!(
            layout.manifest_key("fuzf", "0.1.0", "x86_64-unknown-linux-gnu"),
            "tools/fuzf/fuzf-0.1.0-x86_64-unknown-linux-gnu.manifest.json"
        );
        assert_eq!(
            layout.tarball_key("fuzf-0.1.0-x86_64-unknown-linux-gnu.tar.gz"),
            "tools/fuzf/fuzf-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            ReleaseLayout::tarball_filename("fuzf", "0.1.0", "x86_64-unknown-linux-gnu"),
            "fuzf-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
        );
    }
}
