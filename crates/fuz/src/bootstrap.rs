//! Bootstrap command - self-install of the fuz binary as an artifact.
//!
//! This is the entry point used by the install script (intended one-liner, not
//! hosted yet):
//!
//! ```sh
//! curl -sSf https://www.fuz.dev/install.sh | sh
//! ```
//!
//! The script downloads the fuz binary, marks it executable, then runs
//! `./fuz self bootstrap`. Bootstrap creates a full artifact directory
//! (`~/.fuz/artifacts/v1-<hash>/`) containing the running binary and a
//! `meta.json`, points `~/.fuz/current` at it, sets up
//! `~/.fuz/bin/fuz -> ../current/fuz`, then optionally edits the user's
//! shell rc file to add the bin dir to PATH (`~/.fuz` throughout is the
//! default; `FUZ_HOME` relocates it, and the rc line names the real bin dir).
//!
//! Bootstrap-installed artifacts contain only the `fuz` binary
//! (no `fuzd`) — they're marked with `source: "bootstrap"` in meta.json
//! so `fuz self status` and `fuz artifact list` can treat them appropriately.
//!
//! When `FUZ_RELEASE_LOG_URL` names a witness, the binary is held to the
//! release log before any of that happens: the log must record this version
//! for this target with the BLAKE3 of the bytes being installed. A binary the
//! log revokes, does not record, or records with another hash is not installed,
//! and the shell rc file is not touched. What a refusal leaves behind is the
//! empty home skeleton `ensure_fuz_home` makes, and the cached head when a
//! witness answered. See `crate::release_log`.

use argh::FromArgs;
use fuz_artifact::{
    ArtifactMeta, BuildSource, ContentHash, acquire_artifact_lock, cleanup_incomplete,
    create_artifact, get_current_artifact, record_switch, setup_bin_symlinks, switch_current,
};
use fuz_home::ensure_fuz_home;
use fuz_release::{LocalSelfBinary, check_bootstrap_binary};
use fuz_sys::collapse_tilde;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

use crate::CliError;
use crate::release::ReleaseCommandError;

/// Permissions for shell rc files we create. An rc that already exists keeps
/// its own permission bits.
const RC_FILE_MODE: u32 = 0o644;

/// Permissions for the directories we create above a new rc file (fish's
/// `~/.config` and `~/.config/fish`) — what desktop stacks create `~/.config`
/// at, rather than whatever the umask leaves. Existing directories keep theirs.
const RC_DIR_MODE: u32 = 0o700;

/// The permission bits of a mode, without the file-type bits.
const MODE_PERMISSION_BITS: u32 = 0o7777;

/// The owner-write permission bit.
const MODE_OWNER_WRITE: u32 = 0o200;

/// Begin marker for our managed block in rc files
const RC_BEGIN_MARKER: &str = "# >>> fuz initialize >>>";

/// End marker for our managed block in rc files
const RC_END_MARKER: &str = "# <<< fuz initialize <<<";

/// Errors specific to the bootstrap command
// Every variant ends in `Failed` by design — these are all "operation X
// failed" cases, and the suffix reads naturally at the construction sites
// (`map_err(BootstrapError::CurrentExeFailed)`). Dropping it would make
// `BootstrapError::CurrentExe` less clear, not more.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Could not resolve the running executable's path
    #[error("failed to resolve current executable")]
    CurrentExeFailed(#[source] std::io::Error),

    /// Could not read the running fuz binary
    #[error("failed to read fuz binary at {path}")]
    ReadBinaryFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to update a shell rc file (read or write)
    #[error("failed to update shell config at {path}")]
    UpdateShellRcFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

//
// CLI args
//

/// Self-install fuz to ~/.fuz/bin and update shell PATH.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "bootstrap")]
pub struct Bootstrap {
    /// don't modify shell config files
    #[argh(switch)]
    pub no_modify_path: bool,

    /// suppress success output and the PATH-setup notes (release log warnings still print)
    #[argh(switch, short = 'q')]
    pub quiet: bool,
}

//
// Command entry point
//

/// Handle `fuz self bootstrap`
pub async fn cmd_bootstrap(args: &Bootstrap) -> Result<(), CliError> {
    // 0. The release log policy, before anything is read or created: a
    //    configuration the check cannot run under leaves the machine as it was.
    let release_log = crate::release_log::policy_from_env()?;

    // 1. Resolve self
    let self_path = std::env::current_exe().map_err(BootstrapError::CurrentExeFailed)?;

    // 2. Read binary into memory
    let bytes = fs::read(&self_path).map_err(|source| BootstrapError::ReadBinaryFailed {
        path: self_path.clone(),
        source,
    })?;

    // 3. Ensure ~/.fuz/ exists with secure perms
    ensure_fuz_home()?;

    // 3b. Hold this binary to the release log. After the home exists with
    //     safe modes — the check caches the head under it — and before the
    //     lock, the artifact, `current`, `bin/`, and the shell rc: a refusal
    //     installs nothing. The hash is of `bytes`, the very buffer step 7
    //     writes into the artifact, so what is confirmed is what is installed.
    let version = env!("CARGO_PKG_VERSION");
    crate::release_log::warn_if_revoked(
        &release_log,
        crate::release_log::reported_version(get_current_artifact().ok().flatten().as_ref()),
    );
    let binary = LocalSelfBinary::new(version, ContentHash::blake3(&bytes));
    let log_check = check_bootstrap_binary(&release_log, &binary)
        .await
        .map_err(ReleaseCommandError::Release)?;
    crate::release_log::render(&log_check, args.quiet);

    // 4. Acquire the artifact lock so we don't race a concurrent
    //    build/use/upgrade/bootstrap. The lock also gates
    //    `cleanup_incomplete` below — without it, bootstrap could remove a
    //    live `.building-*` dir from an in-progress build.
    let _lock = acquire_artifact_lock().map_err(CliError::Artifact)?;

    // 5. Sweep stale .building-* / .bootstrapping-* dirs from a previous crash.
    //    Best-effort: a partial sweep shouldn't block the install, since
    //    create_bootstrap_artifact uses its own random temp suffix.
    if let Ok(swept) = cleanup_incomplete()
        && swept > 0
        && !args.quiet
    {
        eprintln!("cleaned up {swept} incomplete artifact dir(s) from prior runs");
    }

    // 6. Capture the previously-current artifact (if any) so we can describe
    //    the install scenario in the success message.
    let previous = get_current_artifact().ok().flatten();

    // 7. Create artifact, switch current, set up bin symlinks
    let meta = install_as_artifact(&bytes, version)?;

    let scenario = InstallScenario::derive(previous.as_ref(), &meta);

    // 7b. Record the switch in history — but only when something actually
    //     changed. A no-op re-run (identical content hash) must not append a
    //     duplicate entry: `history.previous()` (backing `artifact use -`) reads
    //     entries by position, so a duplicate would make `use -` toggle to the
    //     same artifact. Thread the real previous hash (like `artifact use`
    //     does) so `fuz artifact log` shows what this replaced/upgraded.
    //     Recorded here, after the install is fully in place, so a
    //     half-installed bootstrap never shows up in the log.
    if !matches!(scenario, InstallScenario::AlreadyInstalled) {
        let previous_hash = previous.as_ref().map(|m| m.hash.as_str());
        record_switch(&meta.hash, &meta.version, previous_hash).map_err(CliError::Artifact)?;
    }

    // 8. Optionally edit shell rc. PATH setup is best-effort: the artifact is
    //    already installed and runnable from the bin dir, so a shell we can't
    //    detect or an rc we can't write only costs the PATH convenience — it
    //    prints a manual-PATH note and never fails the install.
    let path_setup = if args.no_modify_path {
        PathSetup::Skipped
    } else {
        modify_path(detect_shell(), args.quiet)
    };

    // 9. Success message
    if !args.quiet {
        print_success(&meta, path_setup, &scenario);
    }

    Ok(())
}

/// How this bootstrap relates to what was previously installed.
#[derive(Debug, Clone)]
enum InstallScenario {
    /// First fuz on this machine (no previous current artifact).
    Fresh,
    /// Same version, same content hash — idempotent re-run.
    AlreadyInstalled,
    /// Same version, different content hash (rebuild, different commit, etc.).
    ReplacedSameVersion { previous_version: String },
    /// Version changed (upgrade or downgrade).
    VersionChanged { previous_version: String },
}

impl InstallScenario {
    fn derive(previous: Option<&ArtifactMeta>, new: &ArtifactMeta) -> Self {
        let Some(prev) = previous else {
            return Self::Fresh;
        };
        if prev.hash == new.hash {
            Self::AlreadyInstalled
        } else if prev.version == new.version {
            Self::ReplacedSameVersion {
                previous_version: prev.version.clone(),
            }
        } else {
            Self::VersionChanged {
                previous_version: prev.version.clone(),
            }
        }
    }
}

//
// Artifact installation
//

/// Create a bootstrap artifact from the running binary, point `current` at it,
/// and set up `bin/fuz`.
///
/// History recording is the caller's job — it needs the previous artifact and
/// the derived [`InstallScenario`] to record accurately (and to skip the record
/// entirely on an idempotent re-run).
fn install_as_artifact(bytes: &[u8], version: &str) -> Result<ArtifactMeta, CliError> {
    let meta = create_artifact(version, BuildSource::Bootstrap { fuz_bytes: bytes })
        .map_err(CliError::Artifact)?;
    switch_current(&meta.hash).map_err(CliError::Artifact)?;
    setup_bin_symlinks(&["fuz"]).map_err(CliError::Artifact)?;
    Ok(meta)
}

//
// Shell detection and rc-file editing
//

/// Shells we know how to configure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    /// Default rc file path relative to `$HOME`
    const fn rc_relative_path(self) -> &'static str {
        match self {
            Self::Bash => ".bashrc",
            Self::Zsh => ".zshrc",
            Self::Fish => ".config/fish/config.fish",
        }
    }

    /// PATH line to write inside the marker block, naming `bin_dir`.
    ///
    /// `fish_add_path_supported` is consulted only for the Fish arm. When fish
    /// is older than 3.2.0 (Feb 2021) it lacks `fish_add_path`, and we fall
    /// back to `set -gx PATH` instead.
    fn path_line(self, bin_dir: &RcBinDir, fish_add_path_supported: bool) -> String {
        match self {
            Self::Bash | Self::Zsh => bin_dir.posix_path_line(),
            // `fish_add_path` prepends to the universal `fish_user_paths`
            // variable, which fish persists outside the rc file. The block is
            // therefore not the whole PATH state: a directory an earlier block
            // added stays on PATH until the user removes it from
            // `fish_user_paths`.
            Self::Fish if fish_add_path_supported => bin_dir.fish_add_path_line(),
            Self::Fish => bin_dir.fish_set_path_line(),
        }
    }

    /// Whether `line` is one [`Self::path_line`] writes for this shell, for
    /// some bin dir — the test a block's line must pass before fuz replaces
    /// it. A line in another shell's syntax is not this shell's: fuz never
    /// wrote a bash line into a fish config.
    fn recognizes_path_line(self, line: &str) -> bool {
        match self {
            Self::Bash | Self::Zsh => rc_bin_dir::is_posix_path_line(line),
            Self::Fish => rc_bin_dir::is_fish_path_line(line),
        }
    }

    /// The other line that puts `bin_dir` on PATH just as correctly as
    /// [`Self::path_line`], if the shell has one.
    ///
    /// Fish has two forms and either works on any fish that understands it, so
    /// a block already holding the one `path_line` did not pick is left alone:
    /// which form gets picked can change between runs (fish upgraded across
    /// the `fish_add_path` boundary, or `fish` missing from PATH on a re-run),
    /// and that is no reason to rewrite a working rc.
    fn equivalent_path_line(
        self,
        bin_dir: &RcBinDir,
        fish_add_path_supported: bool,
    ) -> Option<String> {
        match self {
            Self::Bash | Self::Zsh => None,
            Self::Fish => Some(self.path_line(bin_dir, !fish_add_path_supported)),
        }
    }
}

mod rc_bin_dir {
    //! The bin dir in the only form that reaches a shell rc file, the PATH
    //! lines built from it, and the recognizers that tell such a line from
    //! anything else.

    use std::path::{Component, Path};

    use fuz_sys::strip_home;
    use thiserror::Error;

    /// What surrounds the bin dir in the POSIX-shell PATH line.
    const POSIX_LINE_PREFIX: &str = "export PATH=\"";
    const POSIX_LINE_SUFFIX: &str = ":$PATH\"";
    /// How a home-relative bin dir starts in a POSIX-shell line.
    const POSIX_HOME_PREFIX: &str = "$HOME/";

    /// What surrounds the bin dir in fish's two PATH lines.
    const FISH_ADD_PATH_PREFIX: &str = "fish_add_path ";
    const FISH_SET_PATH_PREFIX: &str = "set -gx PATH ";
    const FISH_SET_PATH_SUFFIX: &str = " $PATH";
    /// How a home-relative bin dir starts in a fish line.
    const FISH_HOME_PREFIX: &str = "~/";

    /// Why a bin dir has no rendering that is safe to put in a shell rc file.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
    pub(super) enum RcBinDirError {
        /// The fuz home (and so its bin dir) could not be resolved.
        #[error("the fuz home could not be resolved")]
        Unresolved,
        /// A relative PATH entry would resolve against each shell's cwd.
        /// `fuz_home::get_fuz_home` already refuses a relative `FUZ_HOME`, so
        /// this is the validator's own floor rather than a path bootstrap
        /// reaches today.
        #[error("its path is relative")]
        Relative,
        /// Not representable as rc-file text at all.
        #[error("its path is not valid UTF-8")]
        NotUtf8,
        /// Carries a character a shell could interpret.
        #[error("its path has characters outside [A-Za-z0-9_./+-]")]
        UnsafeChars,
    }

    impl RcBinDirError {
        /// What the user does about it. No amount of quoting makes a relative
        /// PATH entry right, so its remedy is an absolute fuz home; the other
        /// unrenderable paths work once quoted by hand.
        pub(super) const fn advice(self) -> &'static str {
            match self {
                Self::Unresolved => {
                    "set FUZ_HOME (or HOME) to an absolute path, then re-run 'fuz self bootstrap'."
                }
                Self::Relative => {
                    "set FUZ_HOME to an absolute path (or fix a relative HOME), then re-run \
                     'fuz self bootstrap'."
                }
                Self::NotUtf8 | Self::UnsafeChars => {
                    "add that directory to your PATH manually, quoting it for your shell."
                }
            }
        }
    }

    /// A bin dir validated for interpolation into a shell rc line.
    ///
    /// The only constructor is [`RcBinDir::new`], so every PATH line the rc
    /// writer and the manual notes build names a path that needs no quoting or
    /// escaping in bash, zsh, or fish — a path that would is not representable,
    /// and the caller falls back to manual instructions without printing a
    /// line.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct RcBinDir {
        /// The interpolated text: the remainder below `$HOME` when
        /// `home_relative`, else the whole absolute path. Charset-checked.
        text: String,
        home_relative: bool,
    }

    impl RcBinDir {
        /// Validate `bin_dir` against `home` (the `$HOME` the rc file's shell
        /// will expand; `None` when unset).
        ///
        /// A bin dir under `home` — `fuz_sys::strip_home`'s lexical,
        /// component-wise notion, the one `collapse_tilde` displays with — is
        /// kept home-relative, so the line reads `$HOME/…` / `~/…` and survives
        /// the home directory moving. Only the remainder is then interpolated,
        /// and only it is charset-checked: the shell expands `$HOME` (inside
        /// double quotes) and `~` itself, without re-splitting the result, so
        /// an unusual home directory name never reaches the rc file as text.
        /// Anything else is written absolute and checked whole.
        ///
        /// A `home` the shell could not anchor a path to counts as no home: a
        /// relative one, and one with no named component (`/`), under which
        /// every absolute path sits and `$HOME/opt/fuz/bin` would expand to
        /// `//opt/fuz/bin`.
        pub(super) fn new(bin_dir: &Path, home: Option<&Path>) -> Result<Self, RcBinDirError> {
            let home = home.filter(|home| {
                home.is_absolute()
                    && home
                        .components()
                        .any(|component| matches!(component, Component::Normal(_)))
            });
            let below_home =
                strip_home(bin_dir, home).filter(|relative| !relative.as_os_str().is_empty());
            let (part, home_relative) = match below_home {
                Some(relative) => (relative, true),
                None if bin_dir.is_absolute() => (bin_dir, false),
                None => return Err(RcBinDirError::Relative),
            };
            let text = part.to_str().ok_or(RcBinDirError::NotUtf8)?;
            if !text.bytes().all(is_rc_safe_byte) {
                return Err(RcBinDirError::UnsafeChars);
            }
            Ok(Self {
                text: text.to_owned(),
                home_relative,
            })
        }

        /// Rendering for a POSIX shell, valid inside double quotes.
        pub(super) fn posix(&self) -> String {
            if self.home_relative {
                format!("{POSIX_HOME_PREFIX}{}", self.text)
            } else {
                self.text.clone()
            }
        }

        /// Rendering for fish, as a bare (unquoted) word.
        pub(super) fn fish(&self) -> String {
            if self.home_relative {
                format!("{FISH_HOME_PREFIX}{}", self.text)
            } else {
                self.text.clone()
            }
        }

        /// The POSIX-shell PATH line — what bash and zsh rc files get, and
        /// what the unknown-shell note suggests.
        pub(super) fn posix_path_line(&self) -> String {
            format!("{POSIX_LINE_PREFIX}{}{POSIX_LINE_SUFFIX}", self.posix())
        }

        /// The fish PATH line for a fish that has `fish_add_path`.
        pub(super) fn fish_add_path_line(&self) -> String {
            format!("{FISH_ADD_PATH_PREFIX}{}", self.fish())
        }

        /// The fish PATH line for a fish without `fish_add_path`.
        pub(super) fn fish_set_path_line(&self) -> String {
            format!(
                "{FISH_SET_PATH_PREFIX}{}{FISH_SET_PATH_SUFFIX}",
                self.fish()
            )
        }
    }

    /// Whether `line` is exactly what [`RcBinDir::posix_path_line`] renders
    /// for some bin dir. Any other text — a different command, trailing words
    /// or a comment, an empty or unsafe directory — is not a line fuz wrote.
    pub(super) fn is_posix_path_line(line: &str) -> bool {
        line.strip_prefix(POSIX_LINE_PREFIX)
            .and_then(|rest| rest.strip_suffix(POSIX_LINE_SUFFIX))
            .is_some_and(|dir| is_rendered_dir(dir, POSIX_HOME_PREFIX))
    }

    /// Whether `line` is exactly what [`RcBinDir::fish_add_path_line`] or
    /// [`RcBinDir::fish_set_path_line`] renders for some bin dir.
    pub(super) fn is_fish_path_line(line: &str) -> bool {
        line.strip_prefix(FISH_ADD_PATH_PREFIX)
            .or_else(|| {
                line.strip_prefix(FISH_SET_PATH_PREFIX)
                    .and_then(|rest| rest.strip_suffix(FISH_SET_PATH_SUFFIX))
            })
            .is_some_and(|dir| is_rendered_dir(dir, FISH_HOME_PREFIX))
    }

    /// Whether `dir` is a rendering of some [`RcBinDir`]: charset-safe text
    /// that is either absolute, or `home_prefix` followed by a relative
    /// remainder — the two shapes [`RcBinDir::new`] produces.
    fn is_rendered_dir(dir: &str, home_prefix: &str) -> bool {
        let (text, home_relative) = dir
            .strip_prefix(home_prefix)
            .map_or((dir, false), |rest| (rest, true));
        !text.is_empty()
            && text.bytes().all(is_rc_safe_byte)
            && text.starts_with('/') != home_relative
    }

    /// The conservative charset: no whitespace, quote, `$`, backtick, glob,
    /// `~`, `:` (the PATH separator), or control character can appear.
    const fn is_rc_safe_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b'+' | b'-')
    }
}

use rc_bin_dir::{RcBinDir, RcBinDirError};

/// Minimum fish version that ships `fish_add_path` (Feb 2021).
const FISH_ADD_PATH_MIN: (u32, u32) = (3, 2);

/// Detect whether the user's fish binary supports `fish_add_path`.
///
/// Returns `true` if `fish --version` reports >= 3.2.0, or if detection
/// fails for any reason (fish missing from PATH, unexpected output, etc.).
/// The optimistic default is intentional: 3.2.0 shipped in Feb 2021 — most
/// fish users are well past it — and the worst-case downside of the modern
/// syntax on an old fish is a clear error the user can read and fix, whereas
/// emitting the legacy form for everyone clutters modern rc files.
fn fish_supports_add_path() -> bool {
    let Ok(output) = Command::new("fish").arg("--version").output() else {
        return true;
    };
    if !output.status.success() {
        return true;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_fish_version(&stdout).is_none_or(|(major, minor)| (major, minor) >= FISH_ADD_PATH_MIN)
}

/// Parse "fish, version 3.6.1" → `(3, 6)`. Returns None if format is unexpected.
fn parse_fish_version(s: &str) -> Option<(u32, u32)> {
    // Look for the first token shaped like "<digits>.<digits>" on the first
    // non-empty line. Avoids brittle splitting on the whole "fish, version X.Y.Z" string.
    for line in s.lines() {
        for word in line.split_whitespace() {
            let mut parts = word.split('.');
            let (Some(maj), Some(min)) = (parts.next(), parts.next()) else {
                continue;
            };
            if let (Ok(maj), Ok(min)) = (maj.parse::<u32>(), min.parse::<u32>()) {
                return Some((maj, min));
            }
        }
    }
    None
}

/// Detect the user's shell from `$SHELL`. Returns `None` for unknown shells.
fn detect_shell() -> Option<Shell> {
    let shell = std::env::var("SHELL").ok()?;
    parse_shell(&shell)
}

/// Parse a `$SHELL`-style path into a known [`Shell`].
fn parse_shell(shell_path: &str) -> Option<Shell> {
    let name = Path::new(shell_path).file_name()?.to_str()?;
    match name {
        "bash" => Some(Shell::Bash),
        "zsh" => Some(Shell::Zsh),
        "fish" => Some(Shell::Fish),
        _ => None,
    }
}

/// Build the full marker block (begin marker, path line, end marker).
fn rc_block(path_line: &str) -> String {
    format!("{RC_BEGIN_MARKER}\n{path_line}\n{RC_END_MARKER}\n")
}

/// Outcome of the best-effort PATH-setup step.
///
/// PATH modification never fails the install — by the time it runs the artifact
/// is already in place — but the success message needs to know what actually
/// happened to print correct next-steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathSetup {
    /// `--no-modify-path`: the user opted out.
    Skipped,
    /// The detected shell's rc gained our managed block.
    Added(Shell),
    /// The rc's managed block named a different PATH line and was rewritten.
    Updated(Shell),
    /// The rc already carried a block putting the bin dir on PATH; untouched.
    AlreadyPresent(Shell),
    /// The detected shell's rc exists in a state fuz won't write to (see
    /// [`RcUntouched`]); untouched. A note — the reason and the line to add by
    /// hand — was already printed.
    LeftUnchanged(Shell),
    /// No rc could be edited (unknown shell, no usable `$HOME`, a bin dir that
    /// can't be written safely, or an I/O error). A manual note — with the
    /// reason — was already printed.
    Manual,
}

/// Best-effort PATH setup: put the fuz bin dir on PATH in the detected shell's
/// rc file.
///
/// **Never fails the install.** The artifact is already installed and runnable
/// from the bin dir by the time this runs, so an undetectable shell, a missing
/// `$HOME`, a bin dir with no safe rendering, an rc fuz won't write to, or an
/// unreadable/unwritable rc only costs the PATH convenience. Any such case
/// prints a manual note (with the reason) and returns [`PathSetup::Manual`] or
/// [`PathSetup::LeftUnchanged`] rather than aborting — how rustup treats
/// profile edits.
fn modify_path(shell: Option<Shell>, quiet: bool) -> PathSetup {
    // An empty or relative `$HOME` is an error here, not a path: either would
    // join to an rc path under the process cwd.
    let home = fuz_sys::home_dir();

    // Every line below — written or merely suggested — is built from this
    // value, so a path that isn't safe to interpolate produces no line at all.
    let bin_dir = match fuz_home::get_bin_dir()
        .map_err(|_| RcBinDirError::Unresolved)
        .and_then(|dir| RcBinDir::new(&dir, home.as_deref().ok()))
    {
        Ok(bin_dir) => bin_dir,
        Err(reason) => {
            if !quiet {
                eprintln!(
                    "note: not editing your shell config for {}: {reason}.",
                    display_bin_dir()
                );
                eprintln!("  {}", reason.advice());
            }
            return PathSetup::Manual;
        }
    };

    let Some(shell) = shell else {
        if !quiet {
            eprintln!("note: couldn't detect your shell. Add this to your shell's startup file:");
            eprintln!("  {}", bin_dir.posix_path_line());
        }
        return PathSetup::Manual;
    };

    let home = match home {
        Ok(home) => home,
        Err(reason) => {
            if !quiet {
                eprintln!(
                    "note: skipping shell config: {reason}. Add {} to your PATH manually.",
                    display_bin_dir()
                );
            }
            return PathSetup::Manual;
        }
    };

    let rc_path = home.join(shell.rc_relative_path());

    // Only probe fish version when we actually need it; bash/zsh don't care.
    let fish_add_path_supported = if matches!(shell, Shell::Fish) {
        fish_supports_add_path()
    } else {
        true
    };
    let path_line = shell.path_line(&bin_dir, fish_add_path_supported);
    let equivalent_line = shell.equivalent_path_line(&bin_dir, fish_add_path_supported);

    let print_manual = || {
        eprintln!("  add {} to your PATH manually:", display_bin_dir());
        eprintln!("    {path_line}");
    };

    match update_rc_file(&rc_path, shell, &path_line, equivalent_line.as_deref()) {
        Ok(RcUpdate::Added) => {
            if !quiet {
                eprintln!(
                    "added {} to PATH in {}",
                    display_bin_dir(),
                    collapse_tilde(&rc_path)
                );
            }
            PathSetup::Added(shell)
        }
        Ok(RcUpdate::Updated) => {
            if !quiet {
                eprintln!(
                    "updated the fuz block in {} (it did not match this install); PATH now gets {}",
                    collapse_tilde(&rc_path),
                    display_bin_dir()
                );
            }
            PathSetup::Updated(shell)
        }
        Ok(RcUpdate::AlreadyPresent) => PathSetup::AlreadyPresent(shell),
        Ok(RcUpdate::Untouched(reason)) => {
            if !quiet {
                eprintln!(
                    "note: left {} unchanged: {reason}",
                    collapse_tilde(&rc_path)
                );
                print_manual();
            }
            PathSetup::LeftUnchanged(shell)
        }
        Err(e) => {
            // Best-effort: tell the user why and how to finish, but don't fail —
            // fuz is already installed in the bin dir. The io cause is the
            // diagnostic (a non-UTF-8 rc, a file this user can't write, …),
            // so it is printed alongside the wrapper's message.
            if !quiet {
                let cause = std::error::Error::source(&e)
                    .map(|source| format!(": {source}"))
                    .unwrap_or_default();
                eprintln!(
                    "note: couldn't update {} ({e}{cause})",
                    collapse_tilde(&rc_path)
                );
                print_manual();
            }
            PathSetup::Manual
        }
    }
}

/// What [`update_rc_file`] did to the rc file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RcUpdate {
    /// No managed block existed; one was appended (or the file created).
    Added,
    /// The managed block held one fuz-written line naming another directory
    /// and was rewritten in place.
    Updated,
    /// The managed block already puts the bin dir on PATH; no write.
    AlreadyPresent,
    /// The rc is in a state fuz won't write to; no write.
    Untouched(RcUntouched),
}

/// Why an existing rc file was left exactly as found.
///
/// Each is a state where writing would alter or destroy something fuz did not
/// write, or where what fuz did write can no longer be told apart from the
/// user's own lines. The `Display` text completes "left the rc unchanged: …".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
enum RcUntouched {
    /// The markers don't delimit one well-formed block.
    #[error(
        "its fuz block is malformed: expected one '{RC_BEGIN_MARKER}' line, then one \
         '{RC_END_MARKER}' line, each alone on its line, with LF line endings"
    )]
    MalformedBlock,
    /// The block is well-formed but its body is not one PATH line in the form
    /// fuz writes for this shell, so replacing it would delete what the user
    /// put there.
    #[error(
        "its fuz block has been edited (fuz only rewrites a block holding exactly one line, a \
         PATH line in the form fuz writes for this shell)"
    )]
    EditedBlock,
    /// The rc path resolves to something other than a regular file — a
    /// directory, a FIFO (reading one blocks until a writer appears), a device
    /// (`~/.bashrc -> /dev/null`, which an atomic replace would overwrite).
    #[error("it is not a regular file")]
    NotRegularFile,
    /// The rc path is a symlink whose target does not exist.
    #[error("it is a dangling symlink (its target does not exist)")]
    DanglingLink,
    /// A write is called for and the file is not owner-writable. An atomic replace would go through
    /// anyway (rename needs only directory permission), so the bit is honored
    /// explicitly.
    #[error("it is read-only")]
    ReadOnly,
}

/// What an existing rc file's contents call for.
#[derive(Debug, PartialEq, Eq)]
enum RcPlan {
    /// Write these contents: the original plus an appended block.
    Append(String),
    /// Write these contents: the original with the block's one line replaced.
    Rewrite(String),
    AlreadyPresent,
    /// See [`RcUntouched::EditedBlock`].
    Edited,
    /// See [`RcUntouched::MalformedBlock`].
    Malformed,
}

/// How many times a marker occurs in an rc file, with the position of a sole
/// occurrence.
enum MarkerOccurrence {
    Absent,
    Once(usize),
    Repeated,
}

impl MarkerOccurrence {
    fn of(contents: &str, marker: &str) -> Self {
        let mut positions = contents.match_indices(marker).map(|(index, _)| index);
        match (positions.next(), positions.next()) {
            (None, _) => Self::Absent,
            (Some(index), None) => Self::Once(index),
            (Some(_), Some(_)) => Self::Repeated,
        }
    }
}

/// The managed block as found in an rc file.
#[derive(Debug, PartialEq, Eq)]
enum BlockBody {
    /// Neither marker occurs anywhere.
    NoBlock,
    /// Exactly one well-formed block; the range is the bytes strictly between
    /// the begin-marker line and the end-marker line.
    Body(std::ops::Range<usize>),
    /// Any other arrangement of the markers.
    Malformed,
}

/// Locate the managed block's body in `contents`.
///
/// A well-formed block means each marker occurs once in the whole file, each
/// is a whole line (`\n`-terminated; the end marker may instead end the file),
/// and begin precedes end. Every other arrangement — a marker missing or
/// repeated, out of order, sharing its line with other text, or
/// `\r\n`-terminated — is [`BlockBody::Malformed`]: the block's extent would
/// be a guess, and a wrong guess deletes the user's own lines.
fn find_block_body(contents: &str) -> BlockBody {
    let (begin, end) = match (
        MarkerOccurrence::of(contents, RC_BEGIN_MARKER),
        MarkerOccurrence::of(contents, RC_END_MARKER),
    ) {
        (MarkerOccurrence::Absent, MarkerOccurrence::Absent) => return BlockBody::NoBlock,
        (MarkerOccurrence::Once(begin), MarkerOccurrence::Once(end)) => (begin, end),
        _ => return BlockBody::Malformed,
    };

    let at_line_start = |index: usize| index == 0 || contents[..index].ends_with('\n');
    let after_begin = begin + RC_BEGIN_MARKER.len();
    let after_end = end + RC_END_MARKER.len();
    let body_start = after_begin + 1;
    let well_formed = at_line_start(begin)
        && contents[after_begin..].starts_with('\n')
        && end >= body_start
        && at_line_start(end)
        && (after_end == contents.len() || contents[after_end..].starts_with('\n'));
    if well_formed {
        BlockBody::Body(body_start..end)
    } else {
        BlockBody::Malformed
    }
}

/// Decide what an rc file holding `existing` needs so that its managed block
/// puts the bin dir on PATH. Pure; every byte outside the block body is
/// carried over unchanged.
///
/// `path_line` is the line to write. `equivalent_line`, when the shell has
/// one, is a second line that is just as correct; a block holding either is
/// already present.
///
/// A block is rewritten only when its body is exactly one line that `shell`
/// recognizes ([`Shell::recognizes_path_line`]) — a line fuz wrote for another
/// directory. An emptied body, one with more lines, or a single line of any
/// other text (`source ~/paths.sh`, a PATH line with a trailing comment) holds
/// the user's own edits, and is reported as [`RcPlan::Edited`] rather than
/// replaced.
fn plan_rc_update(
    existing: &str,
    shell: Shell,
    path_line: &str,
    equivalent_line: Option<&str>,
) -> RcPlan {
    let body = match find_block_body(existing) {
        BlockBody::Malformed => return RcPlan::Malformed,
        BlockBody::NoBlock => {
            // Append the block, ensuring a leading blank line for readability.
            let mut out = existing.to_owned();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
            out.push_str(&rc_block(path_line));
            return RcPlan::Append(out);
        }
        BlockBody::Body(body) => body,
    };

    // The end marker starts a line, so a non-empty body is whole lines.
    let Some(line) = existing[body.clone()].strip_suffix('\n') else {
        return RcPlan::Edited;
    };
    if line.contains('\n') {
        return RcPlan::Edited;
    }
    if line == path_line || equivalent_line == Some(line) {
        return RcPlan::AlreadyPresent;
    }
    if !shell.recognizes_path_line(line) {
        return RcPlan::Edited;
    }
    RcPlan::Rewrite(format!(
        "{}{path_line}\n{}",
        &existing[..body.start],
        &existing[body.end..]
    ))
}

/// Where an rc path's bytes live, or why it is left alone.
#[derive(Debug)]
enum RcTarget {
    /// Nothing exists at the rc path; the file is created there.
    Create,
    /// The regular file to read and replace — the rc path with every symlink
    /// resolved — and the permission bits it keeps.
    Existing { path: PathBuf, mode: u32 },
    /// See [`RcUntouched`].
    Untouched(RcUntouched),
}

/// Resolve `rc_path` to the file a write must land on.
///
/// An atomic write renames over its path, which would replace a symlink
/// (`~/.bashrc -> dotfiles/bashrc`) with a regular file and leave the link's
/// target stale. Writing to the canonical target instead keeps the link.
///
/// Only a regular file is a target. The type is checked before anything opens
/// the path: a FIFO would block the read, and a device would be replaced by
/// the rename.
fn resolve_rc_target(rc_path: &Path) -> std::io::Result<RcTarget> {
    let path = match fs::canonicalize(rc_path) {
        Ok(path) => path,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Not-found covers both "no such file" and "a link to nothing";
            // only the first is fuz's to create.
            return match fs::symlink_metadata(rc_path) {
                Ok(_) => Ok(RcTarget::Untouched(RcUntouched::DanglingLink)),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(RcTarget::Create),
                Err(e) => Err(e),
            };
        }
        Err(e) => return Err(e),
    };
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() {
        return Ok(RcTarget::Untouched(RcUntouched::NotRegularFile));
    }
    let mode = metadata.permissions().mode() & MODE_PERMISSION_BITS;
    Ok(RcTarget::Existing { path, mode })
}

/// Make `rc_path`'s managed block put the bin dir on PATH: create the file,
/// append the block, rewrite a block whose one line differs, or leave the file
/// alone. [`RcUpdate`] says which happened.
///
/// Writes are atomic, land on the symlink-resolved file, and keep an existing
/// file's permission bits; [`RC_FILE_MODE`] applies only to a file created
/// here. See [`plan_rc_update`] for `shell` / `path_line` / `equivalent_line`.
fn update_rc_file(
    rc_path: &Path,
    shell: Shell,
    path_line: &str,
    equivalent_line: Option<&str>,
) -> Result<RcUpdate, BootstrapError> {
    let failed_at = |path: &Path| {
        let path = path.to_path_buf();
        move |source| BootstrapError::UpdateShellRcFailed { path, source }
    };

    let (target, mode) = match resolve_rc_target(rc_path).map_err(failed_at(rc_path))? {
        RcTarget::Untouched(reason) => return Ok(RcUpdate::Untouched(reason)),
        RcTarget::Existing { path, mode } => (path, mode),
        RcTarget::Create => {
            // Ensure parent directory exists (fish lives under ~/.config/fish/).
            // Only missing levels are created, at 0700 rather than the umask's
            // mode; existing ones are left alone.
            if let Some(parent) = rc_path.parent()
                && !parent.as_os_str().is_empty()
            {
                fuz_sys::fs::create_dir_all_mode(parent, RC_DIR_MODE).map_err(failed_at(parent))?;
            }
            fuz_sys::fs::write_atomic(rc_path, rc_block(path_line).as_bytes(), RC_FILE_MODE)
                .map_err(failed_at(rc_path))?;
            return Ok(RcUpdate::Added);
        }
    };

    let existing = fs::read_to_string(&target).map_err(failed_at(&target))?;
    let (new_contents, update) = match plan_rc_update(&existing, shell, path_line, equivalent_line)
    {
        RcPlan::Append(contents) => (contents, RcUpdate::Added),
        RcPlan::Rewrite(contents) => (contents, RcUpdate::Updated),
        RcPlan::AlreadyPresent => return Ok(RcUpdate::AlreadyPresent),
        RcPlan::Edited => return Ok(RcUpdate::Untouched(RcUntouched::EditedBlock)),
        RcPlan::Malformed => return Ok(RcUpdate::Untouched(RcUntouched::MalformedBlock)),
    };

    // A write is called for, so the file's own writability now matters. The
    // atomic write renames a new file over the target, which needs only
    // directory permission: it would replace a file this user cannot write
    // (another owner's, say, in a directory the user owns), and hand the user
    // its ownership. The mode-bit check stays alongside the open below: root
    // passes any open.
    if mode & MODE_OWNER_WRITE == 0 {
        return Ok(RcUpdate::Untouched(RcUntouched::ReadOnly));
    }
    // Opening the target for append — nothing is written — asks the kernel
    // whether the user may write the file itself.
    fs::OpenOptions::new()
        .append(true)
        .open(&target)
        .map(drop)
        .map_err(failed_at(&target))?;

    fuz_sys::fs::write_atomic(&target, new_contents.as_bytes(), mode)
        .map_err(failed_at(&target))?;
    // The replacement was created under the process umask, which can only
    // have narrowed `mode`; restore the bits the file had. A failure here is
    // reported as a failed update although the new contents are in place, at
    // a mode no wider than the file had.
    fs::set_permissions(&target, fs::Permissions::from_mode(mode)).map_err(failed_at(&target))?;
    Ok(update)
}

//
// Display helpers
//

/// The bin dir a user puts on `PATH`, as shown in hints: the resolved
/// `<fuz home>/bin` (so a `FUZ_HOME` override is named, not `~/.fuz/bin`),
/// tilde-collapsed when it sits under `$HOME`.
fn display_bin_dir() -> String {
    fuz_home::get_bin_dir().map_or_else(|_| "~/.fuz/bin".to_string(), |d| collapse_tilde(&d))
}

fn print_success(meta: &ArtifactMeta, path_setup: PathSetup, scenario: &InstallScenario) {
    // The `bin/fuz` symlink is what ends up on the user's PATH. We display
    // it as the canonical install location even though the real binary
    // lives under `artifacts/v1-<hash>/fuz`.
    let bin_target = fuz_home::get_bin_dir().map_or_else(
        |_| "~/.fuz/bin/fuz".to_string(),
        |d| collapse_tilde(&d.join("fuz")),
    );

    // Pretty hash: strip the `v1-` prefix so users see the meaningful
    // 16 hex chars rather than a redundant version tag.
    let short_hash = fuz_artifact::short_content_hash(&meta.hash, 16);

    let header = match scenario {
        InstallScenario::Fresh => format!("fuz {} installed", meta.version),
        InstallScenario::AlreadyInstalled => format!("fuz {} already installed", meta.version),
        InstallScenario::ReplacedSameVersion { previous_version } => format!(
            "fuz {} installed (replaced {})",
            meta.version, previous_version
        ),
        InstallScenario::VersionChanged { previous_version } => {
            format!("fuz {} installed (was {})", meta.version, previous_version)
        }
    };
    println!("{header}");
    println!("  binary:  {bin_target}");
    println!("  hash:    {short_hash}");
    println!("  version: {}", meta.version);
    println!();

    // A re-run into the same artifact with nothing new on PATH changed nothing
    // in the user's env, so there is no next step beyond verifying. An rc that
    // was just added to or repaired still needs a new shell, whatever the
    // artifact scenario.
    let rc_changed = matches!(path_setup, PathSetup::Added(_) | PathSetup::Updated(_));
    if matches!(scenario, InstallScenario::AlreadyInstalled) && !rc_changed {
        println!("Run 'fuz self status' to verify installation.");
        return;
    }

    match path_setup {
        PathSetup::Added(shell) | PathSetup::Updated(shell) => {
            let rc = format!("~/{}", shell.rc_relative_path());
            println!("Next: open a new shell or run 'source {rc}',");
            println!("then 'fuz self status' to verify installation.");
        }
        PathSetup::AlreadyPresent(shell) => {
            println!(
                "~/{} already puts {} on PATH.",
                shell.rc_relative_path(),
                display_bin_dir()
            );
            println!("Run 'fuz self status' to verify installation.");
        }
        PathSetup::Skipped => {
            println!(
                "Add {} to your PATH, then run 'fuz self status' to verify installation.",
                display_bin_dir()
            );
        }
        PathSetup::LeftUnchanged(shell) => {
            // modify_path already printed the reason + the line to add.
            println!(
                "Next: ~/{} was left unchanged; add {} to your PATH there,",
                shell.rc_relative_path(),
                display_bin_dir()
            );
            println!("then run 'fuz self status'.");
        }
        PathSetup::Manual => {
            // modify_path already printed the reason + manual instructions.
            println!(
                "Next: add {} to your shell's PATH, then run 'fuz self status'.",
                display_bin_dir()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const HOME: &str = "/home/u";

    /// A validated bin dir, with `/home/u` as the home.
    fn rc_bin_dir(path: &str) -> RcBinDir {
        RcBinDir::new(Path::new(path), Some(Path::new(HOME))).expect("safe bin dir")
    }

    /// The default layout's lines, byte for byte: `$HOME/.fuz/bin` for the
    /// POSIX shells, `~/.fuz/bin` for fish.
    #[test]
    fn path_line_default_layout_is_home_relative() {
        let bin = rc_bin_dir("/home/u/.fuz/bin");
        assert_eq!(
            Shell::Bash.path_line(&bin, true),
            r#"export PATH="$HOME/.fuz/bin:$PATH""#
        );
        assert_eq!(
            Shell::Zsh.path_line(&bin, true),
            r#"export PATH="$HOME/.fuz/bin:$PATH""#
        );
        assert_eq!(
            Shell::Fish.path_line(&bin, true),
            "fish_add_path ~/.fuz/bin"
        );
        assert_eq!(
            Shell::Fish.path_line(&bin, false),
            "set -gx PATH ~/.fuz/bin $PATH"
        );
    }

    /// A relocated home under `$HOME` stays home-relative and names the real
    /// directory, not `.fuz`.
    #[test]
    fn path_line_names_a_relocated_home_under_home() {
        let bin = rc_bin_dir("/home/u/tools/fuz-2/bin");
        assert_eq!(
            Shell::Bash.path_line(&bin, true),
            r#"export PATH="$HOME/tools/fuz-2/bin:$PATH""#
        );
        assert_eq!(
            Shell::Fish.path_line(&bin, true),
            "fish_add_path ~/tools/fuz-2/bin"
        );
    }

    /// Outside `$HOME` — including a sibling sharing a string prefix, and any
    /// path when `$HOME` is unset or empty — the line is absolute.
    #[test]
    fn path_line_outside_home_is_absolute() {
        let bin = rc_bin_dir("/opt/fuz/bin");
        assert_eq!(
            Shell::Bash.path_line(&bin, true),
            r#"export PATH="/opt/fuz/bin:$PATH""#
        );
        assert_eq!(
            Shell::Fish.path_line(&bin, true),
            "fish_add_path /opt/fuz/bin"
        );
        assert_eq!(
            Shell::Fish.path_line(&bin, false),
            "set -gx PATH /opt/fuz/bin $PATH"
        );

        // `/home/u2` shares a string prefix with `/home/u` but is not under it.
        assert_eq!(rc_bin_dir("/home/u2/.fuz/bin").posix(), "/home/u2/.fuz/bin");

        for absent in [None, Some(Path::new(""))] {
            let bin = RcBinDir::new(Path::new("/home/u/.fuz/bin"), absent).expect("safe");
            assert_eq!(bin.posix(), "/home/u/.fuz/bin", "home: {absent:?}");
            assert_eq!(bin.fish(), "/home/u/.fuz/bin", "home: {absent:?}");
        }
    }

    /// A home of `/` (no named component) has every absolute path under it;
    /// the line is written absolute rather than as `$HOME/opt/…`, which would
    /// expand to `//opt/…`. A relative home anchors nothing either.
    #[test]
    fn rc_bin_dir_ignores_a_home_that_anchors_nothing() {
        for home in ["/", "//", "/.", "/.."] {
            let bin = RcBinDir::new(Path::new("/opt/fuz/bin"), Some(Path::new(home)))
                .expect("safe bin dir");
            assert_eq!(bin.posix(), "/opt/fuz/bin", "home: {home:?}");
            assert_eq!(bin.fish(), "/opt/fuz/bin", "home: {home:?}");
        }
        assert_eq!(
            RcBinDir::new(Path::new("h/.fuz/bin"), Some(Path::new("h"))),
            Err(RcBinDirError::Relative)
        );
    }

    /// The advice matches the reason: a relative bin dir is fixed by an
    /// absolute fuz home, not by quoting.
    #[test]
    fn rc_bin_dir_error_advice_matches_the_reason() {
        assert!(RcBinDirError::Relative.advice().contains("absolute"));
        assert!(!RcBinDirError::Relative.advice().contains("quoting"));
        assert!(RcBinDirError::UnsafeChars.advice().contains("quoting"));
        assert!(RcBinDirError::NotUtf8.advice().contains("quoting"));
        assert!(RcBinDirError::Unresolved.advice().contains("absolute"));
    }

    /// Only the interpolated text is charset-checked: a home directory with a
    /// space is fine when the line says `$HOME/…`, since the shell expands it.
    #[test]
    fn rc_bin_dir_does_not_interpolate_the_home_prefix() {
        let bin = RcBinDir::new(
            Path::new("/home/a b$c/.fuz/bin"),
            Some(Path::new("/home/a b$c")),
        )
        .expect("remainder is safe");
        assert_eq!(bin.posix(), "$HOME/.fuz/bin");
        assert_eq!(bin.fish(), "~/.fuz/bin");
    }

    #[test]
    fn rc_bin_dir_rejects_unsafe_characters() {
        let home = Some(Path::new(HOME));
        for path in [
            "/opt/my fuz/bin",
            "/opt/$(id)/bin",
            "/opt/a\"b/bin",
            "/opt/a'b/bin",
            "/opt/a`b`/bin",
            "/opt/a;b/bin",
            "/opt/a:b/bin",
            "/opt/a\nb/bin",
            "/opt/a\\b/bin",
            "/opt/a*/bin",
            "/opt/~/bin",
            "/opt/caf\u{e9}/bin",
            // under home: the remainder is what gets checked
            "/home/u/my fuz/bin",
            "/home/u/$x/bin",
        ] {
            assert_eq!(
                RcBinDir::new(Path::new(path), home),
                Err(RcBinDirError::UnsafeChars),
                "path: {path:?}"
            );
        }
        // An unsafe home is only tolerated as an expanded prefix: written
        // absolute (home unset), the same directory is refused.
        assert_eq!(
            RcBinDir::new(Path::new("/home/a b/.fuz/bin"), None),
            Err(RcBinDirError::UnsafeChars)
        );
    }

    #[test]
    fn rc_bin_dir_rejects_relative_and_non_utf8() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let home = Some(Path::new(HOME));
        assert_eq!(
            RcBinDir::new(Path::new("fuzhome/bin"), home),
            Err(RcBinDirError::Relative)
        );
        assert_eq!(
            RcBinDir::new(Path::new("fuzhome/bin"), None),
            Err(RcBinDirError::Relative)
        );
        let non_utf8 = Path::new(OsStr::from_bytes(b"/opt/f\xffz/bin"));
        assert_eq!(RcBinDir::new(non_utf8, home), Err(RcBinDirError::NotUtf8));
        let non_utf8_under_home = Path::new(OsStr::from_bytes(b"/home/u/f\xffz/bin"));
        assert_eq!(
            RcBinDir::new(non_utf8_under_home, home),
            Err(RcBinDirError::NotUtf8)
        );
    }

    #[test]
    fn rc_block_wraps_the_line_in_markers() {
        assert_eq!(
            rc_block("LINE"),
            "# >>> fuz initialize >>>\nLINE\n# <<< fuz initialize <<<\n"
        );
    }

    #[test]
    fn parse_fish_version_handles_canonical_output() {
        assert_eq!(parse_fish_version("fish, version 3.6.1\n"), Some((3, 6)));
        assert_eq!(parse_fish_version("fish, version 3.2.0"), Some((3, 2)));
        assert_eq!(parse_fish_version("fish, version 3.1.2"), Some((3, 1)));
    }

    #[test]
    fn parse_fish_version_returns_none_on_garbage() {
        assert_eq!(parse_fish_version(""), None);
        assert_eq!(parse_fish_version("no version here"), None);
    }

    #[test]
    fn install_scenario_derive_fresh() {
        let new = ArtifactMeta::new_bootstrap("0.1.0".into(), ContentHash::blake3(b"abc"));
        let scenario = InstallScenario::derive(None, &new);
        assert!(matches!(scenario, InstallScenario::Fresh));
    }

    #[test]
    fn install_scenario_derive_already_installed() {
        let prev = ArtifactMeta::new_bootstrap("0.1.0".into(), ContentHash::blake3(b"abc"));
        let new = prev.clone();
        let scenario = InstallScenario::derive(Some(&prev), &new);
        assert!(matches!(scenario, InstallScenario::AlreadyInstalled));
    }

    #[test]
    fn install_scenario_derive_replaced_same_version() {
        let prev = ArtifactMeta::new_bootstrap("0.1.0".into(), ContentHash::blake3(b"aaa"));
        let new = ArtifactMeta::new_bootstrap("0.1.0".into(), ContentHash::blake3(b"bbb"));
        let scenario = InstallScenario::derive(Some(&prev), &new);
        match scenario {
            InstallScenario::ReplacedSameVersion { previous_version } => {
                assert_eq!(previous_version, "0.1.0");
            }
            other => panic!("expected ReplacedSameVersion, got {other:?}"),
        }
    }

    #[test]
    fn install_scenario_derive_version_changed() {
        let prev = ArtifactMeta::new_bootstrap("0.1.0".into(), ContentHash::blake3(b"aaa"));
        let new = ArtifactMeta::new_bootstrap("0.2.0".into(), ContentHash::blake3(b"bbb"));
        let scenario = InstallScenario::derive(Some(&prev), &new);
        match scenario {
            InstallScenario::VersionChanged { previous_version } => {
                assert_eq!(previous_version, "0.1.0");
            }
            other => panic!("expected VersionChanged, got {other:?}"),
        }
    }

    #[test]
    fn parse_shell_recognizes_known_shells() {
        assert_eq!(parse_shell("/bin/bash"), Some(Shell::Bash));
        assert_eq!(parse_shell("/usr/bin/zsh"), Some(Shell::Zsh));
        assert_eq!(parse_shell("/usr/local/bin/fish"), Some(Shell::Fish));
    }

    #[test]
    fn parse_shell_returns_none_for_unknown() {
        assert_eq!(parse_shell("/bin/dash"), None);
        assert_eq!(parse_shell("/usr/bin/sh"), None);
        assert_eq!(parse_shell(""), None);
        assert_eq!(parse_shell("/"), None);
    }

    const BASH_LINE: &str = r#"export PATH="$HOME/.fuz/bin:$PATH""#;
    const STALE_LINE: &str = r#"export PATH="$HOME/elsewhere/bin:$PATH""#;

    #[test]
    fn update_rc_file_creates_missing_file() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Added);

        let contents = fs::read_to_string(&rc).expect("read rc");
        assert_eq!(contents, rc_block(BASH_LINE));
    }

    #[test]
    fn update_rc_file_is_idempotent() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");

        let first = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("first update");
        assert_eq!(first, RcUpdate::Added);
        let before = fs::read_to_string(&rc).expect("read rc");

        let second = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("second update");
        assert_eq!(second, RcUpdate::AlreadyPresent);
        assert_eq!(fs::read_to_string(&rc).expect("read rc"), before);
    }

    #[test]
    fn update_rc_file_appends_to_existing_unmanaged_file() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        let seed = "# pre-existing user content\nalias ll='ls -la'\n";
        fs::write(&rc, seed).expect("seed rc file");

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Added);

        let contents = fs::read_to_string(&rc).expect("read rc");
        assert_eq!(contents, format!("{seed}\n{}", rc_block(BASH_LINE)));
    }

    #[test]
    fn update_rc_file_creates_fish_parent_dir() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".config/fish/config.fish");

        let update =
            update_rc_file(&rc, Shell::Fish, "fish_add_path ~/.fuz/bin", None).expect("update rc");
        assert_eq!(update, RcUpdate::Added);

        let contents = fs::read_to_string(&rc).expect("read rc");
        assert_eq!(contents, rc_block("fish_add_path ~/.fuz/bin"));
    }

    /// The directories created above a new rc file are 0700 whatever the
    /// umask, and one that already exists keeps its mode.
    #[test]
    fn update_rc_file_creates_missing_parent_dirs_at_0700_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode_of = |path: &Path| fs::metadata(path).expect("stat").permissions().mode() & 0o777;

        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".config/fish/config.fish");
        update_rc_file(&rc, Shell::Fish, "fish_add_path ~/.fuz/bin", None).expect("update rc");
        assert_eq!(mode_of(&dir.path().join(".config")), 0o700);
        assert_eq!(mode_of(&dir.path().join(".config/fish")), 0o700);

        let dir = TempDir::new().expect("create temp dir");
        let config = dir.path().join(".config");
        fs::create_dir(&config).expect("create .config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o751)).expect("chmod");
        let rc = config.join("fish/config.fish");
        update_rc_file(&rc, Shell::Fish, "fish_add_path ~/.fuz/bin", None).expect("update rc");
        assert_eq!(mode_of(&config), 0o751, "an existing dir keeps its mode");
        assert_eq!(mode_of(&config.join("fish")), 0o700);
    }

    /// A block whose body differs is rewritten on disk, and only the body.
    #[test]
    fn update_rc_file_rewrites_a_stale_block() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        let before = "alias a=b\n\n";
        let after = "\n# trailing user line, no newline";
        fs::write(&rc, format!("{before}{}{after}", rc_block(STALE_LINE))).expect("seed");

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Updated);
        assert_eq!(
            fs::read_to_string(&rc).expect("read rc"),
            format!("{before}{}{after}", rc_block(BASH_LINE))
        );

        // And the repaired block is now a no-op.
        assert_eq!(
            update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("re-run"),
            RcUpdate::AlreadyPresent
        );
    }

    /// A malformed block is reported and the file is not written at all.
    #[test]
    fn update_rc_file_leaves_a_malformed_block_untouched() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        let seed = format!("alias a=b\n{RC_BEGIN_MARKER}\n{STALE_LINE}\nalias c=d\n");
        fs::write(&rc, &seed).expect("seed");

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Untouched(RcUntouched::MalformedBlock));
        assert_eq!(fs::read_to_string(&rc).expect("read rc"), seed);
    }

    /// An edited block is reported as such and the file is not written.
    #[test]
    fn update_rc_file_leaves_an_edited_block_untouched() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        let seed = format!("a=1\n{RC_BEGIN_MARKER}\n{STALE_LINE}\nalias mine=1\n{RC_END_MARKER}\n");
        fs::write(&rc, &seed).expect("seed");

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Untouched(RcUntouched::EditedBlock));
        assert_eq!(fs::read_to_string(&rc).expect("read rc"), seed);
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).expect("stat").permissions().mode() & 0o7777
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// `rc -> real` with `real` seeded at an explicit mode.
    fn symlinked_rc(dir: &Path, seed: &str, mode: u32) -> (PathBuf, PathBuf) {
        let dotfiles = dir.join("dotfiles");
        fs::create_dir(&dotfiles).expect("mkdir");
        let real = dotfiles.join("bashrc");
        fs::write(&real, seed).expect("seed");
        set_mode(&real, mode);
        let rc = dir.join(".bashrc");
        // A relative link, the way dotfile managers lay them down.
        std::os::unix::fs::symlink("dotfiles/bashrc", &rc).expect("symlink");
        (rc, real)
    }

    fn is_symlink(path: &Path) -> bool {
        fs::symlink_metadata(path)
            .expect("lstat")
            .file_type()
            .is_symlink()
    }

    /// Appending through a symlinked rc writes the link's target and leaves
    /// the link a link.
    #[test]
    fn update_rc_file_appends_through_a_symlink() {
        let dir = TempDir::new().expect("create temp dir");
        let seed = "alias a=b\n";
        let (rc, real) = symlinked_rc(dir.path(), seed, 0o644);

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Added);
        assert!(is_symlink(&rc), "the rc is still a symlink");
        assert_eq!(
            fs::read_link(&rc).expect("readlink"),
            Path::new("dotfiles/bashrc")
        );
        assert_eq!(
            fs::read_to_string(&real).expect("read target"),
            format!("{seed}\n{}", rc_block(BASH_LINE))
        );
    }

    /// A stale block behind a symlinked rc is rewritten in the target.
    #[test]
    fn update_rc_file_rewrites_through_a_symlink() {
        let dir = TempDir::new().expect("create temp dir");
        let (rc, real) = symlinked_rc(dir.path(), &rc_block(STALE_LINE), 0o644);

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Updated);
        assert!(is_symlink(&rc), "the rc is still a symlink");
        assert_eq!(
            fs::read_to_string(&real).expect("read target"),
            rc_block(BASH_LINE)
        );
    }

    /// A dangling symlink is neither followed into a new file nor replaced.
    #[test]
    fn update_rc_file_leaves_a_dangling_symlink_untouched() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        std::os::unix::fs::symlink("dotfiles/bashrc", &rc).expect("symlink");

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Untouched(RcUntouched::DanglingLink));
        assert!(is_symlink(&rc), "the rc is still a symlink");
        assert_eq!(
            fs::read_link(&rc).expect("readlink"),
            Path::new("dotfiles/bashrc")
        );
        assert!(!dir.path().join("dotfiles").exists(), "no target created");
        assert_eq!(
            fs::read_dir(dir.path()).expect("read dir").count(),
            1,
            "nothing but the link in the directory"
        );
    }

    /// An existing rc keeps its permission bits across both kinds of write —
    /// a private `0600` rc is not widened to the creation mode, and a wider
    /// one is not narrowed by the umask.
    #[test]
    fn update_rc_file_preserves_the_mode_of_an_existing_file() {
        for mode in [0o600, 0o640, 0o666, 0o755] {
            let dir = TempDir::new().expect("create temp dir");
            let rc = dir.path().join(".bashrc");

            fs::write(&rc, "alias a=b\n").expect("seed");
            set_mode(&rc, mode);
            let update = update_rc_file(&rc, Shell::Bash, STALE_LINE, None).expect("append");
            assert_eq!(update, RcUpdate::Added);
            assert_eq!(mode_of(&rc), mode, "after append, mode {mode:o}");

            let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("rewrite");
            assert_eq!(update, RcUpdate::Updated);
            assert_eq!(mode_of(&rc), mode, "after rewrite, mode {mode:o}");
        }
    }

    /// The mode kept through a symlink is the target's.
    #[test]
    fn update_rc_file_preserves_the_mode_of_a_symlink_target() {
        let dir = TempDir::new().expect("create temp dir");
        let (rc, real) = symlinked_rc(dir.path(), "alias a=b\n", 0o600);

        update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(mode_of(&real), 0o600);
    }

    /// A file created here gets [`RC_FILE_MODE`] masked by the umask, never
    /// more.
    #[test]
    fn update_rc_file_creates_with_the_rc_file_mode() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(mode_of(&rc) & !RC_FILE_MODE, 0, "{:o}", mode_of(&rc));
    }

    /// A read-only rc is honored: with or without a block to repair, nothing
    /// is written and the mode stays. One whose block is already correct needs
    /// no write, so it is reported as present rather than as read-only.
    #[test]
    fn update_rc_file_leaves_a_read_only_file_untouched() {
        for (seed, expected) in [
            (
                "alias a=b\n".to_owned(),
                RcUpdate::Untouched(RcUntouched::ReadOnly),
            ),
            (
                rc_block(STALE_LINE),
                RcUpdate::Untouched(RcUntouched::ReadOnly),
            ),
            (rc_block(BASH_LINE), RcUpdate::AlreadyPresent),
        ] {
            let dir = TempDir::new().expect("create temp dir");
            let rc = dir.path().join(".bashrc");
            fs::write(&rc, &seed).expect("seed");
            set_mode(&rc, 0o444);

            let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
            assert_eq!(update, expected, "seed: {seed:?}");
            assert_eq!(fs::read_to_string(&rc).expect("read rc"), seed);
            assert_eq!(mode_of(&rc), 0o444);
        }
    }

    /// Whether the tests run as root, for whom permission bits deny nothing.
    fn running_as_root() -> bool {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new().expect("create temp dir");
        fs::metadata(dir.path()).expect("stat").uid() == 0
    }

    /// An rc that can't be read or replaced is an error carrying the io
    /// cause, and is left as found.
    #[test]
    fn update_rc_file_reports_the_io_cause() {
        use std::error::Error as _;

        // not UTF-8: the read fails
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        fs::write(&rc, b"alias a=\xff\n").expect("seed");
        set_mode(&rc, 0o644);
        let err = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect_err("not UTF-8");
        let cause = err.source().expect("carries the cause").to_string();
        assert!(cause.contains("UTF-8"), "cause: {cause}");
        assert_eq!(fs::read(&rc).expect("read rc"), b"alias a=\xff\n");

        // a writable file in a directory that isn't: the replacement can't be
        // created beside it. Root writes there regardless, so it has no such
        // case to observe.
        if running_as_root() {
            return;
        }
        let rc = dir.path().join("locked").join(".bashrc");
        fs::create_dir(dir.path().join("locked")).expect("mkdir");
        fs::write(&rc, "alias a=b\n").expect("seed");
        set_mode(&rc, 0o644);
        set_mode(&dir.path().join("locked"), 0o500);
        let result = update_rc_file(&rc, Shell::Bash, BASH_LINE, None);
        set_mode(&dir.path().join("locked"), 0o700);
        let err = result.expect_err("an unwritable directory");
        let cause = err.source().expect("carries the cause");
        assert!(cause.to_string().contains("os error"), "cause: {cause}");
        assert_eq!(fs::read_to_string(&rc).expect("read rc"), "alias a=b\n");
        assert_eq!(
            fs::read_dir(dir.path().join("locked"))
                .expect("read dir")
                .count(),
            1,
            "no temp file left beside the rc"
        );
    }

    /// A directory at the rc path is not a file to edit: reported, not read.
    #[test]
    fn update_rc_file_leaves_a_directory_untouched() {
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        fs::create_dir(&rc).expect("mkdir");
        set_mode(&rc, 0o700);

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Untouched(RcUntouched::NotRegularFile));
        assert!(rc.is_dir());
        assert_eq!(fs::read_dir(&rc).expect("read dir").count(), 0);
    }

    /// A FIFO at the rc path — directly or behind a symlink — is reported
    /// without being opened: reading one blocks until a writer appears. The
    /// call runs on its own thread under a deadline, so opening the FIFO fails
    /// this test rather than hanging the suite.
    #[test]
    fn update_rc_file_leaves_a_fifo_untouched() {
        use std::os::unix::fs::FileTypeExt;
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = TempDir::new().expect("create temp dir");
        let fifo = dir.path().join("fifo");
        // std has no FIFO constructor; without `mkfifo(1)` there is nothing
        // to test against.
        if !Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|status| status.success())
        {
            eprintln!("skipping: mkfifo(1) unavailable");
            return;
        }
        let link = dir.path().join(".bashrc");
        std::os::unix::fs::symlink("fifo", &link).expect("symlink");

        for rc in [fifo.clone(), link] {
            let (sender, receiver) = mpsc::channel();
            let path = rc.clone();
            std::thread::spawn(move || {
                // The receiver is gone only once the deadline has failed the test.
                let _ = sender.send(update_rc_file(&path, Shell::Bash, BASH_LINE, None));
            });
            let update = receiver
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("blocked on the FIFO at {}", rc.display()))
                .expect("update rc");
            assert_eq!(update, RcUpdate::Untouched(RcUntouched::NotRegularFile));
            assert!(
                fs::metadata(&fifo).expect("stat").file_type().is_fifo(),
                "still a FIFO"
            );
        }
        assert_eq!(fs::read_dir(dir.path()).expect("read dir").count(), 2);
    }

    /// `rc -> /dev/null` is reported, not written through: an atomic replace
    /// of the link's target would rename a regular file over the device.
    #[test]
    fn update_rc_file_leaves_a_device_symlink_untouched() {
        // Only a regression reaches the write, and as root that write would
        // replace the system's `/dev/null`; a test must not carry that risk.
        if running_as_root() {
            eprintln!("skipping: running as root");
            return;
        }
        let dir = TempDir::new().expect("create temp dir");
        let rc = dir.path().join(".bashrc");
        std::os::unix::fs::symlink("/dev/null", &rc).expect("symlink");

        let update = update_rc_file(&rc, Shell::Bash, BASH_LINE, None).expect("update rc");
        assert_eq!(update, RcUpdate::Untouched(RcUntouched::NotRegularFile));
        assert!(is_symlink(&rc), "the rc is still a symlink");
        assert_eq!(
            fs::read_link(&rc).expect("readlink"),
            Path::new("/dev/null")
        );
    }

    /// Everything outside the block body survives a rewrite byte for byte,
    /// wherever the block sits.
    #[test]
    fn plan_rc_update_rewrites_only_the_block_body() {
        let stale = rc_block(STALE_LINE);
        let fresh = rc_block(BASH_LINE);
        let stale_no_newline = stale.trim_end_matches('\n');
        let fresh_no_newline = fresh.trim_end_matches('\n');
        for (existing, expected) in [
            // the whole file
            (stale.clone(), fresh.clone()),
            // in the middle, with odd whitespace and a tab around it
            (
                format!("a=1\n\n\n{stale}\t\nb=2  \n\n"),
                format!("a=1\n\n\n{fresh}\t\nb=2  \n\n"),
            ),
            // at the end, end marker closing the file with no newline
            (
                format!("a=1\n{stale_no_newline}"),
                format!("a=1\n{fresh_no_newline}"),
            ),
            // at the start, user content after
            (format!("{stale}b=2"), format!("{fresh}b=2")),
        ] {
            assert_eq!(
                plan_rc_update(&existing, Shell::Bash, BASH_LINE, None),
                RcPlan::Rewrite(expected),
                "existing: {existing:?}"
            );
        }
    }

    /// A block is rewritten only while it holds one line. Emptied, or with any
    /// line added — before, after, or around the fuz line, even the current
    /// one — it holds the user's edits and is left alone.
    #[test]
    fn plan_rc_update_never_rewrites_an_edited_block() {
        for body in [
            String::new(),
            format!("{STALE_LINE}\nextra\n"),
            format!("extra\n{STALE_LINE}\n"),
            format!("{BASH_LINE}\nextra\n"),
            format!("# why\n{BASH_LINE}\n"),
            format!("{STALE_LINE}\n\n"),
            "\n\n".to_owned(),
        ] {
            let existing = format!("x\n{RC_BEGIN_MARKER}\n{body}{RC_END_MARKER}\ny\n");
            assert_eq!(
                plan_rc_update(&existing, Shell::Bash, BASH_LINE, None),
                RcPlan::Edited,
                "existing: {existing:?}"
            );
        }
    }

    /// A block holding one line that is not a PATH line fuz writes for the
    /// shell is the user's, however much it resembles one.
    #[test]
    fn plan_rc_update_never_rewrites_a_line_fuz_did_not_write() {
        for line in [
            "source ~/paths.sh",
            "# export PATH=\"$HOME/.fuz/bin:$PATH\"",
            r#"export PATH="$HOME/.fuz/bin:$PATH" # mine"#,
            r#"export PATH="$HOME/elsewhere/bin:$PATH"; alias mine=1"#,
            // fish's line in a bash rc
            "fish_add_path ~/elsewhere/bin",
        ] {
            let existing = format!("x\n{}y\n", rc_block(line));
            assert_eq!(
                plan_rc_update(&existing, Shell::Bash, BASH_LINE, None),
                RcPlan::Edited,
                "line: {line:?}"
            );
        }
        // bash's line in a fish config
        assert_eq!(
            plan_rc_update(
                &rc_block(STALE_LINE),
                Shell::Fish,
                "fish_add_path ~/.fuz/bin",
                Some("set -gx PATH ~/.fuz/bin $PATH")
            ),
            RcPlan::Edited
        );
    }

    /// The recognizer is the inverse of the line builders: every line fuz
    /// writes for a shell, for any bin dir it accepts, is recognized by that
    /// shell — each allowed punctuation character included.
    #[test]
    fn recognizes_every_line_fuz_writes() {
        for path in [
            "/home/u/.fuz/bin",
            "/home/u/tools/fuz-2/bin",
            "/home/u/bin",
            "/opt/fuz/bin",
            "/bin",
            "/opt/a_b/bin",
            "/opt/a.b/bin",
            "/opt/a+b/bin",
            "/opt/a-b/bin",
            "/home/u/a_b.c+d-e/bin",
            "/home/u/a/../fz/bin",
            "/opt/a/../b/bin",
            "/home/u/a/b/c/d/e/bin",
            "/opt/0/bin",
        ] {
            let bin = rc_bin_dir(path);
            for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
                for fish_add_path_supported in [true, false] {
                    let line = shell.path_line(&bin, fish_add_path_supported);
                    assert!(shell.recognizes_path_line(&line), "{shell:?}: {line:?}");
                    if let Some(equivalent) =
                        shell.equivalent_path_line(&bin, fish_add_path_supported)
                    {
                        assert!(
                            shell.recognizes_path_line(&equivalent),
                            "{shell:?}: {equivalent:?}"
                        );
                    }
                }
            }
        }
    }

    /// The fixed lines every default install already carries in its rc.
    #[test]
    fn recognizes_the_default_layout_lines() {
        let posix = r#"export PATH="$HOME/.fuz/bin:$PATH""#;
        assert!(Shell::Bash.recognizes_path_line(posix));
        assert!(Shell::Zsh.recognizes_path_line(posix));
        assert!(Shell::Fish.recognizes_path_line("fish_add_path ~/.fuz/bin"));
        assert!(Shell::Fish.recognizes_path_line("set -gx PATH ~/.fuz/bin $PATH"));
    }

    #[test]
    fn recognizes_nothing_fuz_does_not_write() {
        for line in [
            "",
            " ",
            "source ~/paths.sh",
            "# a comment",
            r#"# export PATH="$HOME/.fuz/bin:$PATH""#,
            // trailing or leading text
            r#"export PATH="$HOME/.fuz/bin:$PATH" # mine"#,
            r#"export PATH="$HOME/.fuz/bin:$PATH" "#,
            r#" export PATH="$HOME/.fuz/bin:$PATH""#,
            // an empty directory
            r#"export PATH=":$PATH""#,
            r#"export PATH="$HOME/:$PATH""#,
            // an unsafe character, or a second PATH entry
            r#"export PATH="/opt/my fuz/bin:$PATH""#,
            r#"export PATH="/opt/$(id)/bin:$PATH""#,
            r#"export PATH="/opt/a/bin:/opt/b/bin:$PATH""#,
            r#"export PATH="$HOME/a:$HOME/b:$PATH""#,
            // neither absolute nor under `$HOME`
            r#"export PATH="opt/fuz/bin:$PATH""#,
            r#"export PATH="~/.fuz/bin:$PATH""#,
            r#"export PATH="$HOME//opt/fuz/bin:$PATH""#,
            // another shape of the same idea
            r#"export PATH="$PATH:$HOME/.fuz/bin""#,
            r#"PATH="$HOME/.fuz/bin:$PATH""#,
            // a trailing carriage return or tab
            "export PATH=\"$HOME/.fuz/bin:$PATH\"\r",
            "export PATH=\"$HOME/.fuz/bin:$PATH\"\t",
            // `$HOME` itself, or a non-ASCII directory
            r#"export PATH="$HOME:$PATH""#,
            r#"export PATH="/opt/café/bin:$PATH""#,
            // fish's lines
            "fish_add_path ~/.fuz/bin",
            "set -gx PATH ~/.fuz/bin $PATH",
        ] {
            assert!(!Shell::Bash.recognizes_path_line(line), "bash: {line:?}");
            assert!(!Shell::Zsh.recognizes_path_line(line), "zsh: {line:?}");
        }
        for line in [
            "",
            "source ~/paths.fish",
            "# fish_add_path ~/.fuz/bin",
            "fish_add_path ~/.fuz/bin # mine",
            "fish_add_path -g ~/.fuz/bin",
            "fish_add_path ~/.fuz/bin ~/other/bin",
            "fish_add_path ",
            "fish_add_path ~/",
            "fish_add_path $HOME/.fuz/bin",
            "fish_add_path .fuz/bin",
            "fish_add_path ~//opt/fuz/bin",
            "fish_add_path '/opt/my fuz/bin'",
            "set -gx PATH ~/.fuz/bin",
            "set -gx PATH  $PATH",
            "set -gx PATH ~/.fuz/bin $PATH; true",
            "set -x PATH ~/.fuz/bin $PATH",
            // `~` itself, a trailing carriage return, a non-ASCII directory
            "fish_add_path ~",
            "fish_add_path ~/.fuz/bin\r",
            "fish_add_path /opt/café/bin",
            // the POSIX line
            r#"export PATH="$HOME/.fuz/bin:$PATH""#,
        ] {
            assert!(!Shell::Fish.recognizes_path_line(line), "fish: {line:?}");
        }
    }

    /// Fish has two correct lines; a block holding either is already present,
    /// whichever one this run would write. A bare-line match is not enough:
    /// the equivalent has to be the whole body.
    #[test]
    fn plan_rc_update_accepts_either_fish_form() {
        let bin = rc_bin_dir("/home/u/.fuz/bin");
        for supported in [true, false] {
            let line = Shell::Fish.path_line(&bin, supported);
            let equivalent = Shell::Fish
                .equivalent_path_line(&bin, supported)
                .expect("fish has two forms");
            assert_eq!(equivalent, Shell::Fish.path_line(&bin, !supported));
            for held in [&line, &equivalent] {
                assert_eq!(
                    plan_rc_update(&rc_block(held), Shell::Fish, &line, Some(&equivalent)),
                    RcPlan::AlreadyPresent,
                    "supported: {supported}, held: {held}"
                );
            }
            // Either form naming another directory is still stale.
            for stale in ["fish_add_path ~/old/bin", "set -gx PATH ~/old/bin $PATH"] {
                assert_eq!(
                    plan_rc_update(&rc_block(stale), Shell::Fish, &line, Some(&equivalent)),
                    RcPlan::Rewrite(rc_block(&line)),
                    "supported: {supported}, stale: {stale}"
                );
            }
        }
        assert_eq!(
            Shell::Bash.equivalent_path_line(&bin, true),
            None,
            "the POSIX shells have one form"
        );
        assert_eq!(Shell::Zsh.equivalent_path_line(&bin, true), None);
    }

    #[test]
    fn plan_rc_update_matching_block_is_already_present() {
        let block = rc_block(BASH_LINE);
        for existing in [
            block.clone(),
            format!("a=1\n\n{block}b=2\n"),
            format!("a=1\n{}", block.trim_end_matches('\n')),
        ] {
            assert_eq!(
                plan_rc_update(&existing, Shell::Bash, BASH_LINE, None),
                RcPlan::AlreadyPresent,
                "existing: {existing:?}"
            );
        }
    }

    #[test]
    fn plan_rc_update_appends_when_no_marker_exists() {
        let block = rc_block(BASH_LINE);
        for (existing, expected) in [
            (String::new(), format!("\n\n{block}")),
            ("a=1\n".to_owned(), format!("a=1\n\n{block}")),
            ("a=1".to_owned(), format!("a=1\n\n{block}")),
        ] {
            assert_eq!(
                plan_rc_update(&existing, Shell::Bash, BASH_LINE, None),
                RcPlan::Append(expected),
                "existing: {existing:?}"
            );
        }
    }

    /// Every arrangement that isn't exactly one whole-line begin marker
    /// followed by one whole-line end marker is refused, never repaired.
    #[test]
    fn plan_rc_update_refuses_malformed_blocks() {
        let block = rc_block(STALE_LINE);
        for existing in [
            // begin without end
            format!("a=1\n{RC_BEGIN_MARKER}\n{STALE_LINE}\n"),
            // begin as the last bytes of the file
            format!("a=1\n{RC_BEGIN_MARKER}"),
            // end without begin
            format!("a=1\n{RC_END_MARKER}\n"),
            // duplicated block
            format!("{block}{block}"),
            // duplicated end marker
            format!("{block}{RC_END_MARKER}\n"),
            // duplicated begin marker
            format!("{RC_BEGIN_MARKER}\n{block}"),
            // end before begin
            format!("{RC_END_MARKER}\n{STALE_LINE}\n{RC_BEGIN_MARKER}\n"),
            // begin marker not at the start of its line
            format!("  {block}"),
            // begin marker sharing its line with trailing text
            format!("{RC_BEGIN_MARKER} x\n{STALE_LINE}\n{RC_END_MARKER}\n"),
            // end marker not at the start of its line
            format!("{RC_BEGIN_MARKER}\n{STALE_LINE} {RC_END_MARKER}\n"),
            // end marker with trailing text
            format!("{RC_BEGIN_MARKER}\n{STALE_LINE}\n{RC_END_MARKER} x\n"),
            // both markers on one line
            format!("{RC_BEGIN_MARKER}{RC_END_MARKER}\n"),
            // CRLF line endings
            block.replace('\n', "\r\n"),
        ] {
            assert_eq!(
                plan_rc_update(&existing, Shell::Bash, BASH_LINE, None),
                RcPlan::Malformed,
                "existing: {existing:?}"
            );
        }
    }
}
