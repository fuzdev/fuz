//! Publisher key management (`cargo xtask key …`).
//!
//! Signing-key operations are publisher-only: maintainers generate a keypair
//! and add its public key to `crates/fuz_crypto/src/public_keys.json`. Releases
//! are signed by the publish flow (`cargo xtask publish`, via `fuz_sign`), not
//! here — this surface only manages keys: generate / info / export /
//! list-trusted. End users never run these; release verification happens
//! automatically during `fuz tool install` / `fuz self upgrade` against the
//! embedded trusted keys.

use std::path::PathBuf;

use argh::FromArgs;
use base64::Engine;
use fuz_crypto::PUBLIC_KEYS;
use fuz_sign::{
    KeyFileError, default_key_path, generate_keypair, load_signing_key, serialize_key_file,
};
use fuz_sys::secure_file::{SecureFileError, write_secure_file};
use fuz_sys::{SECURE_FILE_MODE, collapse_tilde, rfc3339_now};
use thiserror::Error;

/// Errors from key operations.
#[derive(Debug, Error)]
pub enum KeyCommandError {
    #[error("key file already exists: {0} (use --force to overwrite)")]
    KeyFileExists(PathBuf),
    /// The new key file could not be written.
    #[error(transparent)]
    SecureFile(#[from] SecureFileError),
    /// The signing key could not be located, read, or parsed.
    #[error(transparent)]
    Key(#[from] KeyFileError),
    #[error("failed to create directory: {0}")]
    CreateDir(PathBuf, #[source] std::io::Error),
    #[error("failed to serialize JSON")]
    Json(#[from] serde_json::Error),
}

impl KeyCommandError {
    /// Returns true if the fuz home, which holds the default key, cannot be
    /// used as configured — the key loader's
    /// [`KeyFileError::is_unusable_home`], forwarded.
    ///
    /// Exhaustive, so a new variant is classified where it is added.
    pub const fn is_unusable_home(&self) -> bool {
        match self {
            Self::Key(e) => e.is_unusable_home(),
            Self::KeyFileExists(_) | Self::SecureFile(_) | Self::CreateDir(..) | Self::Json(_) => {
                false
            }
        }
    }
}

/// Manage signing keys (publisher-only).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "key")]
pub struct Key {
    #[argh(subcommand)]
    nested: KeySub,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum KeySub {
    Generate(KeyGenerate),
    Info(KeyInfo),
    Export(KeyExport),
    ListTrusted(KeyListTrusted),
}

/// Generate a new signing keypair.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "generate")]
struct KeyGenerate {
    /// output path (default: `$FUZ_HOME/config/signing.key`)
    #[argh(option, short = 'o')]
    output: Option<PathBuf>,

    /// overwrite existing key file
    #[argh(switch, short = 'f')]
    force: bool,
}

/// Show key info (public key, created date).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "info")]
struct KeyInfo {
    /// key file path (default: `$FUZ_HOME/config/signing.key`)
    #[argh(option, short = 'k')]
    key_file: Option<PathBuf>,

    /// JSON output
    #[argh(switch)]
    json: bool,
}

/// Print public key only (for `public_keys.json`).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "export")]
struct KeyExport {
    /// key file path (default: `$FUZ_HOME/config/signing.key`)
    #[argh(option, short = 'k')]
    key_file: Option<PathBuf>,
}

/// Show embedded trusted public keys.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list-trusted")]
struct KeyListTrusted {}

/// Dispatch `cargo xtask key …`.
pub fn cmd_key(args: Key) -> Result<(), KeyCommandError> {
    match args.nested {
        KeySub::Generate(opts) => cmd_key_generate(opts),
        KeySub::Info(opts) => cmd_key_info(&opts),
        KeySub::Export(opts) => cmd_key_export(&opts),
        KeySub::ListTrusted(_) => cmd_key_list_trusted(),
    }
}

fn cmd_key_generate(args: KeyGenerate) -> Result<(), KeyCommandError> {
    let key_path = match args.output {
        Some(p) => p,
        None => default_key_path()?,
    };

    if !args.force && key_path.exists() {
        return Err(KeyCommandError::KeyFileExists(key_path));
    }

    if let Some(parent) = key_path.parent()
        && !parent.exists()
    {
        // The default parent is `~/.fuz/config/`, which is about to hold a
        // private signing key. `write_secure_file` lands the key itself at
        // 0600, but an umask-derived directory around it would still let
        // another local user unlink and replace it, so state the mode.
        fuz_sys::fs::create_dir_all_mode(parent, fuz_sys::SECURE_DIR_MODE)
            .map_err(|e| KeyCommandError::CreateDir(parent.to_path_buf(), e))?;
    }

    let key = generate_keypair();
    let created = rfc3339_now();
    let bytes = serialize_key_file(&key, &created);
    write_secure_file(&key_path, &bytes, SECURE_FILE_MODE)?;

    let public_key =
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
    println!("Signing key generated: {}", collapse_tilde(&key_path));
    println!("Public key: {public_key}");
    println!();
    println!("To use this key for releases, add the public key to:");
    println!("  crates/fuz_crypto/src/public_keys.json");

    Ok(())
}

fn cmd_key_info(args: &KeyInfo) -> Result<(), KeyCommandError> {
    let loaded = load_signing_key(args.key_file.as_deref())?;
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(loaded.key.verifying_key().as_bytes());

    if args.json {
        let info = serde_json::json!({
            "algorithm": "ed25519",
            "public_key": public_key,
            "file": collapse_tilde(&loaded.path),
            "created": loaded.metadata.created,
        });
        println!("{}", serde_json::to_string(&info)?);
    } else {
        println!("Algorithm:  ed25519");
        println!("Public key: {public_key}");
        println!("File:       {}", collapse_tilde(&loaded.path));
        println!("Created:    {}", loaded.metadata.created);
    }

    Ok(())
}

fn cmd_key_export(args: &KeyExport) -> Result<(), KeyCommandError> {
    let loaded = load_signing_key(args.key_file.as_deref())?;
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(loaded.key.verifying_key().as_bytes());
    println!("{public_key}");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)] // consistent with the other cmd_key_* signatures
fn cmd_key_list_trusted() -> Result<(), KeyCommandError> {
    println!("Trusted public keys ({} embedded):", PUBLIC_KEYS.len());
    for key_bytes in PUBLIC_KEYS {
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        println!("  {key_b64}");
    }
    Ok(())
}
