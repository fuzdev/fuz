//! SHA512 sidecar checksum files for the install script.
//!
//! The release manifest uses BLAKE3 internally because it's faster and
//! collision-resistant by design, but `b3sum` isn't universally installed.
//! The install script ships as a POSIX shell script and needs to verify the
//! downloaded binary using tools that exist on every system out of the box —
//! `sha512sum` (GNU/Linux) and `shasum -a 512` (macOS).
//!
//! SHA-512 (rather than SHA-256) is the secondary anchor across the whole
//! trust tier, so the bootstrap edge compares the same digest the release
//! witness records. It is exactly as available as SHA-256 at this edge:
//! coreutils ships `sha512sum` beside `sha256sum`, and macOS's `shasum -a 512`
//! is the same script as `-a 256`.
//!
//! For each binary uploaded to flat release layout (`fuz-{version}-{target}`,
//! `fuz-latest-{target}`), we publish a sidecar `.sha512` file with the
//! standard `sha512sum`-compatible line format:
//!
//! ```text
//! <128-char-hex-hash>  <filename>
//! ```
//!
//! Two-space separator (not tab) matches GNU coreutils' "text mode" output, so
//! our sidecars are byte-identical to what `sha512sum > file.sha512` would have
//! produced. `sha512sum -c` itself is permissive (it also accepts a tab, a
//! single space, uppercase hex, and no trailing newline) — the strict shape is
//! a convention we hold ourselves to for reproducibility, not a parser
//! requirement.

use fuz_crypto::ContentHash;

/// Hex-encoded SHA512 of `bytes`. Always 128 lowercase hex chars.
#[must_use]
pub fn sha512_hex(bytes: &[u8]) -> String {
    ContentHash::sha512(bytes).to_hex()
}

/// Format the body of a `.sha512` sidecar file for a binary.
///
/// Produces a single line in `sha512sum` text-mode format:
/// `"{hash_hex}  {filename}\n"` (note the two-space separator).
///
/// The trailing newline is required for POSIX text-file compliance and is
/// what most shasum tools emit; including it keeps round-trips with
/// `sha512sum --check` clean.
#[must_use]
pub fn sidecar_content(filename: &str, hash_hex: &str) -> String {
    format!("{hash_hex}  {filename}\n")
}

/// Parse the body of a `.sha512` sidecar file in the exact shape
/// [`sidecar_content`] writes: one line, `<128 lowercase hex>  <filename>\n`.
///
/// Returns the digest and the file name the line carries. Strict where
/// `sha512sum -c` is permissive — one line, the two-space separator, lowercase
/// hex, the trailing newline — because the shape is the one a publisher writes,
/// and a sidecar in any other shape was not written by one.
///
/// # Errors
///
/// A short description of the first rule the bytes break.
pub fn parse_sidecar(bytes: &[u8]) -> Result<(ContentHash, &str), &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8")?;
    let line = text.strip_suffix('\n').ok_or("no trailing newline")?;
    if line.contains(['\n', '\r']) {
        return Err("more than one line");
    }
    let (hex, filename) = line
        .split_once("  ")
        .ok_or("no two-space separator between digest and file name")?;
    let digest = ContentHash::from_lower_hex(fuz_crypto::HashAlgo::Sha512, hex)
        .map_err(|_| "digest is not 128 lowercase hex characters")?;
    if filename.is_empty() {
        return Err("no file name");
    }
    Ok((digest, filename))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sidecar_reads_what_sidecar_content_writes() {
        let name = "fuz-0.1.0-x86_64-unknown-linux-gnu";
        let digest = ContentHash::sha512(b"binary");
        let line = sidecar_content(name, &digest.to_hex());
        assert_eq!(parse_sidecar(line.as_bytes()), Ok((digest, name)));
    }

    #[test]
    fn parse_sidecar_refuses_every_other_shape() {
        let hex = sha512_hex(b"binary");
        let cases: [(String, &str); 10] = [
            (format!("{hex}  name"), "no trailing newline"),
            (format!("{hex}  name\n{hex}  other\n"), "more than one line"),
            (format!("{hex}  name\r\n"), "more than one line"),
            (format!("{hex} name\n"), "no two-space separator"),
            (format!("{hex}\tname\n"), "no two-space separator"),
            (
                format!("{}  name\n", hex.to_uppercase()),
                "128 lowercase hex",
            ),
            (format!("{}  name\n", &hex[..64]), "128 lowercase hex"),
            (format!("{hex}  \n"), "no file name"),
            // the digest is checked before the file name
            (format!("{}  \n", hex.to_uppercase()), "128 lowercase hex"),
            (String::new(), "no trailing newline"),
        ];
        for (content, reason) in cases {
            let error = parse_sidecar(content.as_bytes()).unwrap_err();
            assert!(error.contains(reason), "{content:?}: {error}");
        }
        assert_eq!(parse_sidecar(&[0xff, b'\n']), Err("not UTF-8"));
    }

    #[test]
    fn sha512_hex_known_vector_empty() {
        // Standard NIST test vector for SHA512("")
        assert_eq!(
            sha512_hex(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn sha512_hex_known_vector_abc() {
        // Standard NIST test vector for SHA512("abc")
        assert_eq!(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha512_hex_is_lowercase_hex() {
        let hex = sha512_hex(b"hello world");
        assert_eq!(hex.len(), 128);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }

    #[test]
    fn sidecar_content_format() {
        let line = sidecar_content("fuz-0.1.0-x86_64-unknown-linux-gnu", "deadbeef");
        assert_eq!(line, "deadbeef  fuz-0.1.0-x86_64-unknown-linux-gnu\n");
    }

    #[test]
    fn sidecar_content_two_space_separator() {
        // Two spaces, not one, not tab — matches `sha512sum` text-mode output
        let line = sidecar_content("name", "hash");
        assert!(line.contains("hash  name"), "must use two-space separator");
        assert!(!line.contains("hash\tname"), "must not use tab");
    }

    #[test]
    fn sidecar_content_ends_with_newline() {
        let line = sidecar_content("x", "y");
        assert!(line.ends_with('\n'));
    }

    /// A sidecar we produce verifies against the real `sha512sum -c`.
    ///
    /// What this pins: **our producer agrees with the actual tool**. The
    /// vectors above pin `sha512_hex` against NIST and the shell suite pins
    /// `sha512sum` against the install script, but nothing else feeds *our
    /// output* to *the real binary* — the round-trip this module's docs
    /// promise.
    ///
    /// What it does *not* pin: the line format. `sha512sum -c` is far more
    /// permissive than our format — it accepts a single space, a tab, uppercase
    /// hex, leading whitespace, and a missing trailing newline. So the
    /// two-space-plus-newline shape is a convention we hold ourselves to
    /// (pinned by `sidecar_content_two_space_separator` /
    /// `sidecar_content_ends_with_newline`), **not** something `-c` enforces.
    /// Don't expect this test to catch a format regression.
    ///
    /// Skips when `sha512sum` is absent rather than failing — the tool is not a
    /// build requirement.
    #[test]
    fn sidecar_round_trips_through_sha512sum_check() {
        use std::process::Command;

        if Command::new("sha512sum").arg("--version").output().is_err() {
            eprintln!("skipping: sha512sum not available");
            return;
        }

        let dir = std::env::temp_dir().join(format!(
            "fuz_sidecar_{}",
            fuz_sys::rand::random_hex_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let name = "fuz-0.1.0-x86_64-unknown-linux-gnu";
        let bytes = b"not a real binary, but the bytes are what get hashed";
        std::fs::write(dir.join(name), bytes).expect("write payload");
        std::fs::write(
            dir.join(format!("{name}.sha512")),
            sidecar_content(name, &sha512_hex(bytes)),
        )
        .expect("write sidecar");

        // `-c` resolves the filename recorded *inside* the sidecar, so run from
        // the dir holding both — the same coupling the published install docs
        // depend on.
        let ok = Command::new("sha512sum")
            .arg("-c")
            .arg(format!("{name}.sha512"))
            .current_dir(&dir)
            .output()
            .expect("run sha512sum -c");
        assert!(
            ok.status.success(),
            "sha512sum -c rejected our own sidecar: {}",
            String::from_utf8_lossy(&ok.stderr)
        );

        // And it must reject tampered bytes — otherwise the check above could
        // pass for reasons unrelated to the digest.
        std::fs::write(dir.join(name), b"tampered").expect("tamper");
        let tampered = Command::new("sha512sum")
            .arg("-c")
            .arg(format!("{name}.sha512"))
            .current_dir(&dir)
            .output()
            .expect("run sha512sum -c");
        assert!(
            !tampered.status.success(),
            "sha512sum -c accepted tampered bytes"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
