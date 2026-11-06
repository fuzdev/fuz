//! Shared unit-test helpers for `fuzi_core` — SRI builders, a fixed test host,
//! and a gzipped-tar fixture builder. Consolidated here so each module's
//! `mod tests` reaches for the same primitives instead of re-deriving them.

#![cfg(test)]

use std::io::Write as _;

use fuz_crypto::ContentHash;

use crate::entry::{Integrity, IntegrityParse};
use crate::platform::{Cpu, Libc, Os, Platform};

/// The `sha512-<base64>` SRI string of `data` — the form an npm `integrity`
/// field carries.
pub fn sha512_sri(data: &[u8]) -> String {
    ContentHash::sha512(data).to_sri()
}

/// The `sha256-<base64>` SRI string of `data` (for the weaker-hash test paths).
pub fn sha256_sri(data: &[u8]) -> String {
    ContentHash::sha256(data).to_sri()
}

/// Build an [`Integrity`] from raw bytes — its sha512 is the cache key.
pub fn integrity_of(data: &[u8]) -> Integrity {
    match Integrity::parse(Some(&sha512_sri(data))) {
        IntegrityParse::Ok(i) => i,
        other => panic!("expected Ok integrity, got {other:?}"),
    }
}

/// The canonical test host: linux / x64 / glibc.
pub fn host_linux_x64_glibc() -> Platform {
    Platform {
        os: Os::Linux,
        cpu: Cpu::X64,
        libc: Some(Libc::Glibc),
    }
}

/// One regular-file tar entry — the common case for [`gz_tar`].
pub fn reg<'a>(
    name: &'a str,
    mode: u32,
    data: &'a [u8],
) -> (&'a str, u32, tar::EntryType, &'a [u8]) {
    (name, mode, tar::EntryType::Regular, data)
}

/// Build a gzipped tar from `(path, mode, type, data)` entries. Pair with
/// [`reg`] for the regular-file case: `gz_tar(&[reg("package/x", 0o644, b"…")])`.
pub fn gz_tar(entries: &[(&str, u32, tar::EntryType, &[u8])]) -> Vec<u8> {
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        for (name, mode, ty, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("set path");
            header.set_entry_type(*ty);
            header.set_size(data.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            builder.append(&header, &data[..]).expect("append");
        }
        builder.finish().expect("finish tar");
    }
    gz(&tar_data)
}

/// A mode-`0644` tar header carrying `name` verbatim — for adversarial names
/// (`..`, absolute) the `tar` builder's `set_path` refuses to write but a
/// reader must still defend against. `name` must fit the 100-byte field.
pub fn raw_header(name: &[u8], ty: tar::EntryType, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.as_old_mut().name[..name.len()].copy_from_slice(name);
    header.set_entry_type(ty);
    header.set_mode(0o644);
    header.set_size(size);
    header.set_cksum();
    header
}

/// Build a gzipped tar from prebuilt `(header, body)` pairs (see
/// [`raw_header`]), end-of-archive marker included.
pub fn gz_raw_tar(entries: &[(tar::Header, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (header, body) in entries {
        builder.append(header, *body).expect("append");
    }
    gz(&builder.into_inner().expect("finish tar"))
}

/// gzip `data` as one member.
pub fn gz(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).expect("gz write");
    enc.finish().expect("gz finish")
}

/// A no-follow listing of everything under `dir`: one `path kind mode size`
/// line per entry (a symlink also carries its text), sorted. Comparing two
/// listings is how a test proves a link target was left alone — a created,
/// removed, retyped, chmodded, or resized entry changes it.
pub fn tree_listing(dir: &std::path::Path) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt as _;

    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            let meta = std::fs::symlink_metadata(&path).expect("lstat");
            let rel = path.strip_prefix(root).expect("under root").display();
            let mode = meta.permissions().mode() & 0o7777;
            if meta.file_type().is_symlink() {
                let text = std::fs::read_link(&path).expect("readlink");
                out.push(format!("{rel} link -> {}", text.display()));
            } else if meta.is_dir() {
                out.push(format!("{rel} dir {mode:o}"));
                walk(root, &path, out);
            } else {
                out.push(format!("{rel} file {mode:o} {}", meta.len()));
            }
        }
    }

    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}
