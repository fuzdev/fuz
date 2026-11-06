//! Response-body bounds shared by the HTTP backends (`ForgeStorage`,
//! `HttpsStorage`).
//!
//! A response body is untrusted-size input: `Content-Length` is a hint the
//! server chooses, so the bound that holds is a byte counter enforced while
//! the body streams. The helpers here carry that counter, so each HTTP backend
//! applies the same rule rather than re-deriving it, alongside the request
//! deadline they share. [`download_body_to_file`] is the streaming download
//! both backends end in, so they also agree on what a failed one leaves at
//! its destination.

use std::path::Path;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::error::{StorageBackendKind, StorageError};

/// Total deadline for one request, from connect through the end of the
/// response body (5 minutes).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// What a body transfer is bounded by and how its failures are labeled.
#[derive(Debug, Clone, Copy)]
pub struct BodyLimit<'a> {
    /// Backend identity for the error.
    pub backend: StorageBackendKind,
    /// The storage key being transferred, as reported in the error.
    pub path: &'a str,
    /// Maximum body size in bytes.
    pub max: u64,
}

impl BodyLimit<'_> {
    fn too_large(&self, size: u64) -> StorageError {
        StorageError::TooLarge {
            backend: self.backend,
            path: self.path.to_string(),
            size,
            max: self.max,
        }
    }

    const fn failed(&self, message: String) -> StorageError {
        StorageError::DownloadFailed {
            backend: self.backend,
            message,
        }
    }
}

/// Render a request error with its causes.
///
/// `reqwest::Error`'s own `Display` names the failed phase and URL; the reason
/// — a timeout, a TLS failure, a refused redirect — is in the source chain.
pub fn error_chain(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// Most bytes of an error response's body [`read_error_text`] reads.
///
/// More than a `StorageError` message shows of it. A longer body is shown as
/// its start and the end of what was read, not the end of the body.
pub const MAX_ERROR_BODY_LEN: usize = 2 * crate::error::MAX_SHOWN_MESSAGE_LEN;

/// Refuse a response whose declared `Content-Length` already exceeds the limit,
/// before any of the body is read.
///
/// A fast path only — an absent or understated length passes, and the
/// mid-stream counter in [`read_body_capped`] / `write_body_capped` is the
/// bound that holds.
pub fn check_content_length(
    response: &reqwest::Response,
    limit: &BodyLimit<'_>,
) -> Result<(), StorageError> {
    match response.content_length() {
        Some(len) if len > limit.max => Err(limit.too_large(len)),
        _ => Ok(()),
    }
}

/// Buffer a response body into memory, aborting as soon as it passes the limit.
///
/// The body is read one chunk at a time against a running byte counter, so an
/// oversized body costs at most the limit plus one chunk of memory however the
/// server framed it.
pub async fn read_body_capped(
    response: &mut reqwest::Response,
    limit: &BodyLimit<'_>,
) -> Result<Vec<u8>, StorageError> {
    let mut body = Vec::new();
    let mut total: u64 = 0;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| limit.failed(format!("failed to read body: {}", error_chain(&e))))?
    {
        total = total.saturating_add(chunk.len() as u64);
        if total > limit.max {
            return Err(limit.too_large(total));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The start of an error response's body as text, for a message.
///
/// At most [`MAX_ERROR_BODY_LEN`] bytes, read one chunk at a time. A longer
/// body is cut there and the rest is not read, so an error response costs the
/// same memory whatever the server sends with it.
///
/// Best-effort, like the message it feeds: a body that fails mid-read yields
/// what arrived, and bytes that are not UTF-8 are replaced. The text is the
/// server's, unescaped — the type that renders it escapes it there.
pub async fn read_error_text(response: &mut reqwest::Response) -> String {
    let mut body = Vec::new();
    while body.len() < MAX_ERROR_BODY_LEN {
        let Ok(Some(chunk)) = response.chunk().await else {
            break;
        };
        let take = chunk.len().min(MAX_ERROR_BODY_LEN - body.len());
        body.extend_from_slice(&chunk[..take]);
    }
    String::from_utf8_lossy(&body).into_owned()
}

/// Stream a successful response's body into a file created at `dest`, bounded
/// by `limit`. Returns the bytes written.
///
/// A declared `Content-Length` over the limit is refused before `dest` is
/// created, so that refusal leaves whatever was at `dest` as it was. Once the
/// file is created — which truncates a file already there, and follows a
/// symlink already there — a failure of any kind (an overrun mid-stream, a
/// truncated, reset, or stalled body, a write or flush error) unlinks the path
/// `dest`, so the caller never sees a partial download. For a symlink it is
/// the link, not its target, that is removed.
pub async fn download_body_to_file(
    response: &mut reqwest::Response,
    dest: &Path,
    limit: &BodyLimit<'_>,
) -> Result<u64, StorageError> {
    check_content_length(response, limit)?;
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| limit.failed(format!("create {} failed: {e}", dest.display())))?;
    let result = write_body_capped(response, &mut file, dest, limit).await;
    if result.is_err() {
        drop(file);
        let _ = tokio::fs::remove_file(dest).await;
    }
    result
}

/// Stream a response body into `file` one chunk at a time (bounded memory),
/// aborting as soon as it passes the limit. Returns the bytes written.
///
/// `dest` only labels the error messages. On an error the file is left as
/// written so far; [`download_body_to_file`] unlinks it.
async fn write_body_capped(
    response: &mut reqwest::Response,
    file: &mut tokio::fs::File,
    dest: &Path,
    limit: &BodyLimit<'_>,
) -> Result<u64, StorageError> {
    let mut total: u64 = 0;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| limit.failed(format!("stream read failed: {}", error_chain(&e))))?
    {
        total = total.saturating_add(chunk.len() as u64);
        if total > limit.max {
            return Err(limit.too_large(total));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| limit.failed(format!("write to {} failed: {e}", dest.display())))?;
    }
    file.flush()
        .await
        .map_err(|e| limit.failed(format!("flush {} failed: {e}", dest.display())))?;
    Ok(total)
}
