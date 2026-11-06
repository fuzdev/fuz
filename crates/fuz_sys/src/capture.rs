//! Bounded subprocess-pipe capture.
//!
//! The shared halves of the capped-capture protocol: read a child's pipe
//! keeping at most a cap's bytes, either stopping at the cap (the value
//! channel — the caller kills the child, since output past the cap is
//! unusable anyway) or draining the remainder to EOF discarding it (the
//! diagnostic channel — the writer must never block on a full pipe while the
//! child is still doing useful work).
//!
//! Callers own the orchestration around these (which pipes to join, when to
//! kill, how to surface truncation); `fuz_eval::eval_module` and
//! `fuz_storage`'s ssh backend are the two consumers, and the shared ceilings
//! live in [`crate::limits`].

use tokio::io::{AsyncRead, AsyncReadExt};

/// A bounded pipe capture — at most the cap's bytes kept, plus whether the
/// stream ran past it.
#[derive(Debug)]
pub struct CappedCapture {
    /// The captured bytes, truncated to the cap when `exceeded`.
    pub bytes: Vec<u8>,
    /// Whether the stream held more than the cap.
    pub exceeded: bool,
}

/// Read `reader` keeping at most `cap` bytes, stopping once the cap is
/// exceeded — the caller decides what to do with the still-open stream
/// (a value channel typically kills the subprocess).
///
/// # Errors
///
/// Propagates the underlying read error.
pub async fn read_capped<R: AsyncRead + Unpin>(
    reader: &mut R,
    cap: u64,
) -> std::io::Result<CappedCapture> {
    let mut bytes = Vec::new();
    // One byte past the cap distinguishes exactly-at-cap from over it.
    let mut limited = reader.take(cap.saturating_add(1));
    limited.read_to_end(&mut bytes).await?;
    let exceeded = u64::try_from(bytes.len()).is_ok_and(|n| n > cap);
    if exceeded {
        bytes.pop();
    }
    Ok(CappedCapture { bytes, exceeded })
}

/// Like [`read_capped`], but drain any remainder to EOF, discarding it.
///
/// For a stream whose writer must not block on a full pipe (stderr, while the
/// subprocess may still be doing useful work on the value channel).
///
/// # Errors
///
/// Propagates the underlying read error.
pub async fn read_capped_draining<R: AsyncRead + Unpin>(
    reader: &mut R,
    cap: u64,
) -> std::io::Result<CappedCapture> {
    let capture = read_capped(reader, cap).await?;
    if capture.exceeded {
        tokio::io::copy(reader, &mut tokio::io::sink()).await?;
    }
    Ok(capture)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `read_capped` keeps at most the cap and marks the overrun; exactly-at-cap
    /// is not an overrun.
    #[tokio::test]
    async fn read_capped_marks_exceeded_and_truncates() {
        let data = vec![7u8; 100];
        let mut over: &[u8] = &data;
        let capture = read_capped(&mut over, 64).await.unwrap();
        assert!(capture.exceeded);
        assert_eq!(capture.bytes.len(), 64);

        let mut at: &[u8] = &data;
        let capture = read_capped(&mut at, 100).await.unwrap();
        assert!(!capture.exceeded);
        assert_eq!(capture.bytes, data);
    }

    /// The draining variant consumes the remainder to EOF (so a real pipe's
    /// writer can't block on it) while still keeping only the cap.
    #[tokio::test]
    async fn read_capped_draining_consumes_to_eof() {
        let data = vec![1u8; 100];
        let mut reader: &[u8] = &data;
        let capture = read_capped_draining(&mut reader, 10).await.unwrap();
        assert!(capture.exceeded);
        assert_eq!(capture.bytes.len(), 10);
        assert!(reader.is_empty(), "remainder must be drained to EOF");
    }
}
