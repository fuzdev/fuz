//! The decompression budget: [`BudgetReader`] charges every decompressed byte
//! against the total-size and ratio ceilings and holds reads inside the armed
//! header window (see the crate-level *Decompression budget* section).

use std::cell::{Cell, RefCell};
use std::io::Read;

use crate::ExtractLimits;
use crate::error::ArchiveError;

/// The decompression budget: counts every byte the gzip decoder yields to the
/// tar reader and [`charge`]s it, so the total-size and ratio ceilings bound the
/// whole decompressed stream, and holds reads inside the header window while
/// [`safe_extract`](crate::safe_extract) has one armed (see the crate-level
/// *Decompression budget* section). A violation surfaces as an `io::Error`
/// wrapping the [`ArchiveError`], which
/// [`tar_error`](crate::error::tar_error) unwraps back out of the tar layer.
///
/// `decompressed_size` is also the tar reader's stream position: `tar` reads
/// only through this reader, so the two count the same bytes.
pub struct BudgetReader<'w, R> {
    pub inner: R,
    pub decompressed_size: u64,
    pub compressed_size: u64,
    pub limits: ExtractLimits,
    /// The armed header window, `None` while `safe_extract` reads an entry's
    /// data. Shared with `safe_extract`, which can't reach the reader once
    /// `tar::Archive` owns it.
    pub header_window: &'w Cell<Option<HeaderWindow>>,
    /// Every byte read at or past the armed window's `start`: the header
    /// blocks and extension bodies of one iterator step, which
    /// [`check_one_reading`](crate::one_reading::check_one_reading) re-reads.
    /// The window's limit bounds it to [`ExtractLimits::max_header_size`].
    pub captured: &'w RefCell<Vec<u8>>,
}

/// One iterator step's header window: reads may not pass `limit`, and what is
/// read at or past `start` (the previous entry's padded body end) is captured.
#[derive(Debug, Clone, Copy)]
pub struct HeaderWindow {
    pub start: u64,
    pub limit: u64,
}

impl<R: Read> Read for BudgetReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let window = self.header_window.get();
        let buf = match window {
            Some(HeaderWindow { limit, .. }) => {
                // Clamp the read to the window, so a body crossing it is
                // refused before its bytes are decompressed, not after one
                // oversized read. A request at the limit asks for more than the
                // window allows.
                let room = limit.saturating_sub(self.decompressed_size);
                if room == 0 && !buf.is_empty() {
                    return Err(std::io::Error::other(ArchiveError::HeaderTooLarge(
                        self.limits.max_header_size,
                    )));
                }
                let len = usize::try_from(room).map_or(buf.len(), |room| buf.len().min(room));
                &mut buf[..len]
            }
            None => buf,
        };
        let offset = self.decompressed_size;
        let n = self.inner.read(buf)?;
        charge(
            &mut self.decompressed_size,
            n as u64,
            self.compressed_size,
            &self.limits,
        )
        .map_err(std::io::Error::other)?;
        if let Some(HeaderWindow { start, .. }) = window {
            // The unread rest of a skipped body lies before `start`; only what
            // follows it is header data.
            let skip = usize::try_from(start.saturating_sub(offset)).map_or(n, |skip| skip.min(n));
            self.captured.borrow_mut().extend_from_slice(&buf[skip..n]);
        }
        Ok(n)
    }
}

/// Charge `delta` decompressed bytes against the denial-of-service budget: fold
/// them into the running `decompressed_size`, then enforce the total-size and
/// compression-ratio ceilings **in that order** (total before ratio). Called by
/// [`BudgetReader`] on every read of the decompressed stream.
///
/// `compressed_size` must be non-zero (guaranteed at [`safe_extract`](crate::safe_extract) entry);
/// the ratio is integer division.
pub const fn charge(
    decompressed_size: &mut u64,
    delta: u64,
    compressed_size: u64,
    limits: &ExtractLimits,
) -> Result<(), ArchiveError> {
    *decompressed_size += delta;
    if *decompressed_size > limits.max_total_size {
        return Err(ArchiveError::TotalTooLarge(*decompressed_size));
    }
    let ratio = *decompressed_size / compressed_size;
    if ratio > limits.max_compression_ratio {
        return Err(ArchiveError::CompressionBomb(ratio));
    }
    Ok(())
}
