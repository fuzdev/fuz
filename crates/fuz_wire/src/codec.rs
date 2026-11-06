//! Wire framing helpers.
//!
//! Frame layout (big-endian fields):
//!
//! ```text
//! ┌────────────────┬─────────────────┬───────────────┬────────────┬──────────┐
//! │ total_len (u32)│ request_id (u32)│ action_id(u16)│ flags (u8) │ payload  │
//! └────────────────┴─────────────────┴───────────────┴────────────┴──────────┘
//! ```
//!
//! `total_len` is the byte count of everything *after* itself (header
//! remainder + payload). It bounds payload size and is validated against
//! the caller's limit before any allocation, so a malicious
//! `len = u32::MAX` cannot turn into a multi-GiB read buffer.
//!
//! `flags` carries per-frame stream state ([`FrameFlags`]). A single
//! request/response is one frame with [`FrameFlags::FINAL`] set; a
//! streaming response is many frames against one `request_id`, the last
//! flagged `FINAL` (or, for an open-ended subscription, terminated by the
//! connection closing rather than a `FINAL` frame).

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::actions::{Action, ActionId};
use super::error::ProtoError;

/// Bytes of header after `total_len`: `request_id (4) + action_id (2) +
/// flags (1)`.
pub const HEADER_BYTES: u32 = 7;

/// Per-frame stream flags, carried as one byte after `action_id`.
///
/// The wire-level streaming primitive: a frame is `FINAL` when it is the
/// last (or only) frame for its `request_id`. Single request/response
/// pairs always set `FINAL`; a streaming sender clears it on every frame
/// but the last. Open-ended subscriptions never send a `FINAL` frame —
/// they end when the connection closes.
///
/// Reserved bits stay zero; new flags append without a wire break beyond
/// the meaning of the new bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// No flags set — one frame in the middle of a stream.
    pub const EMPTY: Self = Self(0);
    /// Last (or only) frame for this `request_id`.
    pub const FINAL: Self = Self(0b0000_0001);

    /// Raw byte representation (what goes on the wire).
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Reconstruct from the wire byte. Unknown bits are preserved but
    /// carry no meaning to this version.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Is the `FINAL` bit set?
    #[must_use]
    pub const fn is_final(self) -> bool {
        self.0 & Self::FINAL.0 != 0
    }
}

/// Header parsed off a frame before the payload is decoded.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// Per-connection monotonic id chosen by the initiator. Responses
    /// echo it.
    pub request_id: u32,
    /// Stable wire id of the action carried by the payload.
    pub action: ActionId,
    /// Per-frame stream flags.
    pub flags: FrameFlags,
}

/// Read one frame, validating `total_len` against `limit` before any
/// allocation. Returns the header and the raw payload bytes (for the
/// caller to decode via [`decode_payload`]).
///
/// # Errors
///
/// Returns [`ProtoError::FrameTooLarge`] before allocating if the
/// declared length exceeds the limit, [`ProtoError::FrameTooSmall`] if
/// the declared length is below the header size, or [`ProtoError::Io`]
/// for any underlying socket failure.
pub async fn read_frame<R>(r: &mut R, limit: u32) -> Result<(Header, Vec<u8>), ProtoError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    let total_len = r.read_u32().await?;
    if total_len > limit {
        return Err(ProtoError::FrameTooLarge {
            declared: total_len,
            limit,
        });
    }
    if total_len < HEADER_BYTES {
        return Err(ProtoError::FrameTooSmall {
            declared: total_len,
            header: HEADER_BYTES,
        });
    }
    let request_id = r.read_u32().await?;
    let action_id = r.read_u16().await?;
    let flags = r.read_u8().await?;
    let payload_len = (total_len - HEADER_BYTES) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok((
        Header {
            request_id,
            action: ActionId(action_id),
            flags: FrameFlags::from_bits(flags),
        },
        payload,
    ))
}

/// Write one complete single-frame message.
///
/// Payload is postcard-encoded; the total frame size is checked against
/// `limit` *before* writing the length prefix, so an oversized payload
/// never partially streams onto the wire.
///
/// The frame is flagged [`FrameFlags::FINAL`] — every `write_frame` is a
/// complete message (a request, or a one-shot response). Multi-frame
/// streaming responses use [`write_raw_frame`] with explicit flags.
///
/// # Errors
///
/// Returns [`ProtoError::Encode`] if postcard fails to serialize the
/// payload, [`ProtoError::FrameTooLarge`] if the encoded size exceeds
/// the limit (checked before any byte is written), or [`ProtoError::Io`]
/// on socket failure.
pub async fn write_frame<W, A>(
    w: &mut W,
    request_id: u32,
    payload: &A,
    limit: u32,
) -> Result<(), ProtoError>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
    A: Action + Sync,
{
    let body = postcard::to_allocvec(payload).map_err(ProtoError::Encode)?;
    write_raw_frame(w, request_id, A::ID, FrameFlags::FINAL, &body, limit).await
}

/// Decode a postcard payload from the body bytes returned by [`read_frame`].
///
/// # Errors
///
/// Returns [`ProtoError::Decode`] if the bytes don't postcard-decode to `A`.
pub fn decode_payload<A: Action>(body: &[u8]) -> Result<A, ProtoError> {
    postcard::from_bytes(body).map_err(|source| ProtoError::Decode {
        action: A::ID,
        source,
    })
}

/// Postcard-encode an action's payload. Pairs with [`write_raw_frame`]
/// when the call site needs to detach encoding from framing.
///
/// # Errors
///
/// Returns [`ProtoError::Encode`] if postcard fails to serialize.
pub fn encode_payload<A: Action>(payload: &A) -> Result<Vec<u8>, ProtoError> {
    postcard::to_allocvec(payload).map_err(ProtoError::Encode)
}

/// Write a frame from already-encoded payload bytes, with explicit flags.
///
/// Pairs with [`encode_payload`] when a writer task needs to fan out
/// heterogeneous outgoing frames over one socket — the dispatcher
/// pre-encodes and pushes onto an mpsc channel; the writer task pulls
/// and frames via this function. This is the streaming path: a collector
/// pushes [`FrameFlags::EMPTY`] frames for the stream body and one
/// [`FrameFlags::FINAL`] frame to close a finite stream.
///
/// # Errors
///
/// Returns [`ProtoError::FrameTooLarge`] if `body` exceeds the limit
/// (checked before any byte is written) or [`ProtoError::Io`] on socket
/// failure.
pub async fn write_raw_frame<W>(
    w: &mut W,
    request_id: u32,
    action: ActionId,
    flags: FrameFlags,
    body: &[u8],
    limit: u32,
) -> Result<(), ProtoError>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let body_len = u32::try_from(body.len()).map_err(|_| ProtoError::FrameTooLarge {
        declared: u32::MAX,
        limit,
    })?;
    let total_len = HEADER_BYTES.saturating_add(body_len);
    if total_len > limit {
        return Err(ProtoError::FrameTooLarge {
            declared: total_len,
            limit,
        });
    }
    w.write_u32(total_len).await?;
    w.write_u32(request_id).await?;
    w.write_u16(action.0).await?;
    w.write_u8(flags.bits()).await?;
    if !body.is_empty() {
        w.write_all(body).await?;
    }
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::AuthLevel;
    use crate::messages::{HelloRequest, Ping, Pong};
    use crate::{MAX_FRAME, PROTOCOL_VERSION};
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn round_trip_hello_request() {
        let req = HelloRequest {
            protocol_version: PROTOCOL_VERSION,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, 42, &req, MAX_FRAME).await.unwrap();
        let mut cursor = Cursor::new(buf);
        let (header, body) = read_frame(&mut cursor, MAX_FRAME).await.unwrap();
        assert_eq!(header.request_id, 42);
        assert_eq!(header.action, HelloRequest::ID);
        // write_frame always sets FINAL — a single request is a complete message.
        assert!(header.flags.is_final());
        let decoded: HelloRequest = decode_payload(&body).unwrap();
        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn round_trip_ping_pong() {
        let mut buf = Vec::new();
        write_frame(&mut buf, 1, &Ping, MAX_FRAME).await.unwrap();
        write_frame(&mut buf, 2, &Pong, MAX_FRAME).await.unwrap();
        let mut cursor = Cursor::new(buf);
        let (h1, b1) = read_frame(&mut cursor, MAX_FRAME).await.unwrap();
        assert_eq!(h1.action, Ping::ID);
        let _: Ping = decode_payload(&b1).unwrap();
        let (h2, b2) = read_frame(&mut cursor, MAX_FRAME).await.unwrap();
        assert_eq!(h2.action, Pong::ID);
        let _: Pong = decode_payload(&b2).unwrap();
    }

    #[tokio::test]
    async fn frame_too_large_rejected_before_alloc() {
        // Forge a frame with len = u32::MAX. read_frame must reject
        // *before* trying to allocate a multi-GiB buffer.
        let mut buf = Vec::new();
        buf.write_u32(u32::MAX).await.unwrap();
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor, MAX_FRAME).await.unwrap_err();
        match err {
            ProtoError::FrameTooLarge { declared, limit } => {
                assert_eq!(declared, u32::MAX);
                assert_eq!(limit, MAX_FRAME);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn frame_too_small_rejected() {
        // Anything below HEADER_BYTES is malformed.
        let mut buf = Vec::new();
        buf.write_u32(HEADER_BYTES - 1).await.unwrap();
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor, MAX_FRAME).await.unwrap_err();
        match err {
            ProtoError::FrameTooSmall { declared, header } => {
                assert_eq!(declared, HEADER_BYTES - 1);
                assert_eq!(header, HEADER_BYTES);
            }
            other => panic!("expected FrameTooSmall, got {other:?}"),
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TinyPayload {
        x: u8,
    }
    impl Action for TinyPayload {
        const ID: ActionId = ActionId(0xFFFF);
        const AUTH: AuthLevel = AuthLevel::Keeper;
    }

    #[tokio::test]
    async fn encode_payload_pairs_with_write_raw_frame() {
        let payload = TinyPayload { x: 7 };
        let body = encode_payload(&payload).unwrap();
        let mut buf = Vec::new();
        write_raw_frame(
            &mut buf,
            9,
            TinyPayload::ID,
            FrameFlags::EMPTY,
            &body,
            MAX_FRAME,
        )
        .await
        .unwrap();
        let mut cursor = Cursor::new(buf);
        let (header, decoded_body) = read_frame(&mut cursor, MAX_FRAME).await.unwrap();
        assert_eq!(header.request_id, 9);
        assert_eq!(header.action, TinyPayload::ID);
        assert!(!header.flags.is_final());
        let decoded: TinyPayload = decode_payload(&decoded_body).unwrap();
        assert_eq!(decoded.x, 7);
    }

    #[tokio::test]
    async fn streaming_many_frames_one_request_id() {
        // Three frames against request_id 7: two stream-body frames
        // (EMPTY) then one FINAL. The reader walks frames until FINAL.
        let mut buf = Vec::new();
        for i in 0u8..2 {
            let body = encode_payload(&TinyPayload { x: i }).unwrap();
            write_raw_frame(
                &mut buf,
                7,
                TinyPayload::ID,
                FrameFlags::EMPTY,
                &body,
                MAX_FRAME,
            )
            .await
            .unwrap();
        }
        let body = encode_payload(&TinyPayload { x: 99 }).unwrap();
        write_raw_frame(
            &mut buf,
            7,
            TinyPayload::ID,
            FrameFlags::FINAL,
            &body,
            MAX_FRAME,
        )
        .await
        .unwrap();

        let mut cursor = Cursor::new(buf);
        let mut seen = Vec::new();
        loop {
            let (header, body) = read_frame(&mut cursor, MAX_FRAME).await.unwrap();
            assert_eq!(header.request_id, 7);
            let p: TinyPayload = decode_payload(&body).unwrap();
            seen.push(p.x);
            if header.flags.is_final() {
                break;
            }
        }
        assert_eq!(seen, vec![0, 1, 99]);
    }
}
