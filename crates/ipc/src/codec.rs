//! Newline-delimited JSON framing over any `Read`/`Write` (R1).
//!
//! Each protocol message is one JSON object serialized with no embedded literal
//! newline (JSON escapes `\n` inside strings, so `\n` is an unambiguous frame
//! terminator), followed by one `0x0A` byte. The codec is a pure function over
//! any [`std::io::Read`]/[`std::io::Write`] pair, so it is exercisable over a
//! [`std::io::Cursor`] or `socketpair` without a real socket or root.

use std::io::{BufRead, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Maximum single-frame length in bytes (excluding the terminating newline). A
/// longer line is a protocol error that closes the connection; reads never
/// allocate beyond this bound.
pub const MAX_FRAME: usize = 1024 * 1024;

/// A framing or (de)serialization failure.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The underlying stream returned an I/O error.
    #[error("codec io error: {0}")]
    Io(#[from] std::io::Error),
    /// The payload was not valid JSON for the target type.
    #[error("codec json error: {0}")]
    Json(#[from] serde_json::Error),
    /// A frame exceeded [`MAX_FRAME`] bytes.
    #[error("frame exceeds MAX_FRAME ({MAX_FRAME} bytes)")]
    FrameTooLarge,
    /// The stream reached EOF at a frame boundary (peer closed the connection).
    #[error("connection closed")]
    Closed,
    /// The stream ended mid-frame without a terminating newline.
    #[error("truncated frame")]
    Truncated,
}

/// Serialize `msg` as one JSON line and write it, then flush. Fails with
/// [`CodecError::FrameTooLarge`] before writing if the encoding exceeds
/// [`MAX_FRAME`].
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<(), CodecError> {
    let mut bytes = serde_json::to_vec(msg)?;
    if bytes.len() > MAX_FRAME {
        return Err(CodecError::FrameTooLarge);
    }
    bytes.push(b'\n');
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

/// Read one newline-delimited JSON frame and deserialize it into `T`.
///
/// Returns [`CodecError::Closed`] if the peer closed cleanly at a frame
/// boundary, [`CodecError::FrameTooLarge`] if the line exceeds [`MAX_FRAME`]
/// (the read is bounded — it never allocates past the limit), and
/// [`CodecError::Truncated`] on EOF mid-frame.
pub fn read_message<R: BufRead, T: DeserializeOwned>(reader: &mut R) -> Result<T, CodecError> {
    // Scan the buffered stream a chunk at a time, copying up to the newline
    // while enforcing MAX_FRAME — so an oversized line is rejected without ever
    // allocating past the bound (a plain `read_until` would grow unboundedly).
    let mut buf = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(CodecError::Io(err)),
        };
        if available.is_empty() {
            // EOF: clean at a frame boundary, or truncated mid-frame.
            if buf.is_empty() {
                return Err(CodecError::Closed);
            }
            return Err(CodecError::Truncated);
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > MAX_FRAME {
                return Err(CodecError::FrameTooLarge);
            }
            let (head, _) = available.split_at(pos); // exclude the newline
            buf.extend_from_slice(head);
            reader.consume(pos + 1); // consume through the newline
            break;
        }
        if buf.len() + available.len() > MAX_FRAME {
            return Err(CodecError::FrameTooLarge);
        }
        let consumed = available.len();
        buf.extend_from_slice(available);
        reader.consume(consumed);
    }
    let value = serde_json::from_slice(&buf)?;
    Ok(value)
}

#[cfg(test)]
#[path = "codec_test.rs"]
mod codec_test;
