//! Chrome/Firefox native-messaging framing: a 4-byte little-endian length
//! prefix followed by that many bytes of UTF-8 JSON, in both directions.

use serde_json::Value;
use std::io::{self, Read, Write};

/// Messages larger than this are rejected before we allocate a buffer for
/// them. Chrome's own limit for host -> extension messages is 1 MiB; we
/// apply the same cap in both directions so a malformed or hostile length
/// prefix can't be used to force a large allocation.
const MAX_MESSAGE_BYTES: u32 = 1024 * 1024;

#[derive(Debug)]
pub enum ReadError {
    Eof,
    TooLarge(u32),
    Io(io::Error),
    Json(serde_json::Error),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

/// Reads one framed message from `r`. Returns `Err(ReadError::Eof)` when the
/// stream is closed cleanly at a message boundary (the normal shutdown path
/// when the browser disconnects the port).
pub fn read_message<R: Read>(r: &mut R) -> Result<Value, ReadError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(ReadError::Eof),
        Err(e) => return Err(ReadError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE_BYTES {
        return Err(ReadError::TooLarge(len));
    }

    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(ReadError::Json)
}

/// Writes one framed message to `w` and flushes it immediately, matching the
/// original host's behavior of flushing after every reply.
pub fn write_message<W: Write>(w: &mut W, value: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(value)?;
    let len = body.len().min(u32::MAX as usize) as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}
