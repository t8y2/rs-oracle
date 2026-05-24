//! Streaming LOB reader for progressive large object access.
//!
//! Reads LOB data chunk by chunk without loading the entire content into memory,
//! similar to `Blob.getBinaryStream()` / `Clob.getCharacterStream()` in JDBC.

use crate::connection::Connection;
use crate::error::Result;
use crate::types::{LobData, LobLocator};

/// A streaming reader for LOB data.
///
/// Reads LOB content progressively in chunks, avoiding full materialization
/// in memory. Use this for large CLOBs/BLOBs that would exceed memory limits.
///
/// # Example
///
/// ```rust,ignore
/// let stream = conn.lob_stream(&locator, 8192);
/// while let Some(chunk) = stream.next().await? {
///     match chunk {
///         LobData::Bytes(b) => writer.write_all(&b)?,
///         LobData::String(s) => writer.write_all(s.as_bytes())?,
///     }
/// }
/// ```
pub struct LobStream {
    conn: Connection,
    locator: LobLocator,
    chunk_size: u64,
    offset: u64,
    total_size: u64,
    finished: bool,
}

impl LobStream {
    /// Create a new LOB stream.
    ///
    /// # Arguments
    /// * `conn` - The database connection
    /// * `locator` - The LOB locator returned from a query
    /// * `chunk_size` - Bytes per chunk (0 = use Oracle's natural chunk size)
    pub fn new(conn: Connection, locator: LobLocator, chunk_size: u64) -> Self {
        let total_size = locator.size();
        Self {
            conn,
            locator,
            chunk_size: if chunk_size == 0 { 8192 } else { chunk_size },
            offset: 1, // Oracle LOB offsets are 1-based
            total_size,
            finished: total_size == 0,
        }
    }

    /// Read the next chunk from the LOB.
    ///
    /// Returns `None` when the entire LOB has been read.
    pub async fn next(&mut self) -> Result<Option<LobData>> {
        if self.finished {
            return Ok(None);
        }

        if self.offset > self.total_size {
            self.finished = true;
            return Ok(None);
        }

        let remaining = self.total_size - self.offset + 1;
        let amount = std::cmp::min(remaining, self.chunk_size);

        let chunk = self
            .conn
            .read_lob_range(&self.locator, self.offset, amount)
            .await?;

        self.offset += amount;

        if self.offset > self.total_size {
            self.finished = true;
        }

        Ok(Some(chunk))
    }

    /// Get the total size of the LOB in bytes.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Get the number of bytes remaining to be read.
    pub fn remaining(&self) -> u64 {
        if self.finished {
            0
        } else {
            self.total_size - self.offset + 1
        }
    }

    /// Check if the stream has been fully consumed.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Consume all remaining chunks and concatenate into a single `LobData`.
    pub async fn collect(mut self) -> Result<LobData> {
        let mut chunks: Vec<LobData> = Vec::new();
        while let Some(chunk) = self.next().await? {
            chunks.push(chunk);
        }
        LobData::merge(chunks)
    }
}

impl LobData {
    /// Merge multiple LOB data chunks into one.
    fn merge(chunks: Vec<LobData>) -> Result<LobData> {
        if chunks.is_empty() {
            return Ok(LobData::Bytes(bytes::Bytes::new()));
        }

        // Check if we're dealing with strings or bytes
        let first_is_string = matches!(&chunks[0], LobData::String(_));

        if first_is_string {
            let mut result = String::new();
            for chunk in chunks {
                match chunk {
                    LobData::String(s) => result.push_str(&s),
                    LobData::Bytes(b) => result.push_str(&String::from_utf8_lossy(&b)),
                }
            }
            Ok(LobData::String(result))
        } else {
            let mut result = Vec::new();
            for chunk in chunks {
                match chunk {
                    LobData::Bytes(b) => result.extend_from_slice(&b),
                    LobData::String(s) => result.extend_from_slice(s.as_bytes()),
                }
            }
            Ok(LobData::Bytes(result.into()))
        }
    }
}
