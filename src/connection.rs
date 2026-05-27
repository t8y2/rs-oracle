//! Oracle database connection
//!
//! This module provides the main `Connection` type for interacting with Oracle databases.
//!
//! # Example
//!
//! ```rust,ignore
//! use rust_oracle::{Connection, Config};
//!
//! #[tokio::main]
//! async fn main() -> rust_oracle::Result<()> {
//!     // Create a connection
//!     let conn = Connection::connect("localhost:1521/ORCLPDB1", "user", "password").await?;
//!
//!     // Execute a query
//!     let rows = conn.query("SELECT * FROM employees WHERE department_id = :1", &[&10]).await?;
//!
//!     for row in rows {
//!         println!("{:?}", row);
//!     }
//!
//!     // Commit and close
//!     conn.commit().await?;
//!     conn.close().await?;
//!     Ok(())
//! }
//! ```

use bytes::Bytes;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::batch::{BatchBinds, BatchResult};
use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::capabilities::Capabilities;
use crate::config::{Config, ServiceMethod};
use crate::constants::{
    ccap_value, BindDirection, DEFAULT_STREAM_FETCH_SIZE, FetchOrientation, FunctionCode,
    MessageType, MAX_VARCHAR_SQL,
    OracleType, PacketType, PACKET_HEADER_SIZE,
};
use crate::cursor::{ScrollResult, ScrollableCursor};
use crate::error::{Error, Result};
use crate::implicit::{ImplicitResult, ImplicitResults};
use crate::lob_stream::LobStream;
use crate::messages::{
    AcceptMessage, AuthMessage, AuthPhase, ConnectMessage, ExecuteMessage, ExecuteOptions,
    LobOpMessage, RedirectMessage,
};
use crate::packet::Packet;
use crate::protocol::parser::{parse_type_name, ProtocolParser};
use crate::row::{Row, Value};
use crate::statement::{BindParam, ColumnInfo, Statement, StatementType};
use crate::statement_cache::StatementCache;
use crate::transport::{connect_tls, TlsConfig, TlsOracleStream};
use crate::types::{LobData, LobLocator, LobValue};

/// Transaction isolation level.
///
/// Corresponds to Oracle's transaction isolation modes:
/// - `ReadCommitted` (default) — each query sees committed data as of statement start
/// - `Serializable` — each transaction sees data as of transaction start
/// - `ReadOnly` — serializable + no writes allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransactionIsolation {
    /// Read committed (default Oracle behavior)
    #[default]
    ReadCommitted,
    /// Serializable isolation
    Serializable,
    /// Read only (serializable + no DML)
    ReadOnly,
}

impl TransactionIsolation {
    /// Convert to the SQL SET TRANSACTION statement
    fn to_sql(self) -> &'static str {
        match self {
            TransactionIsolation::ReadCommitted => "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
            TransactionIsolation::Serializable => "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            TransactionIsolation::ReadOnly => "SET TRANSACTION READ ONLY",
        }
    }

}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// TCP connection established
    Connected,
    /// Protocol negotiation complete
    ProtocolNegotiated,
    /// Data types negotiated
    DataTypesNegotiated,
    /// Fully authenticated and ready
    Ready,
    /// Connection is closed
    Closed,
}

/// Options for query execution
#[derive(Debug, Clone)]
pub struct QueryOptions {
    /// Number of rows to prefetch
    pub prefetch_rows: u32,
    /// Array size for batch operations
    pub array_size: u32,
    /// Whether to auto-commit after DML
    pub auto_commit: bool,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            prefetch_rows: 100,
            array_size: 100,
            auto_commit: false,
        }
    }
}

/// Result set from a query
#[derive(Debug)]
pub struct QueryResult {
    /// Column information
    pub columns: Vec<ColumnInfo>,
    /// Rows returned
    pub rows: Vec<Row>,
    /// Number of rows affected (for DML)
    pub rows_affected: u64,
    /// Whether there are more rows to fetch
    pub has_more_rows: bool,
    /// Cursor ID for subsequent fetches (needed for fetch_more)
    pub cursor_id: u16,
}

impl QueryResult {
    /// Create an empty query result
    pub fn empty() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
        }
    }

    /// Get the number of columns
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get the number of rows
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Check if the result is empty
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get a column by name
    pub fn column_by_name(&self, name: &str) -> Option<&ColumnInfo> {
        self.columns
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// Get column index by name
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// Iterate over rows
    pub fn iter(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter()
    }

    /// Get a single row (first row)
    pub fn first(&self) -> Option<&Row> {
        self.rows.first()
    }
}

impl IntoIterator for QueryResult {
    type Item = Row;
    type IntoIter = std::vec::IntoIter<Row>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

/// Result from executing a PL/SQL block with OUT parameters
#[derive(Debug)]
pub struct PlsqlResult {
    /// OUT parameter values indexed by position (0-based)
    pub out_values: Vec<Value>,
    /// Number of rows affected (if applicable)
    pub rows_affected: u64,
    /// Cursor ID (if the result contains a REF CURSOR)
    pub cursor_id: Option<u16>,
    /// Implicit result sets returned via DBMS_SQL.RETURN_RESULT
    pub implicit_results: ImplicitResults,
}

impl PlsqlResult {
    /// Create an empty PL/SQL result
    pub fn empty() -> Self {
        Self {
            out_values: Vec::new(),
            rows_affected: 0,
            cursor_id: None,
            implicit_results: ImplicitResults::new(),
        }
    }

    /// Get an OUT value by position (0-based)
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.out_values.get(index)
    }

    /// Get a string OUT value by position
    pub fn get_string(&self, index: usize) -> Option<&str> {
        self.out_values.get(index).and_then(|v| v.as_str())
    }

    /// Get an integer OUT value by position
    pub fn get_integer(&self, index: usize) -> Option<i64> {
        self.out_values.get(index).and_then(|v| v.as_i64())
    }

    /// Get a float OUT value by position
    pub fn get_float(&self, index: usize) -> Option<f64> {
        self.out_values.get(index).and_then(|v| v.as_f64())
    }

    /// Get a cursor ID from OUT value by position (for REF CURSOR)
    pub fn get_cursor_id(&self, index: usize) -> Option<u16> {
        self.out_values.get(index).and_then(|v| v.as_cursor_id())
    }
}

/// Server information obtained during connection
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    /// Oracle version string
    pub version: String,
    /// Server banner
    pub banner: String,
    /// Session ID (SID)
    pub session_id: u32,
    /// Serial number
    pub serial_number: u32,
    /// Instance name
    pub instance_name: Option<String>,
    /// Service name
    pub service_name: Option<String>,
    /// Database name
    pub database_name: Option<String>,
    /// Negotiated protocol version
    pub protocol_version: u16,
    /// Whether server supports OOB (out of band) data
    pub supports_oob: bool,
}

/// Stream type that can be either plain TCP or TLS-encrypted
enum OracleStream {
    /// Plain TCP connection
    Plain(TcpStream),
    /// TLS-encrypted connection
    Tls(TlsOracleStream),
}

impl OracleStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => {
                AsyncReadExt::read_exact(stream, buf).await?;
                Ok(())
            }
            OracleStream::Tls(stream) => {
                AsyncReadExt::read_exact(stream, buf).await?;
                Ok(())
            }
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => stream.write_all(buf).await,
            OracleStream::Tls(stream) => stream.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => stream.flush().await,
            OracleStream::Tls(stream) => stream.flush().await,
        }
    }
}

/// Internal connection state shared across async operations
struct ConnectionInner {
    stream: Option<OracleStream>,
    capabilities: Arc<Capabilities>,
    state: ConnectionState,
    server_info: ServerInfo,
    sdu_size: u16,
    large_sdu: bool,
    /// Sequence number for TTC messages (increments per message)
    sequence_number: u8,
    /// Statement cache for prepared statement reuse (separate mutex to avoid I/O contention)
    statement_cache: Option<Arc<tokio::sync::Mutex<StatementCache>>>,
    /// Whether to auto-commit after DML statements
    auto_commit: bool,
    /// Current transaction isolation level
    transaction_isolation: TransactionIsolation,
}

impl ConnectionInner {
    fn new_with_cache(cache_size: usize) -> Self {
        Self {
            stream: None,
            capabilities: Arc::new(Capabilities::default()),
            state: ConnectionState::Disconnected,
            server_info: ServerInfo::default(),
            sdu_size: 8192,
            large_sdu: false,
            sequence_number: 0,
            statement_cache: if cache_size > 0 {
                Some(Arc::new(tokio::sync::Mutex::new(StatementCache::new(cache_size))))
            } else {
                None
            },
            auto_commit: false,
            transaction_isolation: TransactionIsolation::ReadCommitted,
        }
    }

    /// Get the next sequence number (auto-increments, wraps at 255 to 1)
    fn next_sequence_number(&mut self) -> u8 {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        if self.sequence_number == 0 {
            self.sequence_number = 1;
        }
        self.sequence_number
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if let Some(stream) = &mut self.stream {
            stream.write_all(data).await?;
            stream.flush().await?;
            Ok(())
        } else {
            Err(Error::ConnectionClosed)
        }
    }

    /// Send a payload that may need to be split across multiple packets.
    ///
    /// This is used for large LOB writes and other operations where the payload
    /// exceeds the SDU size. The payload is split into multiple DATA packets,
    /// each with proper headers.
    ///
    /// # Arguments
    /// * `payload` - The raw message payload (without packet header or data flags)
    /// * `data_flags` - The data flags for the first packet (typically 0)
    async fn send_multi_packet(&mut self, payload: &[u8], data_flags: u16) -> Result<()> {
        let stream = self.stream.as_mut().ok_or(Error::ConnectionClosed)?;

        // Calculate max payload per packet: SDU - header (8) - data flags (2)
        let max_payload_per_packet = self.sdu_size as usize - PACKET_HEADER_SIZE - 2;

        // Batch all packets into a single buffer and send atomically.
        // Oracle servers can reject incomplete multi-packet messages if
        // TCP_NODELAY causes individual packets to arrive separately.
        let num_packets = (payload.len() + max_payload_per_packet - 1) / max_payload_per_packet;
        let total_wire = num_packets * (PACKET_HEADER_SIZE + 2) + payload.len();
        let mut batch = Vec::with_capacity(total_wire);

        let mut offset = 0;
        let mut is_first = true;

        while offset < payload.len() {
            let remaining = payload.len() - offset;
            let chunk_size = std::cmp::min(remaining, max_payload_per_packet);

            // Build packet
            let packet_len = PACKET_HEADER_SIZE + 2 + chunk_size; // header + data flags + payload

            // Header
            if self.large_sdu {
                batch.extend_from_slice(&(packet_len as u32).to_be_bytes());
            } else {
                batch.extend_from_slice(&(packet_len as u16).to_be_bytes());
                batch.extend_from_slice(&[0, 0]); // Checksum
            }
            batch.push(PacketType::Data as u8);
            batch.push(0); // Flags
            batch.extend_from_slice(&[0, 0]); // Header checksum

            // Data flags - only include on first packet
            if is_first {
                batch.extend_from_slice(&data_flags.to_be_bytes());
                is_first = false;
            } else {
                batch.extend_from_slice(&0u16.to_be_bytes());
            }

            // Payload chunk
            batch.extend_from_slice(&payload[offset..offset + chunk_size]);

            offset += chunk_size;
        }

        // Single atomic write of all packets
        stream.write_all(&batch).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn receive(&mut self) -> Result<bytes::Bytes> {
        if let Some(stream) = &mut self.stream {
            let mut header_buf = [0u8; PACKET_HEADER_SIZE];
            stream.read_exact(&mut header_buf).await?;

            let packet_len = if self.large_sdu {
                u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]])
                    as usize
            } else {
                u16::from_be_bytes([header_buf[0], header_buf[1]]) as usize
            };

            let payload_len = packet_len.saturating_sub(PACKET_HEADER_SIZE);
            let mut full_packet = Vec::with_capacity(packet_len);
            full_packet.extend_from_slice(&header_buf);
            if payload_len > 0 {
                full_packet.resize(packet_len, 0);
                stream
                    .read_exact(&mut full_packet[PACKET_HEADER_SIZE..])
                    .await?;
            }
            Ok(bytes::Bytes::from(full_packet))
        } else {
            Err(Error::ConnectionClosed)
        }
    }

    /// Receive a complete response that may span multiple packets
    ///
    /// This method accumulates packets until the END_OF_RESPONSE flag is detected
    /// in the data flags. It's used for operations like LOB reads that may return
    /// data spanning multiple TNS packets.
    ///
    /// Returns the combined payload of all packets (excluding headers).
    /// Receive a single response packet or accumulated multi-packet response.
    ///
    /// For Oracle with END_OF_RESPONSE support: accumulates packets until the
    /// flag is set. For older Oracle (11g): returns the first packet only —
    /// callers must use `receive_more_data()` if parsing hits BufferUnderflow.
    async fn receive_response(&mut self) -> Result<bytes::Bytes> {
        use crate::constants::{data_flags, MessageType};

        let first_packet = self.receive().await?;
        if first_packet.len() < PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Packet too small".to_string()));
        }

        if first_packet[4] != PacketType::Data as u8 {
            return Ok(first_packet);
        }

        let payload = &first_packet[PACKET_HEADER_SIZE..];
        if payload.len() < 2 {
            return Err(Error::Protocol("DATA packet payload too small".to_string()));
        }

        let flags = u16::from_be_bytes([payload[0], payload[1]]);
        let has_end = (flags & data_flags::END_OF_RESPONSE) != 0
            || (flags & data_flags::EOF) != 0
            || (payload.len() == 3 && payload[2] == MessageType::EndOfResponse as u8);

        if has_end {
            return Ok(first_packet);
        }

        // No end flag — accumulate remaining packets (for servers WITH end-of-response)
        if self.capabilities.supports_end_of_response {
            // Single-pass: build header + accumulated payload directly in BytesMut,
            // avoiding the intermediate Vec→Vec→Bytes triple-copy.
            use bytes::BytesMut;
            let mut result = BytesMut::with_capacity(PACKET_HEADER_SIZE + payload.len() + 4096);
            // Write header placeholder, will patch at the end
            result.resize(PACKET_HEADER_SIZE, 0);
            // Write first payload (including data flags)
            result.extend_from_slice(payload);

            loop {
                let packet = self.receive().await?;
                if packet.len() < PACKET_HEADER_SIZE || packet[4] != PacketType::Data as u8 {
                    break;
                }
                let p = &packet[PACKET_HEADER_SIZE..];
                if p.len() < 2 {
                    break;
                }
                let pf = u16::from_be_bytes([p[0], p[1]]);
                // Skip data flags on continuation packets (2 bytes)
                result.extend_from_slice(&p[2..]);

                if (pf & data_flags::END_OF_RESPONSE) != 0 || (pf & data_flags::EOF) != 0 {
                    break;
                }
            }

            // Patch header
            let total_len = result.len() as u32;
            if self.large_sdu {
                result[..4].copy_from_slice(&total_len.to_be_bytes());
            } else {
                result[..2].copy_from_slice(&(total_len as u16).to_be_bytes());
            }
            result[4] = PacketType::Data as u8;
            result[5] = 0;
            result[6..8].copy_from_slice(&[0, 0]);

            return Ok(result.freeze());
        }

        // Oracle 11g — return single packet, caller will request more if needed
        Ok(first_packet)
    }

    /// Read one more DATA packet and append its payload to the existing response.
    /// Returns the new combined response bytes, or None if no more data.
    async fn receive_more_data(&mut self, existing: &bytes::Bytes) -> Result<bytes::Bytes> {
        let packet = self.receive().await?;
        if packet.len() < PACKET_HEADER_SIZE || packet[4] != PacketType::Data as u8 {
            return Err(Error::Protocol(
                "Expected DATA packet for continuation".to_string(),
            ));
        }
        let p = &packet[PACKET_HEADER_SIZE..];
        if p.len() < 2 {
            return Err(Error::Protocol("DATA packet too small".to_string()));
        }

        // Single-pass: existing payload + new payload (skip new data flags)
        use bytes::BytesMut;
        let existing_payload = &existing[PACKET_HEADER_SIZE..];
        let mut result = BytesMut::with_capacity(
            PACKET_HEADER_SIZE + existing_payload.len() + p.len(),
        );
        result.resize(PACKET_HEADER_SIZE, 0);
        result.extend_from_slice(existing_payload);
        result.extend_from_slice(&p[2..]);

        let total_len = result.len() as u32;
        if self.large_sdu {
            result[..4].copy_from_slice(&total_len.to_be_bytes());
        } else {
            result[..2].copy_from_slice(&(total_len as u16).to_be_bytes());
        }
        result[4] = PacketType::Data as u8;
        result[5] = 0;
        result[6..8].copy_from_slice(&[0, 0]);

        Ok(result.freeze())
    }

    /// Send GetDBVersion message (go-ora compat for Oracle 10g).
    ///
    /// go-ora sends this right after auth to finalise protocol initialisation.
    /// The message payload is: 03 3B 00 01 [compressed 0x100] 01 01
    /// The server responds with msg type 8 containing the banner and version.
    async fn query_db_version_10g(&mut self) -> Result<()> {
        let mut body = WriteBuffer::with_capacity(64);

        // TTC function header
        body.write_u8(MessageType::Function as u8)?;
        body.write_u8(FunctionCode::DbVersion as u8)?;
        body.write_u8(0)?; // seq = 0

        // PutBytes(1) — user_ptr
        body.write_u8(1)?;

        // PutUint(0x100, 2, true, true) — version parameter
        body.write_ub4(0x100)?;

        // PutBytes(1, 1)
        body.write_u8(1)?;
        body.write_u8(1)?;

        let payload = body.freeze();

        // Build packet: header (8) + data_flags (2) + payload
        let packet_len = PACKET_HEADER_SIZE + 2 + payload.len();

        let mut pkt = WriteBuffer::with_capacity(packet_len + 16);
        if self.large_sdu {
            pkt.write_u32_be(packet_len as u32)?;
        } else {
            pkt.write_u16_be(packet_len as u16)?;
            pkt.write_u16_be(0)?; // checksum padding
        }
        pkt.write_u8(PacketType::Data as u8)?;
        pkt.write_u8(0)?; // flags
        pkt.write_u16_be(0)?; // header checksum
        // go-ora 10g uses data flags = 0 (not END_OF_REQUEST) for GetDBVersion.
        // END_OF_REQUEST may cause the server to finalize state prematurely.
        pkt.write_u16_be(0)?;
        pkt.write_bytes(&payload)?;

        let packet = pkt.freeze();
        self.send(&packet).await?;

        // Read and drain the response (message type 8 with banner + version)
        let response = self.receive().await?;

        // Parse response to extract banner
        if response.len() > PACKET_HEADER_SIZE + 2 {
            let raw_payload = &response[PACKET_HEADER_SIZE..];
            // Skip data_flags (2 bytes)
            let ttc = &raw_payload[2..];
            if !ttc.is_empty() && ttc[0] == 8 {
                // Message type 8 — contains banner string and version
                if ttc.len() > 2 {
                    // Read compressed u16 string length
                    let slen = if ttc[1] == 0 {
                        0
                    } else if ttc[1] == 1 && ttc.len() > 2 {
                        ttc[2] as usize
                    } else if ttc[1] == 2 && ttc.len() > 3 {
                        u16::from_be_bytes([ttc[2], ttc[3]]) as usize
                    } else {
                        0
                    };
                    if slen > 0 {
                        let start = if ttc[1] == 0 { 2 } else { ttc[1] as usize + 2 };
                        let end = (start + slen).min(ttc.len());
                        let _banner = String::from_utf8_lossy(&ttc[start..end]);
                    }
                }
            }
        }

        Ok(())
    }

    /// Send CloseCursors piggyback message (go-ora compat for Oracle 10g).
    ///
    /// After a query completes on 10g, the server keeps the cursor open even
    /// after all rows are fetched. We must explicitly close it before the next
    /// execute, otherwise we get ORA-01002 "fetch out of sequence".
    ///
    /// Format (from go-ora v2): PutBytes(0x11, 0x69, 0, 1, 1, 1) + PutUint(cursor_id, 4)
    async fn close_cursor_10g(&mut self, cursor_id: u16) -> Result<()> {
        let mut body = WriteBuffer::with_capacity(64);

        // Piggyback header + CloseCursors function code
        body.write_u8(MessageType::Piggyback as u8)?; // 0x11
        body.write_u8(FunctionCode::CloseCursors as u8)?; // 0x69
        body.write_u8(0)?; // reserved
        body.write_u8(1)?; // param 1
        body.write_u8(1)?; // param 2
        body.write_u8(1)?; // param 3

        // Cursor ID: UB2 for 10g (ttc_fv <= 4), UB4 for 11g+
        if self.capabilities.ttc_field_version <= ccap_value::FIELD_VERSION_10_2 {
            body.write_ub2(cursor_id)?;
        } else {
            body.write_ub4(cursor_id as u32)?;
        }

        let payload = body.freeze();

        // Build packet
        let packet_len = PACKET_HEADER_SIZE + 2 + payload.len();
        let mut pkt = WriteBuffer::with_capacity(packet_len + 16);
        if self.large_sdu {
            pkt.write_u32_be(packet_len as u32)?;
        } else {
            pkt.write_u16_be(packet_len as u16)?;
            pkt.write_u16_be(0)?;
        }
        pkt.write_u8(PacketType::Data as u8)?;
        pkt.write_u8(0)?;
        pkt.write_u16_be(0)?;
        pkt.write_u16_be(0)?; // data flags = 0

        pkt.write_bytes(&payload)?;

        let packet = pkt.freeze();
        self.send(&packet).await?;

        // Read and drain the response (expect Status message type 9)
        // 10g may not respond to CloseCursors — use timeout to avoid hanging
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.receive(),
        )
        .await;
        if let Ok(Ok(response)) = response {
            if response.len() > PACKET_HEADER_SIZE + 2 {
                let raw = &response[PACKET_HEADER_SIZE..];
                if raw.len() >= 3 {
                    let msg_type = raw[2];
                    if msg_type == MessageType::Error as u8 {
                        if raw.len() > 12 {
                            let error_code = u16::from_be_bytes([raw[10], raw[11]]);
                            if error_code != 0 {
                                // Non-zero error in piggyback response — log but don't fail
                            }
                        }
                    }
                }
            }
        }
        // Timeout or receive error: 10g doesn't respond to CloseCursors, so this is expected.

        // Drain any remaining response data
        self.drain_stale_packets().await;

        Ok(())
    }

    /// Send a marker packet with the specified marker type
    async fn send_marker(&mut self, marker_type: u8) -> Result<()> {
        let mut buf = WriteBuffer::with_capacity(16);

        // Build marker packet header
        // Marker packet structure: [length][0x00][0x00][0x00][0x0c][flags][0x00][0x00] + payload
        // Payload: [0x01][0x00][marker_type]
        let payload_len = 3; // 0x01, 0x00, marker_type
        let total_len = (PACKET_HEADER_SIZE + payload_len) as u16;

        // Header
        buf.write_u16_be(total_len)?;
        buf.write_u16_be(0)?; // zeros in large_sdu position
        buf.write_u8(PacketType::Marker as u8)?;
        buf.write_u8(0)?; // flags
        buf.write_u16_be(0)?; // reserved

        // Payload
        buf.write_u8(0x01)?; // constant
        buf.write_u8(0x00)?; // constant
        buf.write_u8(marker_type)?;

        self.send(buf.as_slice()).await
    }

    /// Send Logoff function message to the server.
    ///
    /// This is a best-effort cleanup — errors are ignored since the connection
    /// is being torn down and the server will eventually reclaim the session anyway.
    async fn send_logoff(&mut self) -> Result<()> {
        let seq_num = self.next_sequence_number();

        let mut buf = WriteBuffer::new();
        buf.write_u8(MessageType::Function as u8)?;
        buf.write_u8(FunctionCode::Logoff as u8)?;
        buf.write_u8(seq_num)?;

        if self.capabilities.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        let data_payload = buf.freeze();
        let mut packet_buf = WriteBuffer::new();
        let packet_len = PACKET_HEADER_SIZE + 2 + data_payload.len();
        packet_buf.write_u16_be(packet_len as u16)?;
        packet_buf.write_u16_be(0)?; // Checksum
        packet_buf.write_u8(PacketType::Data as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum
        packet_buf.write_u16_be(0)?; // Data flags at offset 8
        packet_buf.write_bytes(&data_payload)?;

        // Best-effort send — don't wait for response
        let packet_bytes = packet_buf.freeze();
        let _ = self.send(&packet_bytes).await;
        Ok(())
    }

    /// Handle the reset protocol after receiving a MARKER packet
    /// This sends a reset marker, waits for the reset response, then returns the error packet
    /// Returns Err if the connection is closed after reset (some Oracle versions do this)
    async fn handle_marker_reset(&mut self) -> Result<bytes::Bytes> {
        const MARKER_TYPE_RESET: u8 = 2;
        self.send_marker(MARKER_TYPE_RESET).await?;

        let mut buffered_data: Option<bytes::Bytes> = None;

        loop {
            let packet = self.receive().await?;
            if packet.len() < PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Invalid packet received".to_string()));
            }

            let packet_type = packet[4];

            if packet_type == PacketType::Marker as u8 {
                if packet.len() >= PACKET_HEADER_SIZE + 3 {
                    let marker_type = packet[PACKET_HEADER_SIZE + 2];
                    if marker_type == MARKER_TYPE_RESET {
                        break;
                    }
                }
            } else {
                buffered_data = Some(packet);
            }
        }

        if let Some(data) = buffered_data {
            self.drain_stale_packets().await;
            return Ok(data);
        }
        loop {
            match self.receive().await {
                Ok(packet) => {
                    let ptype = packet[4];
                    if ptype != PacketType::Marker as u8 {
                        self.drain_stale_packets().await;
                        return Ok(packet);
                    }
                }
                Err(_) => {
                    self.mark_closed();
                    return Err(Error::ConnectionClosedByServer(
                        "Query failed - Oracle closed the connection without providing error details. \
                         This typically indicates insufficient privileges or the object doesn't exist.".to_string()
                    ));
                }
            }
        }
    }

    async fn drain_stale_packets(&mut self) {
        use tokio::time::{timeout, Duration};
        loop {
            match timeout(Duration::from_millis(1), self.receive()).await {
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }
    }

    fn mark_closed(&mut self) {
        self.stream = None;
        self.state = ConnectionState::Disconnected;
    }
}

/// An Oracle database connection.
///
/// This is the main type for interacting with Oracle databases. It provides
/// methods for executing queries, DML statements, PL/SQL blocks, and managing
/// transactions.
///
/// Connections are created using [`Connection::connect`] or
/// [`Connection::connect_with_config`]. For connection pooling, use the
/// `deadpool-oracle` crate.
///
/// # Example
///
/// ```rust,no_run
/// use rust_oracle::{Config, Connection, Value};
///
/// # async fn example() -> rust_oracle::Result<()> {
/// // Create a connection
/// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
/// let conn = Connection::connect_with_config(config).await?;
///
/// // Execute a query
/// let result = conn.query("SELECT * FROM employees WHERE dept_id = :1", &[10.into()]).await?;
/// for row in &result.rows {
///     let name = row.get_by_name("name").and_then(|v| v.as_str()).unwrap_or("");
///     println!("Employee: {}", name);
/// }
///
/// // Execute DML with transaction
/// conn.execute("INSERT INTO logs (msg) VALUES (:1)", &["Hello".into()]).await?;
/// conn.commit().await?;
///
/// // Close the connection
/// conn.close().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// `Connection` is `Send` and `Sync`, but operations are serialized internally
/// via a mutex. For parallel query execution, use multiple connections (e.g.,
/// via a connection pool).
pub struct Connection {
    inner: Arc<Mutex<ConnectionInner>>,
    config: Config,
    closed: Arc<AtomicBool>,
    id: u32,
}

// Connection ID counter
static CONNECTION_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

impl Clone for Connection {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            config: self.config.clone(),
            closed: Arc::clone(&self.closed),
            id: self.id,
        }
    }
}

impl Connection {
    /// Create a new connection to an Oracle database
    ///
    /// # Arguments
    ///
    /// * `connect_string` - Connection string in EZConnect format (e.g., "host:port/service")
    /// * `username` - Database username
    /// * `password` - Database password
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let conn = Connection::connect("localhost:1521/ORCLPDB1", "scott", "tiger").await?;
    /// ```
    pub async fn connect(connect_string: &str, username: &str, password: &str) -> Result<Self> {
        let mut config: Config = connect_string.parse()?;
        config.username = username.to_string();
        config.set_password(password);
        Self::connect_with_config(config).await
    }

    /// Create a new connection using a [`Config`].
    ///
    /// This is the preferred way to create connections as it gives full control
    /// over connection parameters including TLS, timeouts, and statement caching.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rust_oracle::{Config, Connection};
    ///
    /// # async fn example() -> rust_oracle::Result<()> {
    /// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password")
    ///     .with_statement_cache_size(50);
    ///
    /// let conn = Connection::connect_with_config(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(skip(config), fields(conn.id = tracing::field::Empty))]
    #[tracing::instrument(skip(config), fields(conn.id = tracing::field::Empty))]
    pub async fn connect_with_config(config: Config) -> Result<Self> {
        let id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        tracing::Span::current().record("conn.id", id);
        tracing::debug!(host = %config.host, port = config.port, service = ?config.service, "connecting to Oracle");

        let retry_count = config.retry_count;
        let mut delay = config.retry_delay;
        let mut last_error: Option<Error> = None;

        for attempt in 0..=retry_count {
            if attempt > 0 {
                tracing::warn!(
                    attempt = attempt,
                    delay_ms = delay.as_millis() as u64,
                    error = ?last_error,
                    "retrying Oracle connection"
                );
                tokio::time::sleep(delay).await;
                // Exponential backoff with cap
                delay = std::cmp::min(
                    std::time::Duration::from_secs_f64(
                        delay.as_secs_f64() * config.retry_backoff_multiplier,
                    ),
                    config.retry_max_delay,
                );
            }

            match Self::try_connect(&config, id).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    tracing::debug!(attempt = attempt, error = %e, "connection attempt failed");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::ConnectionTimeout(config.connect_timeout)))
    }

    /// Attempt a single TCP connection and protocol handshake.
    async fn try_connect(config: &Config, id: u32) -> Result<Self> {
        // Create TCP connection
        let addr = config.socket_addr();
        let tcp_stream = tokio::time::timeout(config.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::ConnectionTimeout(config.connect_timeout))??;

        // Set TCP options
        tcp_stream.set_nodelay(true)?;
        if config.tcp_keepalive {
            let sock = socket2::SockRef::from(&tcp_stream);
            let keepalive = socket2::TcpKeepalive::new().with_time(config.tcp_keepalive_idle);
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            let keepalive = keepalive.with_interval(std::time::Duration::from_secs(15));
            let _ = sock.set_tcp_keepalive(&keepalive);
        }

        // Wrap with TLS if configured
        let stream = if config.is_tls_enabled() {
            let tls_config = config
                .tls_config
                .as_ref()
                .cloned()
                .unwrap_or_else(TlsConfig::new);

            let tls_stream = connect_tls(tcp_stream, &config.host, &tls_config).await?;
            OracleStream::Tls(tls_stream)
        } else {
            OracleStream::Plain(tcp_stream)
        };

        let mut inner = ConnectionInner::new_with_cache(config.stmtcachesize);
        inner.stream = Some(stream);
        inner.state = ConnectionState::Connected;
        tracing::debug!("TCP connection established");

        let conn = Connection {
            inner: Arc::new(Mutex::new(inner)),
            config: config.clone(),
            closed: Arc::new(AtomicBool::new(false)),
            id,
        };

        // Perform connection handshake
        conn.perform_handshake().await?;

        Ok(conn)
    }

    /// Get the connection ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Check if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Mark the connection as closed
    ///
    /// This should be called when the underlying connection is detected as broken.
    /// Once marked closed, `is_closed()` returns true and operations will fail fast.
    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    /// Helper to mark connection as closed if the result is a connection error
    fn handle_result<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(ref e) = result {
            if e.is_connection_error() {
                self.mark_closed();
            }
        }
        result
    }

    /// Get server information
    pub async fn server_info(&self) -> ServerInfo {
        let inner = self.inner.lock().await;
        inner.server_info.clone()
    }

    /// Get the current connection state
    pub async fn state(&self) -> ConnectionState {
        let inner = self.inner.lock().await;
        inner.state
    }

    /// Perform the connection handshake
    async fn perform_handshake(&self) -> Result<()> {
        // Step 1: Send CONNECT packet and parse ACCEPT response
        self.send_connect_packet().await?;

        // Step 2: OOB check (required for protocol version >= 318 AND server supports OOB)
        // Both conditions must be met - server must have indicated OOB support in ACCEPT
        let needs_oob_check = {
            let inner = self.inner.lock().await;
            inner.server_info.protocol_version >= crate::constants::version::MIN_OOB_CHECK
                && inner.server_info.supports_oob
        };
        if needs_oob_check {
            self.send_oob_check().await?;
        }

        // Step 3: Protocol negotiation
        self.negotiate_protocol().await?;

        // Step 4: Data types negotiation
        // Oracle 10g (ttc_fv <= 5) uses a go-ora-compatible format
        self.negotiate_data_types().await?;

        // Step 5: Authentication
        self.authenticate().await?;

        Ok(())
    }

    /// Send OOB (Out of Band) check
    /// Required for protocol version >= 318
    async fn send_oob_check(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Step 1: Send raw byte "!" (0x21) for OOB check
        inner.send(&[0x21]).await?;

        // Step 2: Send MARKER packet with Reset
        let marker_payload = [1u8, 0u8, crate::constants::MarkerType::Reset as u8];
        let mut packet_buf = WriteBuffer::new();

        if large_sdu {
            packet_buf.write_u32_be((PACKET_HEADER_SIZE + marker_payload.len()) as u32)?;
        } else {
            packet_buf.write_u16_be((PACKET_HEADER_SIZE + marker_payload.len()) as u16)?;
            packet_buf.write_u16_be(0)?; // Checksum
        }
        packet_buf.write_u8(PacketType::Marker as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum
        packet_buf.write_bytes(&marker_payload)?;

        inner.send(&packet_buf.freeze()).await?;

        // Step 3: Wait for OOB reset response
        // The server sends back a MARKER packet or reset acknowledgment
        let response = inner.receive().await?;

        // Validate response - should be a MARKER packet type (12)
        if response.len() > 4 && response[4] == PacketType::Marker as u8 {
            Ok(())
        } else {
            // Server might just acknowledge without a specific packet
            // This is acceptable in some Oracle versions
            Ok(())
        }
    }

    /// Send the initial CONNECT packet
    async fn send_connect_packet(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;

        // Build connect packet using ConnectMessage for proper packet format
        let connect_msg = ConnectMessage::from_config(&self.config);
        let (connect_packet, continuation) = connect_msg.build_with_continuation()?;

        // Send the CONNECT packet
        inner.send(&connect_packet).await?;

        // If we have a continuation DATA packet (for large connect strings), send it
        if let Some(ref data_packet) = continuation {
            inner.send(data_packet).await?;
        }

        const MAX_RESENDS: u8 = 3;
        let mut resend_count: u8 = 0;

        loop {
            // Wait for response
            let response = inner.receive().await?;

            // Parse response packet type
            if response.len() < PACKET_HEADER_SIZE {
                return Err(Error::PacketTooShort {
                    expected: PACKET_HEADER_SIZE,
                    actual: response.len(),
                });
            }

            let packet_type = response[4];

            match packet_type {
                2 => {
                    // ACCEPT - parse the accept message to get protocol version and capabilities
                    let packet = Packet::from_bytes(response)?;
                    let accept = AcceptMessage::parse(&packet)?;

                    // Set large_sdu mode if protocol version >= 315
                    inner.large_sdu = accept.uses_large_sdu();

                    // Update server info
                    inner.server_info.protocol_version = accept.protocol_version;
                    inner.server_info.supports_oob = accept.supports_oob;
                    inner.sdu_size = accept.sdu.min(65535) as u16;

                    inner.state = ConnectionState::Connected;
                    return Ok(());
                }
                4 => {
                    // REFUSE
                    let mut buf = ReadBuffer::new(response.slice(PACKET_HEADER_SIZE..));
                    let _reason = buf.read_u8()?;
                    let _user_reason = buf.read_u8()?;

                    return Err(Error::ConnectionRefused {
                        error_code: None,
                        message: Some("Connection refused by server".to_string()),
                    });
                }
                5 => {
                    // REDIRECT - follow the redirect to the new address
                    let packet = Packet::from_bytes(response)?;
                    let redirect = RedirectMessage::parse(&packet)?;
                    let addr = redirect.socket_addr().ok_or_else(|| {
                        Error::ConnectionRedirect(format!(
                            "could not parse redirect address: {}",
                            redirect.address
                        ))
                    })?;

                    tracing::debug!(address = %addr, "following Oracle redirect");

                    let tcp_stream: TcpStream = TcpStream::connect(&addr).await.map_err(|e| {
                        Error::ConnectionRedirect(format!(
                            "failed to connect to redirect target {}: {}",
                            addr, e
                        ))
                    })?;
                    tcp_stream.set_nodelay(true).map_err(Error::Io)?;

                    let sock = socket2::SockRef::from(&tcp_stream);
                    let keepalive =
                        socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(60));
                    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                    let keepalive = keepalive.with_interval(std::time::Duration::from_secs(15));
                    let _ = sock.set_tcp_keepalive(&keepalive);

                    inner.stream = Some(OracleStream::Plain(tcp_stream));

                    inner.send(&connect_packet).await?;
                    if let Some(ref data_packet) = continuation {
                        inner.send(data_packet).await?;
                    }
                }
                11 => {
                    // RESEND - server requests retransmission of the connect packet
                    resend_count += 1;
                    if resend_count > MAX_RESENDS {
                        return Err(Error::ProtocolError(
                            "Server requested too many resends during connect".to_string(),
                        ));
                    }
                    inner.send(&connect_packet).await?;
                    if let Some(ref data_packet) = continuation {
                        inner.send(data_packet).await?;
                    }
                }
                _ => {
                    return Err(Error::ProtocolError(format!(
                        "Unexpected packet type during connect: {}",
                        packet_type,
                    )));
                }
            }
        }
    }

    /// Negotiate protocol version and capabilities
    async fn negotiate_protocol(&self) -> Result<()> {
        use crate::messages::ProtocolMessage;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Build protocol request (includes header)
        let protocol_msg = ProtocolMessage::new();
        let packet = protocol_msg.build_request(large_sdu)?;
        inner.send(&packet).await?;

        // Receive response
        let response = inner.receive().await?;

        // Validate packet type (at offset 4 for both SDU modes)
        if response.len() <= 4 || response[4] != PacketType::Data as u8 {
            return Err(Error::ProtocolError(
                "Protocol negotiation failed".to_string(),
            ));
        }

        // Parse the Protocol response to extract server capabilities
        // The payload starts after the 8-byte header
        let payload = response.slice(PACKET_HEADER_SIZE..);
        let mut protocol_msg = ProtocolMessage::new();
        protocol_msg.parse_response(&payload, Arc::make_mut(&mut inner.capabilities))?;

        // Update server info with banner
        if let Some(banner) = &protocol_msg.server_banner {
            inner.server_info.banner = banner.clone();
        }

        inner.state = ConnectionState::ProtocolNegotiated;
        Ok(())
    }

    /// Negotiate data types
    async fn negotiate_data_types(&self) -> Result<()> {
        use crate::messages::DataTypesMessage;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let is_10g = inner.capabilities.ttc_field_version <= 5;

        let data_types_msg = DataTypesMessage::new();
        let packet = if is_10g {
            data_types_msg.build_request_10g(&inner.capabilities, large_sdu)?
        } else {
            data_types_msg.build_request(&inner.capabilities, large_sdu)?
        };

        // Extract payload (skip packet header and data flags) and use
        // send_multi_packet to split across SDU-sized packets.  Oracle 10g
        // has SDU=2048 but the data_types message is ~2342 bytes and must be
        // split into multiple DATA packets like go-ora's Write() does.
        let data_flags = u16::from_be_bytes([packet[PACKET_HEADER_SIZE], packet[PACKET_HEADER_SIZE + 1]]);
        let payload = &packet[PACKET_HEADER_SIZE + 2..];
        inner.send_multi_packet(payload, data_flags).await?;

        // Receive response
        let response = inner.receive().await?;

        // Handle MARKER response — older Oracle versions reject data types
        // with post-era entries.
        if response.len() > 4 && response[4] == PacketType::Marker as u8 {
            if is_10g {
                // Oracle 10g: don't send RESET, just drain any pending markers
                for _ in 0..10 {
                    match inner.receive().await {
                        Ok(pkt) => {
                            let pt = if pkt.len() >= 5 { pkt[4] } else { 0 };
                            if pt != PacketType::Marker as u8 {
                                break;
                            }
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            } else {
                // 11g+: standard RESET handling
                inner.send_marker(2).await?;
                for _ in 0..10 {
                    match inner.receive().await {
                        Ok(pkt) => {
                            let pt = if pkt.len() >= 5 { pkt[4] } else { 0 };
                            if pt == PacketType::Marker as u8 {
                                let mt = pkt.get(PACKET_HEADER_SIZE + 2).copied().unwrap_or(0);
                                if mt == 2 { break; }
                            } else if pt == PacketType::Data as u8 { break; }
                        }
                        Err(_) => { break; }
                    }
                }
            }

            // Drain any remaining stale packets before proceeding to auth
            inner.drain_stale_packets().await;
            inner.state = ConnectionState::DataTypesNegotiated;
            return Ok(());
        }

        // Basic validation - packet type is at offset 4 regardless of large_sdu
        if response.len() > 4 && response[4] == PacketType::Data as u8 {
            // Oracle 10g with small SDU may split server response across multiple packets.
            // The first packet payload ends at SDU boundary, with a continuation packet
            // following immediately.  Try to read it with a short timeout.
            let mut total_payload = response[PACKET_HEADER_SIZE..].to_vec();
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    inner.receive(),
                ).await {
                    Ok(Ok(extra)) => {
                        if extra.len() > 4 && extra[4] == PacketType::Data as u8 {
                            total_payload.extend_from_slice(&extra[PACKET_HEADER_SIZE..]);
                        } else {
                            break;
                        }
                    }
                    Ok(Err(_)) => {
                        break;
                    }
                    Err(_timeout) => {
                        break;
                    }
                }
            }
            inner.state = ConnectionState::DataTypesNegotiated;
            Ok(())
        } else {
            let pkt_type = if response.len() > 4 { response[4] } else { 0 };
            Err(Error::ProtocolError(format!(
                "Data types negotiation failed: packet_type={}, len={}",
                pkt_type, response.len()
            )))
        }
    }

    /// Perform authentication
    async fn authenticate(&self) -> Result<()> {
        let service_name = match &self.config.service {
            ServiceMethod::ServiceName(name) => name.clone(),
            ServiceMethod::Sid(sid) => sid.clone(),
        };

        let mut auth = AuthMessage::new(
            &self.config.username,
            self.config.password().as_bytes(),
            &service_name,
        );

        if self.config.sysdba {
            auth = auth.with_sysdba();
        }

        // Phase one: send username and session info.
        let mut phase1_done = false;
        for attempt in 0..2 {
            let mut inner = self.inner.lock().await;
            let large_sdu = inner.large_sdu;

            let request = auth.build_request(&inner.capabilities, large_sdu)?;
            inner.send(&request).await?;

            let response = match inner.receive().await {
                Ok(r) => r,
                Err(e) => {
                    return Err(e);
                }
            };
            if response.len() <= PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Empty auth response".to_string()));
            }

            let packet_type = response[4];
            if packet_type == PacketType::Marker as u8 {
                let marker_type = response.get(PACKET_HEADER_SIZE + 2).copied().unwrap_or(0);
                if attempt == 0 {
                    // Reset protocol: send RESET, wait for server ACK, drain
                    inner.send_marker(2).await?;
                    // Wait for the server's RESET acknowledgment
                    for _ in 0..10 {
                        match inner.receive().await {
                            Ok(pkt) => {
                                let pt = pkt.get(4).copied().unwrap_or(0);
                                if pt == PacketType::Marker as u8 {
                                    let mt = pkt.get(PACKET_HEADER_SIZE + 2).copied().unwrap_or(0);
                                    if mt == 2 { break; }
                                } else if pt == PacketType::Data as u8 {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    inner.drain_stale_packets().await;
                    drop(inner);
                    continue;
                }
                return Err(Error::AuthenticationFailed(format!(
                    "Server rejected authentication (MARKER type={}). \
                     Older Oracle versions may require different auth protocol.",
                    marker_type
                )));
            }

            // Check for error message type
            if response.len() > PACKET_HEADER_SIZE + 2 {
                let msg_type = response[PACKET_HEADER_SIZE + 2];
                if msg_type == MessageType::Error as u8 {
                    return Err(Error::AuthenticationFailed(
                        "Server rejected authentication phase one".to_string(),
                    ));
                }
            }

            auth.parse_response(&response[PACKET_HEADER_SIZE..])?;
            phase1_done = true;
            break;
        }

        if !phase1_done {
            return Err(Error::AuthenticationFailed(
                "Authentication phase one failed after retry".to_string(),
            ));
        }

        // Phase two: send encrypted password
        if auth.phase() == AuthPhase::Two {
            let mut inner = self.inner.lock().await;
            let large_sdu = inner.large_sdu;
            let request = auth.build_request(&inner.capabilities, large_sdu)?;
            inner.send(&request).await?;

            let response = inner.receive().await?;
            if response.len() <= PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Empty auth phase two response".to_string()));
            }

            // Check for error message type or marker
            let packet_type = response[4];
            if packet_type == PacketType::Marker as u8 {
                // Stale marker — reset and retry Phase Two once
                inner.send_marker(2).await?;
                inner.drain_stale_packets().await;

                // Resend Phase Two request
                let request = auth.build_request(&inner.capabilities, large_sdu)?;
                inner.send(&request).await?;

                let response = inner.receive().await?;
                if response.len() <= PACKET_HEADER_SIZE {
                    return Err(Error::Protocol("Empty auth phase two response".to_string()));
                }
                let packet_type = response[4];
                if packet_type == PacketType::Marker as u8 {
                    return Err(Error::AuthenticationFailed(
                        "Server sent MARKER - authentication rejected".to_string(),
                    ));
                }
                if response.len() > PACKET_HEADER_SIZE + 2 {
                    let msg_type = response[PACKET_HEADER_SIZE + 2];
                    if msg_type == MessageType::Error as u8 {
                        return Err(Error::InvalidCredentials);
                    }
                }
                auth.parse_response(&response[PACKET_HEADER_SIZE..])?;
            } else if response.len() > PACKET_HEADER_SIZE + 2 {
                let msg_type = response[PACKET_HEADER_SIZE + 2];
                if msg_type == MessageType::Error as u8 {
                    return Err(Error::InvalidCredentials);
                }
                auth.parse_response(&response[PACKET_HEADER_SIZE..])?;
            } else {
                auth.parse_response(&response[PACKET_HEADER_SIZE..])?;
            }
        }

        // Verify authentication completed
        if !auth.is_complete() {
            return Err(Error::AuthenticationFailed(
                "Authentication did not complete".to_string(),
            ));
        }

        // Store combo key for later use (encrypted data)
        let mut inner = self.inner.lock().await;
        if let Some(combo_key) = auth.combo_key() {
            Arc::make_mut(&mut inner.capabilities).combo_key = Some(combo_key.to_vec());
        }
        // Auth used sequence numbers 1 and 2, set to 2 so next is 3
        inner.sequence_number = 2;

        // Oracle 10g: send GetDBVersion (go-ora compat) to complete initialization.
        // Without this, the server rejects execute messages with ORA-03120.
        let ttc_fv = inner.capabilities.ttc_field_version;
        if ttc_fv <= ccap_value::FIELD_VERSION_10_2 {
            inner.query_db_version_10g().await?;
        }

        inner.state = ConnectionState::Ready;
        tracing::info!(
            conn.id = self.id,
            ttc_version = inner.capabilities.ttc_field_version,
            "connection ready"
        );

        Ok(())
    }

    /// Execute a SQL statement and return the result
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL statement to execute
    /// * `params` - Bind parameters (use `Value::Integer`, `Value::String`, etc.)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rust_oracle::Value;
    ///
    /// // Query with bind parameters
    /// let result = conn.execute(
    ///     "SELECT * FROM employees WHERE department_id = :1",
    ///     &[Value::Integer(10)]
    /// ).await?;
    ///
    /// // DML with bind parameters
    /// let result = conn.execute(
    ///     "UPDATE employees SET salary = :1 WHERE employee_id = :2",
    ///     &[Value::Integer(50000), Value::Integer(100)]
    /// ).await?;
    /// println!("Rows affected: {}", result.rows_affected);
    /// ```
    #[tracing::instrument(skip(self, params), fields(sql = %sql, params.len = params.len()))]
    pub async fn execute(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        self.ensure_ready().await?;

        // Promote oversized strings to CLOB binds
        let (promoted_params, temp_lobs) = self.promote_params_if_needed(params, MAX_VARCHAR_SQL).await?;
        let has_promotion = !temp_lobs.is_empty();
        let params_to_use: &[Value] = if has_promotion { &promoted_params } else { params };

        // When promotion occurred, skip the statement cache because bind types changed.
        let statement = if has_promotion {
            Statement::new(sql)
        } else {
            let cache_arc = {
                let inner = self.inner.lock().await;
                inner.statement_cache.clone()
            };
            if let Some(cache) = cache_arc {
                let mut cache = cache.lock().await;
                if let Some(cached_stmt) = cache.get(sql) {
                    tracing::trace!(
                        sql = sql,
                        cursor_id = cached_stmt.cursor_id(),
                        "Using cached statement (execute)"
                    );
                    cached_stmt
                } else {
                    Statement::new(sql)
                }
            } else {
                Statement::new(sql)
            }
        };
        let from_cache = statement.cursor_id() > 0;

        let result = match statement.statement_type() {
            StatementType::Query => {
                self.execute_query_with_params(&statement, params_to_use).await
            }
            _ => self.execute_dml_with_params(&statement, params_to_use).await,
        };

        // Clean up temp LOBs regardless of success/failure
        self.cleanup_temp_lobs(&temp_lobs).await;

        // Return statement to cache or cache it for the first time (skip if promoted)
        if !has_promotion {
            match &result {
                Ok(query_result) => {
                    let cache_arc = {
                        let inner = self.inner.lock().await;
                        inner.statement_cache.clone()
                    };
                    if let Some(cache) = cache_arc {
                        let mut cache = cache.lock().await;
                        let should_close_cursor =
                            if statement.statement_type() == StatementType::Query {
                                !query_result.has_more_rows
                            } else {
                                true
                            };

                        if from_cache {
                            cache.return_statement(sql);
                            if should_close_cursor {
                                cache.mark_cursor_closed(sql);
                            }
                        } else if query_result.cursor_id > 0 && !statement.is_ddl() {
                            let mut stmt_to_cache = statement.clone();
                            stmt_to_cache.set_cursor_id(query_result.cursor_id);
                            stmt_to_cache.set_executed(true);
                            cache.put(sql.to_string(), stmt_to_cache);
                            if should_close_cursor {
                                cache.mark_cursor_closed(sql);
                            }
                        }
                    }
                }
                Err(_) => {
                    if from_cache {
                        let cache_arc = {
                            let inner = self.inner.lock().await;
                            inner.statement_cache.clone()
                        };
                        if let Some(cache) = cache_arc {
                            let mut cache = cache.lock().await;
                            cache.return_statement(sql);
                            cache.mark_cursor_closed(sql);
                        }
                    }
                }
            }
        }

        result
    }

    /// Execute a query and return rows
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rust_oracle::Value;
    ///
    /// let result = conn.query(
    ///     "SELECT * FROM employees WHERE salary > :1",
    ///     &[Value::Integer(50000)]
    /// ).await?;
    /// ```
    #[tracing::instrument(skip(self, params), fields(sql = %sql, params.len = params.len()))]
    pub async fn query(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        // Promote oversized strings to CLOB binds
        let (promoted_params, temp_lobs) = self.promote_params_if_needed(params, MAX_VARCHAR_SQL).await?;
        let params_to_use: &[Value] = if temp_lobs.is_empty() { params } else { &promoted_params };

        // Use initial prefetch of 1000 rows. For narrow tables this reduces
        // round-trips significantly. For wide tables, Oracle may return fewer
        // rows in the initial batch (~441 at 8KB SDU), but the auto-fetch
        // loop drains the remainder via FunCode=5 (fetch_more).
        let result = self.query_internal(sql, params_to_use, None, 1000, true).await;

        // Clean up temp LOBs
        self.cleanup_temp_lobs(&temp_lobs).await;

        result
    }

    /// Execute a query and return a streaming result set.
    ///
    /// Unlike [`query`](Self::query), this does not load the entire result set
    /// into memory. Rows are fetched in batches of `fetch_size` and yielded
    /// one at a time via [`RowStream::next`].
    ///
    /// # Arguments
    ///
    /// * `sql` - The SQL query to execute
    /// * `params` - Bind parameters
    /// * `fetch_size` - Number of rows to fetch per network round-trip
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_oracle::Connection;
    /// # async fn example() -> rust_oracle::Result<()> {
    /// let conn = Connection::connect("localhost:1521/FREEPDB1", "user", "pass").await?;
    /// let mut stream = conn.query_stream("SELECT * FROM huge_table", &[], 500).await?;
    /// while let Some(row) = stream.next().await {
    ///     println!("{:?}", row?.get_string(0));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_stream(
        &self,
        sql: &str,
        params: &[Value],
        fetch_size: u32,
    ) -> Result<crate::stream::RowStream> {
        let fetch_size = fetch_size.max(1);

        // CLOB auto-promotion
        let (promoted_params, temp_lobs) = self.promote_params_if_needed(params, MAX_VARCHAR_SQL).await?;
        let params_to_use: &[Value] = if temp_lobs.is_empty() { params } else { &promoted_params };

        let result = self
            .query_internal(sql, params_to_use, None, fetch_size, false)
            .await;

        // Clean up temp LOBs
        self.cleanup_temp_lobs(&temp_lobs).await;

        let result = result?;

        Ok(crate::stream::RowStream::new(
            self.clone(),
            result.columns,
            result.cursor_id,
            result.rows,
            result.has_more_rows,
            fetch_size,
        ))
    }

    /// Execute a query and return a streaming result set with default fetch size.
    ///
    /// Convenience wrapper around [`query_stream`](Self::query_stream) that uses
    /// [`DEFAULT_STREAM_FETCH_SIZE`](crate::constants::DEFAULT_STREAM_FETCH_SIZE) (256 rows per batch).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rust_oracle::Connection;
    ///
    /// # async fn example() -> rust_oracle::Result<()> {
    /// let conn = Connection::connect("localhost:1521/FREEPDB1", "user", "pass").await?;
    /// let mut stream = conn.query_stream_default("SELECT * FROM large_table", &[]).await?;
    /// while let Some(row) = stream.next().await {
    ///     println!("{:?}", row?.get_string(0));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_stream_default(
        &self,
        sql: &str,
        params: &[Value],
    ) -> Result<crate::stream::RowStream> {
        self.query_stream(sql, params, DEFAULT_STREAM_FETCH_SIZE).await
    }


    /// Execute a query and fetch at most `max_rows` rows.
    ///
    /// Unlike [`query`](Self::query), this method does not automatically drain
    /// the entire result set when the query returns more than `max_rows` rows.
    /// It fetches one extra row to detect truncation, then returns at most
    /// `max_rows` rows.
    pub async fn query_with_limit(
        &self,
        sql: &str,
        params: &[Value],
        max_rows: usize,
        fetch_size: u32,
    ) -> Result<QueryResult> {
        self.query_internal(sql, params, Some(max_rows.max(1)), fetch_size.max(1), true)
            .await
    }

    async fn query_internal(
        &self,
        sql: &str,
        params: &[Value],
        row_limit: Option<usize>,
        fetch_size: u32,
        drain: bool,
    ) -> Result<QueryResult> {
        self.ensure_ready().await?;

        // Check statement cache for existing prepared statement.
        // Reset cursor_id so we always use FunCode=94 (ExecuteAndFetch) instead
        // of FunCode=78 (ReexecuteAndFetch), which hangs Oracle XE on consumed cursors.
        let (statement, from_cache) = {
            let cache_arc = {
                let inner = self.inner.lock().await;
                inner.statement_cache.clone()
            };
            if let Some(cache) = cache_arc {
                let mut cache = cache.lock().await;
                if let Some(mut cached_stmt) = cache.get(sql) {
                    cached_stmt.set_cursor_id(0);
                    cached_stmt.set_executed(false);
                    tracing::trace!(
                        sql = sql,
                        "Using cached statement (cursor_id reset)"
                    );
                    (cached_stmt, true)
                } else {
                    (Statement::new(sql), false)
                }
            } else {
                (Statement::new(sql), false)
            }
        };

        // If using cached statement, save the columns (Oracle won't resend on reexecute)
        let cached_columns = if from_cache {
            Some(statement.columns().to_vec())
        } else {
            None
        };

        // Cap initial OALUD prefetch at SDU-safe limit (400 rows).
        // Oracle XE truncates the initial response to SDU without setting
        // cursor_id when the response is too large, so exceeding this loses
        // rows. 400 is safe for tables up to ~14 wide VARCHAR2 columns.
        // Subsequent fetch_more calls (FunCode=5) use the full user-requested
        // batch size, which correctly handles multi-packet responses.
        const MAX_INITIAL_PREFETCH: u32 = 400;
        let initial_fetch_size = row_limit
            .map(|limit| limit.saturating_add(1).min(u32::MAX as usize) as u32)
            .unwrap_or(fetch_size)
            .min(MAX_INITIAL_PREFETCH);
        let mut result = self
            .execute_query_with_params_prefetch(&statement, params, initial_fetch_size)
            .await;

        // If cached statement returned 0 rows, retry with fresh parse
        if from_cache {
            if let Ok(ref qr) = result {
                if qr.rows.is_empty() && qr.columns.is_empty() {
                    let fresh = Statement::new(statement.sql());
                    result = self
                        .execute_query_with_params_prefetch(&fresh, params, initial_fetch_size)
                        .await;
                }
            }
        }

        // Auto-fetch remaining rows using FunCode=5 (Fetch).
        // FunCode=5 now works on Oracle XE (as of sequence-number fix).
        let orig_cursor_id = if let Ok(ref qr) = result { qr.cursor_id } else { 0 };
        if let Ok(ref mut qr) = result {
            // Determine how many more rows we need (if there's a limit)
            let limit = row_limit;

            // Auto-fetch loop: keep calling fetch_more while cursor is open.
            // Only when drain=true (query/query_with_limit). For query_stream
            // (drain=false), the RowStream will lazily fetch more rows.
            if drain {
                // For drain mode, use large batch sizes to minimize round trips.
                // The fetch_size is designed for streaming; for draining we want
                // to pull as many rows as possible per fetch_more call.
                // Capped at 500: Oracle 10g may close the cursor prematurely when
                // fetch_more requests too many rows (e.g. 10000 hits an SDU/internal
                // limit that causes the server to truncate the response + close cursor).
                const DRAIN_BATCH: u32 = 500;
                while qr.cursor_id > 0 {
                    let need_more = match limit {
                        Some(max) => qr.rows.len() < max,
                        None => true,
                    };
                    if !need_more {
                        break;
                    }

                    let batch_size = match limit {
                        Some(max) => {
                            let remaining = max.saturating_sub(qr.rows.len());
                            remaining.min(DRAIN_BATCH as usize) as u32
                        }
                        None => DRAIN_BATCH,
                    };

                    if batch_size == 0 {
                        break;
                    }

                    let columns = qr.columns.clone();
                    match self.fetch_more(qr.cursor_id, &columns, batch_size).await {
                        Ok(more) => {
                            qr.rows.extend(more.rows);
                            qr.cursor_id = more.cursor_id;
                        }
                        Err(_) => {
                            qr.cursor_id = 0;
                            break;
                        }
                    }
                }
            }

            // Apply row_limit truncation
            if let Some(max) = limit {
                if qr.rows.len() > max {
                    qr.rows.truncate(max);
                    qr.has_more_rows = true;
                }
            }

            // After drain, cursor is exhausted or we hit a row_limit.
            // For streaming (drain=false), preserve cursor_id for RowStream.
            if drain {
                qr.has_more_rows = qr.has_more_rows || (qr.cursor_id > 0);
                qr.cursor_id = 0;
            } else {
                qr.has_more_rows = qr.cursor_id > 0;
            }
        }

        // Drain any stale data left in TCP buffer to prevent cross-query pollution
        {
            let mut inner = self.inner.lock().await;
            inner.drain_stale_packets().await;
            // Oracle 10g: close cursor after draining to prevent ORA-01002 on next query.
            // The server keeps cursors open even after all rows are fetched — without
            // an explicit CloseCursors piggyback, the next execute gets rejected.
            if drain
                && inner.capabilities.ttc_field_version <= ccap_value::FIELD_VERSION_10_2
                && orig_cursor_id > 0
            {
                inner.close_cursor_10g(orig_cursor_id).await?;
            }
        }

        // For cached statements, restore columns if Oracle didn't send them
        if let (Ok(ref mut query_result), Some(columns)) = (&mut result, cached_columns) {
            if query_result.columns.is_empty() && !columns.is_empty() {
                query_result.columns = columns;
            }
        }

        // Return statement to cache (cursor_id is always 0 after auto-fetch).
        // The cache avoids re-creating Statement objects; cursor_id=0 ensures
        // FunCode=94 (ExecuteAndFetch) is always used, avoiding FunCode=78 hangs.
        match &result {
            Ok(_query_result) => {
                let cache_arc = {
                    let inner = self.inner.lock().await;
                    inner.statement_cache.clone()
                };
                if let Some(cache) = cache_arc {
                    let mut cache = cache.lock().await;
                    if from_cache {
                        cache.return_statement(sql);
                    } else if !statement.is_ddl() {
                        let mut stmt_to_cache = statement.clone();
                        stmt_to_cache.set_cursor_id(0);
                        stmt_to_cache.set_executed(false);
                        cache.put(sql.to_string(), stmt_to_cache);
                    }
                }
            }
            Err(_) => {
                if from_cache {
                    let cache_arc = {
                        let inner = self.inner.lock().await;
                        inner.statement_cache.clone()
                    };
                    if let Some(cache) = cache_arc {
                        let mut cache = cache.lock().await;
                        cache.return_statement(sql);
                    }
                }
            }
        }

        // Auto-fetch small CLOB/NCLOB locators for transparent string access.
        // Large CLOBs (>4MB) stay as locators for explicit read_clob/lob_stream.
        if let Ok(ref mut qr) = result {
            if let Err(e) = self.auto_fetch_small_clobs(qr).await {
                tracing::warn!("Failed to auto-fetch CLOB content: {}", e);
            }
        }

        self.handle_result(result)
    }

    /// Auto-fetch CLOB/NCLOB locators whose size is under the threshold.
    /// Replaces fetched locators with Value::String so get_string() works
    /// transparently — no need for callers to manually call read_clob().
    /// Skipped on 10g where LOB locator protocol is unreliable.
    async fn auto_fetch_small_clobs(&self, result: &mut QueryResult) -> Result<()> {
        // Skip on 10g (FIELD_VERSION_10_2 = 0): LOB locator reads hang.
        {
            let inner = self.inner.lock().await;
            if inner.capabilities.ttc_field_version <= ccap_value::FIELD_VERSION_10_2 {
                return Ok(());
            }
        }

        const MAX_AUTO_FETCH: u64 = 4 * 1024 * 1024; // 4MB

        for row in &mut result.rows {
            let values = row.values_mut();
            for value in values.iter_mut() {
                let loc = match value {
                    Value::Lob(LobValue::Locator(loc))
                        if loc.is_clob() && loc.size > 0 && loc.size <= MAX_AUTO_FETCH =>
                    {
                        loc.clone()
                    }
                    _ => continue,
                };
                let data = self.read_lob_internal(&loc, 1, loc.size).await?;
                let text = match data {
                    LobData::String(s) => s,
                    _ => String::from_utf8_lossy(
                        data.as_bytes().unwrap_or(&bytes::Bytes::new()),
                    )
                    .into_owned(),
                };
                *value = Value::String(text);
            }
        }
        Ok(())
    }

    /// Execute DML (INSERT, UPDATE, DELETE) and return rows affected
    pub async fn execute_dml_sql(&self, sql: &str, params: &[Value]) -> Result<u64> {
        self.ensure_ready().await?;

        // Check statement cache for existing prepared statement
        let (statement, from_cache) = {
            let cache_arc = {
                let inner = self.inner.lock().await;
                inner.statement_cache.clone()
            };
            if let Some(cache) = cache_arc {
                let mut cache = cache.lock().await;
                if let Some(cached_stmt) = cache.get(sql) {
                    tracing::trace!(
                        sql = sql,
                        cursor_id = cached_stmt.cursor_id(),
                        "Using cached DML statement"
                    );
                    (cached_stmt, true)
                } else {
                    (Statement::new(sql), false)
                }
            } else {
                (Statement::new(sql), false)
            }
        };

        let result = self.execute_dml_with_params(&statement, params).await;

        // Return statement to cache or cache it for the first time
        // DML cursors are always closed after execution (no fetch phase)
        match &result {
            Ok(query_result) => {
                let cache_arc = {
                    let inner = self.inner.lock().await;
                    inner.statement_cache.clone()
                };
                if let Some(cache) = cache_arc {
                    let mut cache = cache.lock().await;
                    if from_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    } else if query_result.cursor_id > 0 && !statement.is_ddl() {
                        let mut stmt_to_cache = statement.clone();
                        stmt_to_cache.set_cursor_id(query_result.cursor_id);
                        stmt_to_cache.set_executed(true);
                        cache.put(sql.to_string(), stmt_to_cache);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
            Err(_) => {
                if from_cache {
                    let cache_arc = {
                        let inner = self.inner.lock().await;
                        inner.statement_cache.clone()
                    };
                    if let Some(cache) = cache_arc {
                        let mut cache = cache.lock().await;
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
        }

        self.handle_result(result).map(|r| r.rows_affected)
    }

    /// Execute a PL/SQL block with IN/OUT/INOUT parameters
    ///
    /// This method allows execution of PL/SQL anonymous blocks or procedure calls
    /// that have OUT or IN OUT parameters. The `params` slice specifies the direction
    /// and type of each bind parameter.
    ///
    /// # Arguments
    ///
    /// * `sql` - The PL/SQL block or procedure call
    /// * `params` - The bind parameters with direction information
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rust_oracle::{Connection, BindParam, OracleType, Value};
    ///
    /// // Call a procedure with IN and OUT parameters
    /// let result = conn.execute_plsql(
    ///     "BEGIN get_employee_name(:1, :2); END;",
    ///     &[
    ///         BindParam::input(Value::Integer(100)),           // IN: employee_id
    ///         BindParam::output(OracleType::Varchar, 100),     // OUT: employee_name
    ///     ]
    /// ).await?;
    ///
    /// // Get the OUT parameter value
    /// let name = result.get_string(0).unwrap_or("Unknown");
    /// println!("Employee name: {}", name);
    /// ```
    ///
    /// # REF CURSOR Example
    ///
    /// ```rust,ignore
    /// use rust_oracle::{Connection, BindParam, Value};
    ///
    /// // Call a procedure that returns a REF CURSOR
    /// let result = conn.execute_plsql(
    ///     "BEGIN OPEN :1 FOR SELECT * FROM employees; END;",
    ///     &[BindParam::output_cursor()]
    /// ).await?;
    ///
    /// // Get the cursor ID and fetch rows
    /// if let Some(cursor_id) = result.get_cursor_id(0) {
    ///     let rows = conn.fetch_cursor(cursor_id, 100).await?;
    ///     for row in rows {
    ///         println!("{:?}", row);
    ///     }
    /// }
    /// ```
    #[tracing::instrument(skip(self, params), fields(sql = %sql, params.len = params.len()))]
    pub async fn execute_plsql(&self, sql: &str, params: &[BindParam]) -> Result<PlsqlResult> {
        self.ensure_ready().await?;

        let statement = Statement::new(sql);

        // Build values for bind parameters
        // IN params: use provided value or Null
        // OUT params: use placeholder value (required for metadata, server ignores actual value)
        // INOUT params: use provided value or Null
        let bind_values: Vec<Value> = params
            .iter()
            .map(|p| {
                if p.direction == BindDirection::Output {
                    // OUT params get a placeholder based on their type
                    // Oracle still needs a value sent in the request (even though it's ignored)
                    p.placeholder_value()
                } else {
                    // IN and INOUT params use the provided value or Null
                    p.value.clone().unwrap_or(Value::Null)
                }
            })
            .collect();

        // Build bind metadata for proper buffer sizes
        // For OUTPUT params, use the user-specified buffer_size
        // For INPUT params, derive buffer_size from the actual value
        let bind_metadata: Vec<crate::messages::BindMetadata> = params
            .iter()
            .zip(bind_values.iter())
            .map(|(p, v)| {
                let buffer_size = if p.buffer_size > 0 {
                    p.buffer_size
                } else {
                    // Derive from value
                    match v {
                        Value::String(s) => std::cmp::max(s.len() as u32, 1),
                        Value::Bytes(b) => std::cmp::max(b.len() as u32, 1),
                        Value::Integer(_) | Value::Number(_) => 22, // Oracle NUMBER max size
                        Value::Float(_) => 8,                       // BINARY_DOUBLE
                        Value::Boolean(_) => 1,
                        Value::Timestamp(_) => 13,
                        Value::Date(_) => 7,
                        Value::RowId(_) => 18,
                        _ => 100, // Default fallback
                    }
                };
                crate::messages::BindMetadata {
                    oracle_type: p.oracle_type,
                    buffer_size,
                }
            })
            .collect();

        // Create execute message with PL/SQL options
        let options = ExecuteOptions::for_plsql();
        let mut execute_msg = ExecuteMessage::new(&statement, options);
        execute_msg.set_bind_values(bind_values);
        execute_msg.set_bind_metadata(bind_metadata);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive response
        let response = inner.receive_response().await?;

        // Check for MARKER packet (indicates error - requires reset protocol)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle marker reset protocol and get the error packet
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            // Parse error response to extract the actual Oracle error
            let _: QueryResult = ProtocolParser.parse_error_response(payload)?;
            return Err(Error::Protocol("PL/SQL execution failed".to_string()));
        }

        // Parse the PL/SQL response
        let payload = response.slice(PACKET_HEADER_SIZE..);
        let caps = Arc::clone(&inner.capabilities);
        drop(inner); // Release lock before parsing

        ProtocolParser.parse_plsql_response(payload, &caps, params)
    }

    /// Execute a batch INSERT/UPDATE/DELETE with multiple rows in one round-trip.
    ///
    /// Convenience wrapper: for advanced control (batch errors, DML row counts),
    /// use [`execute_batch_with_options`](Self::execute_batch_with_options) or the
    /// [`BatchBuilder`](crate::batch::BatchBuilder) API.
    ///
    /// Single-row batches fall back to [`execute`](Self::execute) automatically.
    ///
    /// # Arguments
    /// * `sql` - SQL with bind placeholders (`:1`, `:2`, ...)
    /// * `rows` - Each inner `Vec<Value>` is one row of bind values
    pub async fn execute_batch(
        &self,
        sql: &str,
        rows: &[Vec<Value>],
    ) -> Result<BatchResult> {
        if rows.is_empty() {
            return Ok(BatchResult::new());
        }

        // Single-row fallback: delegate to execute() (no batch overhead)
        if rows.len() == 1 {
            let result = self.execute(sql, &rows[0]).await?;
            return Ok(BatchResult {
                total_rows_affected: result.rows_affected as u64,
                row_counts: Some(vec![result.rows_affected as u64]),
                success_count: 1,
                failure_count: 0,
                errors: Vec::new(),
            });
        }

        // CLOB auto-promotion per row
        let mut promoted_rows: Vec<Vec<Value>> = Vec::with_capacity(rows.len());
        let mut all_temp_lobs: Vec<LobLocator> = Vec::new();

        for row in rows {
            let (promoted_row, temp_lobs) = self.promote_params_if_needed(row, MAX_VARCHAR_SQL).await?;
            if !temp_lobs.is_empty() {
                all_temp_lobs.extend(temp_lobs);
            }
            promoted_rows.push(promoted_row);
        }

        // Build batch with (possibly promoted) rows
        let mut batch = BatchBinds::new(sql);
        for row in &promoted_rows {
            batch.add_row(row.clone());
        }
        batch.validate()?;

        let result = self.execute_batch_impl(&batch).await;

        // Clean up temp LOBs
        self.cleanup_temp_lobs(&all_temp_lobs).await;

        result
    }

    /// Execute a batch of DML statements with multiple rows of bind values.
    ///
    /// This is the full-featured batch API. For simple cases, use
    /// [`execute_batch`](Self::execute_batch) instead.
    ///
    /// # Arguments
    ///
    /// * `batch` - The batch containing SQL and rows of bind values
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rust_oracle::{Connection, BatchBuilder, Value};
    ///
    /// let batch = BatchBuilder::new("INSERT INTO users (id, name) VALUES (:1, :2)")
    ///     .add_row(vec![Value::Integer(1), Value::String("Alice".to_string())])
    ///     .add_row(vec![Value::Integer(2), Value::String("Bob".to_string())])
    ///     .with_row_counts()
    ///     .build();
    ///
    /// let result = conn.execute_batch(&batch).await?;
    /// println!("Total rows affected: {}", result.total_rows_affected);
    /// ```
    #[tracing::instrument(skip(self, batch), fields(sql = %batch.sql(), rows = batch.row_count()))]
    pub async fn execute_batch_impl(&self, batch: &BatchBinds) -> Result<BatchResult> {
        self.ensure_ready().await?;

        // Validate the batch
        batch.validate()?;

        if batch.rows.is_empty() {
            return Ok(BatchResult::new());
        }

        // Build execute options for batch DML
        let mut options = ExecuteOptions::for_dml(batch.options.auto_commit);
        options.num_execs = batch.rows.len() as u32;
        options.batch_errors = batch.options.batch_errors;
        options.dml_row_counts = batch.options.array_dml_row_counts;

        // Create execute message with batch bind values
        let mut execute_msg = ExecuteMessage::new(&batch.statement, options);
        execute_msg.set_batch_bind_values(batch.rows.clone());

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive response
        let mut response = inner.receive_response().await?;

        // Check packet type - handle MARKER packets
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle BREAK/RESET protocol same as regular DML
            response = self.handle_marker_protocol(&mut inner, response).await?;
        }

        // Parse the batch response
        let payload = response.slice(PACKET_HEADER_SIZE..);
        let ttc_fv = inner.capabilities.ttc_field_version;
        drop(inner); // Release lock before parsing

        ProtocolParser.parse_batch_response(
            payload,
            batch.rows.len(),
            batch.options.array_dml_row_counts,
            ttc_fv,
        )
    }

    /// Handle MARKER packet protocol (BREAK/RESET)
    async fn handle_marker_protocol(
        &self,
        inner: &mut ConnectionInner,
        initial_response: Bytes,
    ) -> Result<Bytes> {
        // Extract marker type from packet
        let marker_type = if initial_response.len() >= PACKET_HEADER_SIZE + 3 {
            initial_response[PACKET_HEADER_SIZE + 2]
        } else {
            1 // Assume BREAK
        };

        if marker_type == 1 {
            // BREAK marker - send RESET and wait for response
            self.send_marker(inner, 2).await?;

            // Wait for RESET marker back
            loop {
                match inner.receive().await {
                    Ok(pkt) => {
                        if pkt.len() < PACKET_HEADER_SIZE + 1 {
                            break;
                        }
                        let pkt_type = pkt[4];
                        if pkt_type == PacketType::Marker as u8 {
                            if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                if mk_type == 2 {
                                    // Got RESET marker, break out
                                    break;
                                }
                            }
                        } else if pkt_type == PacketType::Data as u8 {
                            // Got DATA packet - return it as the response
                            return Ok(pkt);
                        } else {
                            break;
                        }
                    }
                    Err(e) => {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }
                }
            }

            // After RESET, continue receiving until we get DATA packet
            loop {
                match inner.receive().await {
                    Ok(pkt) => {
                        let pkt_type = pkt[4];
                        if pkt_type == PacketType::Marker as u8 {
                            continue;
                        } else if pkt_type == PacketType::Data as u8 {
                            return Ok(pkt);
                        } else {
                            return Err(Error::Protocol(format!(
                                "Unexpected packet type {} after reset",
                                pkt_type
                            )));
                        }
                    }
                    Err(e) => {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }
                }
            }
        }

        Ok(initial_response)
    }

    /// Fetch more rows from an open cursor
    ///
    /// This method is used when a query result has `has_more_rows == true`
    /// to retrieve additional rows from the server.
    ///
    /// # Arguments
    ///
    /// * `cursor_id` - The cursor ID from a previous query result
    /// * `columns` - Column information from the original query
    /// * `fetch_size` - Number of rows to fetch
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut result = conn.query("SELECT * FROM large_table", &[]).await?;
    /// let mut all_rows = result.rows.clone();
    ///
    /// while result.has_more_rows {
    ///     result = conn.fetch_more(result.cursor_id, &result.columns, 100).await?;
    ///     all_rows.extend(result.rows);
    /// }
    /// ```
    pub async fn fetch_more(
        &self,
        cursor_id: u16,
        columns: &[ColumnInfo],
        fetch_size: u32,
    ) -> Result<QueryResult> {
        self.ensure_ready().await?;

        // FunCode=5 (Fetch) packet — fetch more rows from an open cursor.
        // Per OJDBC T4C8Oall.marshal(): cursor_id(SB4) + fetch_size(SB4).
        // The cursor must have been opened with scrollable=true for this to work.
        //
        // Uses WriteBuffer for correct TNS variable-length encoding (write_ub4).
        let mut inner = self.inner.lock().await;
        let ttc_version = inner.capabilities.ttc_field_version;
        let seq_num = inner.next_sequence_number();

        // Single-buffer construction: build payload directly into packet buffer
        // to avoid the extra alloc+copy from the old two-buffer approach.
        let mut packet = WriteBuffer::with_capacity(PACKET_HEADER_SIZE + 2 + 32);

        // Reserve header space — fill in after we know payload length
        packet.write_u16_be(0)?; // placeholder: length
        packet.write_u16_be(0)?; // placeholder: checksum / length upper
        packet.write_u8(PacketType::Data as u8)?;
        packet.write_u8(0)?; // Flags
        packet.write_u16_be(0)?; // Header checksum

        // Data flags (u16 BE)
        packet.write_u16_be(0)?;

        // RPC header
        packet.write_u8(MessageType::Function as u8)?;
        packet.write_u8(FunctionCode::Fetch as u8)?;
        packet.write_u8(seq_num)?;

        // Token (TTC >= 18)
        if ttc_version >= 18 {
            packet.write_ub8(0)?;
        }

        // cursor_id and fetch_size: UB2 for 10g (go-ora compat), UB4 for 11g+
        if ttc_version <= ccap_value::FIELD_VERSION_10_2 {
            packet.write_ub2(cursor_id)?;
            packet.write_ub2(fetch_size as u16)?;
        } else {
            packet.write_ub4(cursor_id as u32)?;
            packet.write_ub4(fetch_size)?;
        }

        // Patch header length
        let total_len = packet.inner_mut().len();
        if inner.large_sdu {
            packet.inner_mut()[..4].copy_from_slice(&(total_len as u32).to_be_bytes());
        } else {
            packet.inner_mut()[..2].copy_from_slice(&(total_len as u16).to_be_bytes());
        }

        inner.send(packet.as_slice()).await?;

        let mut response = inner.receive_response().await?;

        // Handle MARKER (BREAK) — server rejected the request
        if response[4] == PacketType::Marker as u8 {
            let marker_type = response.get(PACKET_HEADER_SIZE + 2).copied().unwrap_or(1);
            if marker_type == 1 {
                inner.send_marker(2).await?;
                for _ in 0..5 {
                    match inner.receive().await {
                        Ok(pkt) if pkt.len() >= PACKET_HEADER_SIZE + 3 => {
                            let pt = pkt[4];
                            if pt == PacketType::Marker as u8 && pkt[PACKET_HEADER_SIZE + 2] == 2 {
                                break;
                            }
                            if pt == PacketType::Data as u8 {
                                return ProtocolParser.parse_error_response(pkt.slice(PACKET_HEADER_SIZE..));
                            }
                        }
                        _ => break,
                    }
                }
            }
            return Err(Error::Protocol("Server rejected cursor re-fetch operation".to_string()));
        }

        let caps = Arc::clone(&inner.capabilities);

        let mut result = loop {
            let payload = response.slice(PACKET_HEADER_SIZE..);
            match ProtocolParser.parse_query_response_with_columns(payload, &caps, columns) {
                Ok(r) => break r,
                Err(Error::BufferUnderflow { .. }) => {
                    response = inner.receive_more_data(&response).await?;
                }
                Err(e) => return Err(e),
            }
        };

        // parse_query_response_with_columns hardcodes has_more_rows=false.
        // has_more_rows is determined by whether the server keeps the cursor open,
        // not by how many rows fit in this batch (SDU limits may reduce batch size).
        if result.cursor_id > 0 {
            result.has_more_rows = true;
        }

        // No drain_stale_packets — fetch_more response is fully consumed by parsing.
        // The caller (RowStream or auto-fetch loop) will drain before next OALUD.

        Ok(result)
    }

    /// Fetch rows from a REF CURSOR
    ///
    /// This method fetches rows from a REF CURSOR that was returned from a
    /// PL/SQL procedure or function. The cursor contains the column metadata
    /// and cursor ID needed to fetch the rows.
    ///
    /// # Arguments
    ///
    /// * `cursor` - The REF CURSOR returned from PL/SQL
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rust_oracle::{Connection, BindParam, Value};
    ///
    /// // Call a procedure that returns a REF CURSOR
    /// let result = conn.execute_plsql(
    ///     "BEGIN OPEN :1 FOR SELECT id, name FROM employees; END;",
    ///     &[BindParam::output_cursor()]
    /// ).await?;
    ///
    /// // Get the cursor and fetch rows
    /// if let Value::Cursor(cursor) = &result.out_values[0] {
    ///     let rows = conn.fetch_cursor(cursor).await?;
    ///     println!("Fetched {} rows", rows.row_count());
    ///     for row in &rows.rows {
    ///         println!("{:?}", row);
    ///     }
    /// }
    /// ```
    pub async fn fetch_cursor(&self, cursor: &crate::types::RefCursor) -> Result<QueryResult> {
        self.fetch_cursor_with_size(cursor, 100).await
    }

    /// Fetch rows from a REF CURSOR with a specified fetch size
    ///
    /// This is the same as `fetch_cursor` but allows specifying how many
    /// rows to fetch at once.
    ///
    /// REF CURSORs use an ExecuteMessage with only the FETCH option because
    /// the cursor is already open from the PL/SQL execution. The cursor_id
    /// and column metadata were obtained when the REF CURSOR was returned.
    ///
    /// # Arguments
    ///
    /// * `cursor` - The REF CURSOR returned from PL/SQL
    /// * `fetch_size` - Number of rows to fetch (default is 100)
    pub async fn fetch_cursor_with_size(
        &self,
        cursor: &crate::types::RefCursor,
        fetch_size: u32,
    ) -> Result<QueryResult> {
        use crate::messages::ExecuteMessage;

        if cursor.cursor_id() == 0 {
            return Err(Error::InvalidCursor(
                "Cursor ID is 0 (not initialized)".to_string(),
            ));
        }

        self.ensure_ready().await?;

        // REF CURSOR uses ExecuteMessage with FETCH only (no SQL, no EXECUTE)
        // Create a statement with the cursor's metadata
        let mut stmt = Statement::new(""); // No SQL for REF CURSOR
        stmt.set_cursor_id(cursor.cursor_id());
        stmt.set_columns(cursor.columns().to_vec());
        stmt.set_executed(true); // Already executed by Oracle
        stmt.set_statement_type(crate::statement::StatementType::Query); // This is a query cursor

        // Build execute message with only FETCH option
        let options = crate::messages::ExecuteOptions::for_ref_cursor(fetch_size);
        let mut execute_msg = ExecuteMessage::new(&stmt, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);

        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response (may span multiple packets — retry on underflow)
        let response = inner.receive_response().await?;

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            return ProtocolParser.parse_error_response(payload);
        }

        // Parse query response - use cursor's columns since they're already defined
        let payload = response.slice(PACKET_HEADER_SIZE..);
        let caps = Arc::clone(&inner.capabilities);
        drop(inner); // Release lock before parsing
        ProtocolParser.parse_fetch_response(payload, cursor.columns(), &caps)
    }

    /// Fetch rows from an implicit result set
    ///
    /// Implicit results are returned via `DBMS_SQL.RETURN_RESULT` from PL/SQL.
    /// They contain cursor metadata but no rows until fetched.
    ///
    /// # Arguments
    ///
    /// * `result` - The implicit result from PL/SQL execution
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let plsql_result = conn.execute_plsql(r#"
    ///     declare
    ///         c sys_refcursor;
    ///     begin
    ///         open c for select * from employees;
    ///         dbms_sql.return_result(c);
    ///     end;
    /// "#, &[]).await?;
    ///
    /// for implicit in plsql_result.implicit_results.iter() {
    ///     let rows = conn.fetch_implicit_result(implicit).await?;
    ///     println!("Fetched {} rows", rows.row_count());
    /// }
    /// ```
    pub async fn fetch_implicit_result(&self, result: &ImplicitResult) -> Result<QueryResult> {
        self.fetch_implicit_result_with_size(result, 100).await
    }

    /// Fetch rows from an implicit result set with a specified fetch size
    pub async fn fetch_implicit_result_with_size(
        &self,
        result: &ImplicitResult,
        fetch_size: u32,
    ) -> Result<QueryResult> {
        // Convert implicit result to RefCursor and use fetch_cursor mechanism
        let cursor = crate::types::RefCursor::new(result.cursor_id, result.columns.clone());
        self.fetch_cursor_with_size(&cursor, fetch_size).await
    }

    /// Open a scrollable cursor for bidirectional navigation
    ///
    /// Scrollable cursors allow moving forward and backward through result sets,
    /// jumping to specific positions, and fetching from various locations.
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL query to execute
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut cursor = conn.open_scrollable_cursor("SELECT * FROM employees").await?;
    ///
    /// // Move to different positions
    /// let first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await?;
    /// let last = conn.scroll(&mut cursor, FetchOrientation::Last, 0).await?;
    /// let row5 = conn.scroll(&mut cursor, FetchOrientation::Absolute, 5).await?;
    ///
    /// conn.close_cursor(&mut cursor).await?;
    /// ```
    pub async fn open_scrollable_cursor(&self, sql: &str) -> Result<ScrollableCursor> {
        self.ensure_ready().await?;

        let statement = Statement::new(sql);

        // For scrollable cursors, execute with scrollable flag and prefetch 1 row
        // to get column metadata. The scroll() method will fetch actual rows at
        // specific positions.
        let mut options = ExecuteOptions::for_query(1); // prefetch 1 row for column info

        options.scrollable = true;

        let mut execute_msg = ExecuteMessage::new(&statement, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;

        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol(
                "Empty scrollable cursor response".to_string(),
            ));
        }

        // Check for MARKER packet (indicates error - requires reset protocol)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle marker reset protocol and get the error packet
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            // Parse error response to extract the actual Oracle error
            let _: QueryResult = ProtocolParser.parse_error_response(payload)?;
            // If we get here without error, something unexpected happened
            return Err(Error::Protocol(
                "Unexpected successful response after MARKER".to_string(),
            ));
        }

        // Parse describe info to get columns
        let payload = response.slice(PACKET_HEADER_SIZE..);
        let result = ProtocolParser.parse_query_response(payload, &inner.capabilities)?;

        Ok(ScrollableCursor::new(result.cursor_id, result.columns))
    }

    /// Scroll to a position in a scrollable cursor and fetch rows
    ///
    /// # Arguments
    ///
    /// * `cursor` - The scrollable cursor to scroll
    /// * `orientation` - The direction/mode of scrolling
    /// * `offset` - Position offset (used for Absolute and Relative modes)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Go to first row
    /// let first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await?;
    ///
    /// // Go to absolute position 10
    /// let row10 = conn.scroll(&mut cursor, FetchOrientation::Absolute, 10).await?;
    ///
    /// // Move 5 rows forward from current position
    /// let plus5 = conn.scroll(&mut cursor, FetchOrientation::Relative, 5).await?;
    ///
    /// // Move 3 rows backward
    /// let minus3 = conn.scroll(&mut cursor, FetchOrientation::Relative, -3).await?;
    /// ```
    pub async fn scroll(
        &self,
        cursor: &mut ScrollableCursor,
        orientation: FetchOrientation,
        offset: i64,
    ) -> Result<ScrollResult> {
        self.ensure_ready().await?;

        if !cursor.is_open() {
            return Err(Error::CursorClosed);
        }

        // Create a statement for the scroll operation (uses the existing cursor)
        let mut stmt = Statement::new("");
        stmt.set_cursor_id(cursor.cursor_id);
        stmt.set_columns(cursor.columns.clone());
        stmt.set_executed(true);
        stmt.set_statement_type(crate::statement::StatementType::Query);

        // Build execute message with scroll_operation=true
        let mut options = ExecuteOptions::for_query(1);
        options.scrollable = true;
        options.scroll_operation = true;
        options.fetch_orientation = orientation as u32;
        // Calculate fetch_pos based on orientation
        options.fetch_pos = match orientation {
            FetchOrientation::First => 1,
            FetchOrientation::Last => 0, // Server calculates
            FetchOrientation::Absolute => offset.max(0) as u32,
            FetchOrientation::Relative => (cursor.position + offset).max(0) as u32,
            FetchOrientation::Next => (cursor.position + 1).max(0) as u32,
            FetchOrientation::Prior => (cursor.position - 1).max(0) as u32,
            FetchOrientation::Current => cursor.position.max(0) as u32,
        };

        let mut execute_msg = ExecuteMessage::new(&stmt, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response (may span multiple packets — retry on underflow)
        let response = inner.receive_response().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty scroll response".to_string()));
        }

        // Check for MARKER packet
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let _: QueryResult = ProtocolParser.parse_error_response(payload)?;
            return Err(Error::Protocol("Scroll operation failed".to_string()));
        }

        let caps = Arc::clone(&inner.capabilities);
        drop(inner); // Release lock before parsing
                     // Use cursor's columns since Oracle doesn't re-send column metadata for scroll operations
        let payload = response.slice(PACKET_HEADER_SIZE..);
        let query_result =
            ProtocolParser.parse_query_response_with_columns(payload, &caps, &cursor.columns)?;

        // Use position from Oracle's response (rows_affected contains the row position)
        // For scrollable cursors, Oracle returns the row number in error_info.rowcount
        let new_position = if !query_result.rows.is_empty() {
            // Position is the actual row number from Oracle
            query_result.rows_affected as i64
        } else {
            // No rows returned - calculate position based on orientation
            match orientation {
                FetchOrientation::First => 0, // Before first
                FetchOrientation::Last => cursor.row_count.unwrap_or(0) as i64 + 1, // After last
                FetchOrientation::Next => cursor.position + 1,
                FetchOrientation::Prior => cursor.position - 1,
                FetchOrientation::Absolute => offset,
                FetchOrientation::Relative => cursor.position + offset,
                FetchOrientation::Current => cursor.position,
            }
        };

        cursor.update_position(new_position);

        let mut result = ScrollResult::new(query_result.rows, new_position);
        result.at_end = !query_result.has_more_rows;
        result.at_beginning = new_position <= 1;

        Ok(result)
    }

    /// Close a scrollable cursor
    ///
    /// Sends a `CloseCursors` function message to the Oracle server to release
    /// the cursor's PGA memory. This is important for long-lived connections
    /// that create and discard many scrollable cursors.
    ///
    /// # Arguments
    ///
    /// * `cursor` - The scrollable cursor to close
    pub async fn close_cursor(&self, cursor: &mut ScrollableCursor) -> Result<()> {
        if !cursor.is_open() {
            return Ok(());
        }

        cursor.mark_closed();
        let cursor_id = cursor.cursor_id;

        let mut inner = self.inner.lock().await;
        if inner.state != ConnectionState::Ready {
            return Ok(());
        }

        let seq_num = inner.next_sequence_number();
        let ttc_version = inner.capabilities.ttc_field_version;

        // Stack-allocated packet: payload ≤ 12 bytes, header 8 bytes
        let mut pkt = [0u8; 64];
        let mut pos: usize = 8; // reserve 8 bytes for header

        // Data flags (u16 BE)
        pkt[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
        pos += 2;

        // RPC header
        pkt[pos] = MessageType::Function as u8;
        pos += 1;
        pkt[pos] = FunctionCode::CloseCursors as u8;
        pos += 1;
        pkt[pos] = seq_num;
        pos += 1;

        // Token (TTC >= 18)
        if ttc_version >= 18 {
            pkt[pos] = 0; // ub8(0)
            pos += 1;
        }

        // cursor_id: UB4-encoded
        match cursor_id as u32 {
            0 => {
                pkt[pos] = 0;
                pos += 1;
            }
            1..=255 => {
                pkt[pos] = 1;
                pkt[pos + 1] = cursor_id as u8;
                pos += 2;
            }
            _ => {
                pkt[pos] = 2;
                pkt[pos + 1..pos + 3].copy_from_slice(&(cursor_id as u16).to_be_bytes());
                pos += 3;
            }
        }

        let payload_len = pos - 8;
        let packet_len = PACKET_HEADER_SIZE + payload_len;

        // Header at position 0
        pkt[0..2].copy_from_slice(&(packet_len as u16).to_be_bytes());
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // checksum
        pkt[4] = PacketType::Data as u8;
        pkt[5] = 0; // flags
        pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // header checksum

        inner.send(&pkt[..pos]).await?;

        // Read response (don't error if it fails — cursor is marked closed either way)
        let _ = inner.receive().await;

        Ok(())
    }

    /// Get type information for a database object or collection type
    ///
    /// This method queries Oracle's data dictionary to retrieve type metadata
    /// for collections (VARRAY, Nested Table) and user-defined object types.
    ///
    /// # Arguments
    ///
    /// * `type_name` - Fully qualified type name (e.g., "SCHEMA.TYPE_NAME" or just "TYPE_NAME")
    ///
    /// # Returns
    ///
    /// A `DbObjectType` containing the type metadata, including:
    /// - Schema and type name
    /// - Whether it's a collection
    /// - Collection type (VARRAY, Nested Table, etc.)
    /// - Element type for collections
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let number_array = conn.get_type("MY_NUMBER_ARRAY").await?;
    /// assert!(number_array.is_collection);
    /// ```
    pub async fn get_type(&self, type_name: &str) -> Result<crate::dbobject::DbObjectType> {
        use crate::dbobject::{CollectionType, DbObjectType};

        self.ensure_ready().await?;

        // Parse type name into schema and name
        let (schema, name) = parse_type_name(type_name, &self.config.username);

        // First, query ALL_TYPES to get basic type info
        let type_info = self
            .query(
                "SELECT typecode, type_oid FROM all_types WHERE owner = :1 AND type_name = :2",
                &[Value::String(schema.clone()), Value::String(name.clone())],
            )
            .await?;

        if type_info.rows.is_empty() {
            return Err(Error::OracleError {
                code: 4043, // ORA-04043: object does not exist
                message: format!("Type {}.{} not found", schema, name),
            });
        }

        let row = &type_info.rows[0];
        let typecode = row.get(0).and_then(|v| v.as_str()).unwrap_or("");
        let type_oid = row.get(1).and_then(|v| v.as_bytes()).map(|b| b.to_vec());

        // Check if it's a collection
        if typecode == "COLLECTION" {
            // Query ALL_COLL_TYPES for collection details
            let coll_info = self.query(
                "SELECT coll_type, elem_type_name, elem_type_owner, upper_bound FROM all_coll_types WHERE owner = :1 AND type_name = :2",
                &[Value::String(schema.clone()), Value::String(name.clone())],
            ).await?;

            if coll_info.rows.is_empty() {
                return Err(Error::OracleError {
                    code: 4043,
                    message: format!("Collection type {}.{} metadata not found", schema, name),
                });
            }

            let coll_row = &coll_info.rows[0];
            let coll_type_str = coll_row.get(0).and_then(|v| v.as_str()).unwrap_or("");
            let elem_type_name = coll_row
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("VARCHAR2");
            let _elem_type_owner = coll_row.get(2).and_then(|v| v.as_str());

            let collection_type = match coll_type_str {
                "VARYING ARRAY" => CollectionType::Varray,
                "TABLE" => CollectionType::NestedTable,
                _ => CollectionType::Varray, // Default
            };

            let element_type = oracle_type_from_name(elem_type_name);

            let mut obj_type =
                DbObjectType::collection(schema, name, collection_type, element_type);
            obj_type.oid = type_oid;
            Ok(obj_type)
        } else {
            // Regular object type (not yet fully implemented)
            let mut obj_type = DbObjectType::new(schema, name);
            obj_type.oid = type_oid;
            Ok(obj_type)
        }
    }

    /// Internal: Execute a query statement with optional bind parameters
    async fn execute_query_with_params(
        &self,
        statement: &Statement,
        params: &[Value],
    ) -> Result<QueryResult> {
        self.execute_query_with_params_prefetch(statement, params, 500)
            .await
    }

    /// Internal: Execute a query statement with optional bind parameters and a custom prefetch size.
    async fn execute_query_with_params_prefetch(
        &self,
        statement: &Statement,
        params: &[Value],
        prefetch_rows: u32,
    ) -> Result<QueryResult> {
        let prefetch_rows = prefetch_rows.max(1);

        let options = ExecuteOptions::for_query(prefetch_rows);
        let mut execute_msg = ExecuteMessage::new(statement, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);

        // Hot path: build request with borrowed params (zero-clone)
        let request = execute_msg.build_request_with_params(&inner.capabilities, large_sdu, params)?;
        inner.send(&request).await?;

        // Receive and parse response — retry with more data on BufferUnderflow
        let mut response = inner.receive_response().await?;

        // Check for MARKER packet (indicates error - requires reset protocol)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            return ProtocolParser.parse_error_response(payload);
        }

        // Parse with retry: if BufferUnderflow, read more packets and retry
        let mut result = loop {
            let payload = response.slice(PACKET_HEADER_SIZE..);
            match ProtocolParser.parse_query_response(payload, &inner.capabilities) {
                Ok(r) => {
                    break r;
                },
                Err(Error::BufferUnderflow { .. }) => {
                    response = inner.receive_more_data(&response).await?;
                }
                Err(e) => return Err(e),
            }
        };

        // Drain stale data after successful parse
        inner.drain_stale_packets().await;

        // Check if any columns are LOB types that require defines
        let has_lob_columns = result.columns.iter().any(|col| col.is_lob());

        if has_lob_columns && !statement.requires_define() {
            // We need to re-execute with column defines
            // Create a modified statement with the define flag set
            let mut stmt_with_define = statement.clone();
            stmt_with_define.set_columns(result.columns.clone());
            stmt_with_define.set_cursor_id(result.cursor_id);
            stmt_with_define.set_requires_define(true);
            stmt_with_define.set_no_prefetch(true);
            stmt_with_define.set_executed(true);

            // Re-execute with defines
            let define_options = ExecuteOptions::for_query(prefetch_rows);
            let mut define_msg = ExecuteMessage::new(&stmt_with_define, define_options);
            let seq_num = inner.next_sequence_number();
            define_msg.set_sequence_number(seq_num);

            let define_request =
                define_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
            inner.send(&define_request).await?;

            // Receive the re-execute response
            let define_response = inner.receive_response().await?;

            // Check for MARKER packet
            let packet_type = define_response[4];
            if packet_type == PacketType::Marker as u8 {
                let error_response = inner.handle_marker_reset().await?;
                let payload = error_response.slice(PACKET_HEADER_SIZE..);
                return ProtocolParser.parse_error_response(payload);
            }

            // Parse the response with LOB data, using the columns we already know
            let payload = define_response.slice(PACKET_HEADER_SIZE..);
            result = ProtocolParser.parse_query_response_with_columns(
                payload,
                &inner.capabilities,
                &stmt_with_define.columns(),
            )?;
        }

        Ok(result)
    }

    /// Internal: Execute a DML statement with optional bind parameters
    async fn execute_dml_with_params(
        &self,
        statement: &Statement,
        params: &[Value],
    ) -> Result<QueryResult> {
        let auto_commit = {
            let inner = self.inner.lock().await;
            inner.auto_commit
        };
        let options = ExecuteOptions::for_dml(auto_commit);
        let mut execute_msg = ExecuteMessage::new(statement, options);

        let mut inner = self.inner.lock().await;
        let ttc_fv = inner.capabilities.ttc_field_version;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_params(&inner.capabilities, large_sdu, params)?;

        inner.send(&request).await?;

        // Receive response
        let mut response = inner.receive_response().await?;

        // Check packet type - handle MARKER packets
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Need to do reset protocol and then get the actual response
            // Extract marker type from packet: after header (8 bytes) + data flags (2 bytes) + marker type (1 byte)
            let marker_type = if response.len() >= PACKET_HEADER_SIZE + 3 {
                response[PACKET_HEADER_SIZE + 2]
            } else {
                1 // Assume BREAK
            };

            if marker_type == 1 {
                // BREAK marker - send RESET and wait for response
                self.send_marker(&mut inner, 2).await?;

                // Wait for RESET marker back or DATA packet with error
                // The server may send: RESET marker, or BREAK marker followed by DATA, or just close
                let mut got_reset = false;
                let mut max_attempts = 5;
                loop {
                    match inner.receive().await {
                        Ok(pkt) => {
                            if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                break;
                            }
                            let pkt_type = pkt[4];
                            if pkt_type == PacketType::Marker as u8 {
                                if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                    let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                    if mk_type == 2 {
                                        // Got RESET marker, break out
                                        got_reset = true;
                                        break;
                                    }
                                    // Got another BREAK marker - server may be acknowledging
                                    // Keep trying a few times
                                    max_attempts -= 1;
                                    if max_attempts == 0 {
                                        // Give up and return a generic error
                                        return Err(Error::Protocol(
                                            "Server rejected operation (multiple BREAK markers)"
                                                .to_string(),
                                        ));
                                    }
                                    continue;
                                }
                            } else if pkt_type == PacketType::Data as u8 {
                                // Got DATA packet - use this as the response (may contain error)
                                let payload = pkt.slice(PACKET_HEADER_SIZE..);
                                return ProtocolParser.parse_dml_response(payload, ttc_fv);
                            } else {
                                break;
                            }
                        }
                        Err(e) => {
                            // If we get EOF, the server may have closed the connection
                            // This can happen with temp LOB binding issues
                            inner.state = ConnectionState::Closed;
                            return Err(Error::Protocol(format!(
                                "Server closed connection during error handling: {}",
                                e
                            )));
                        }
                    }
                }

                // After RESET, try to receive DATA packet with error response
                // Note: Some Oracle servers "quit immediately" after reset without sending
                // an error packet. In that case, we'll get EOF which is handled below.
                if got_reset {
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    // Too short, connection may be closing
                                    break;
                                }
                                let pkt_type = pkt[4];
                                if pkt_type == PacketType::Marker as u8 {
                                    // More markers, keep reading
                                    continue;
                                } else if pkt_type == PacketType::Data as u8 {
                                    // Got DATA packet, use this as the response
                                    response = pkt;
                                    break;
                                } else {
                                    // Unknown packet type, return error
                                    return Err(Error::Protocol(format!(
                                        "Unexpected packet type {} after reset",
                                        pkt_type
                                    )));
                                }
                            }
                            Err(_e) => {
                                // EOF after reset is normal - server may close connection
                                // without sending error details. Return a descriptive error.
                                inner.state = ConnectionState::Closed;
                                return Err(Error::OracleError {
                                    code: 0,
                                    message: "Server rejected the operation and closed the connection. \
                                              This may happen when binding a temporary LOB to an INSERT statement. \
                                              Try using a different approach (e.g., DBMS_LOB procedures).".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Parse with retry for multi-packet responses
        let dml_result = loop {
            let payload = response.slice(PACKET_HEADER_SIZE..);
            match ProtocolParser.parse_dml_response(payload, ttc_fv) {
                Ok(r) => break r,
                Err(Error::BufferUnderflow { .. }) => {
                    response = inner.receive_more_data(&response).await?;
                }
                Err(e) => return Err(e),
            }
        };
        inner.drain_stale_packets().await;
        Ok(dml_result)
    }

    /// Commit the current transaction.
    ///
    /// Makes all changes in the current transaction permanent. After commit,
    /// a new transaction begins automatically.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_oracle::{Connection, Value};
    /// # async fn example(conn: Connection) -> rust_oracle::Result<()> {
    /// conn.execute("INSERT INTO users (name) VALUES (:1)", &["Alice".into()]).await?;
    /// conn.execute("INSERT INTO users (name) VALUES (:1)", &["Bob".into()]).await?;
    /// conn.commit().await?; // Both inserts are now permanent
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(skip(self))]
    pub async fn commit(&self) -> Result<()> {
        self.ensure_ready().await?;
        // Always use SQL COMMIT: the protocol-level FunctionCode::Commit
        // triggers a BREAK/RESET handshake on many Oracle versions (21c, 23ai)
        // and the server often closes the connection after the handshake.
        self.execute("COMMIT", &[]).await?;
        Ok(())
    }

    /// Rollback the current transaction.
    ///
    /// Discards all changes made in the current transaction. After rollback,
    /// a new transaction begins automatically.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_oracle::{Connection, Value};
    /// # async fn example(conn: Connection) -> rust_oracle::Result<()> {
    /// conn.execute("DELETE FROM users WHERE id = :1", &[1.into()]).await?;
    /// // Oops, wrong user!
    /// conn.rollback().await?; // Delete is undone
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(skip(self))]
    pub async fn rollback(&self) -> Result<()> {
        self.ensure_ready().await?;
        tracing::debug!("Sending ROLLBACK via SQL execute");
        // Always use SQL ROLLBACK: the protocol-level FunctionCode::Rollback
        // triggers a BREAK/RESET handshake on many Oracle versions (21c, 23ai)
        // and the server often closes the connection after the handshake.
        self.execute("ROLLBACK", &[]).await?;
        tracing::debug!("ROLLBACK completed successfully");
        Ok(())
    }

    /// Create a savepoint within the current transaction
    ///
    /// Savepoints allow partial rollback of a transaction. You can create multiple
    /// savepoints and rollback to any of them without affecting work done before
    /// that savepoint.
    ///
    /// # Arguments
    /// * `name` - The savepoint name (must be a valid Oracle identifier)
    ///
    /// # Example
    /// ```rust,ignore
    /// conn.execute("INSERT INTO t VALUES (1)", &[]).await?;
    /// conn.savepoint("sp1").await?;
    /// conn.execute("INSERT INTO t VALUES (2)", &[]).await?;
    /// conn.rollback_to_savepoint("sp1").await?; // Undoes the second insert
    /// conn.commit().await?; // Commits only the first insert
    /// ```
    pub async fn savepoint(&self, name: &str) -> Result<()> {
        self.ensure_ready().await?;
        self.execute(&format!("SAVEPOINT {}", name), &[]).await?;
        Ok(())
    }

    /// Rollback to a previously created savepoint
    ///
    /// This undoes all changes made after the savepoint was created, but keeps
    /// the transaction active. Changes made before the savepoint are preserved.
    ///
    /// # Arguments
    /// * `name` - The savepoint name to rollback to
    pub async fn rollback_to_savepoint(&self, name: &str) -> Result<()> {
        self.ensure_ready().await?;
        self.execute(&format!("ROLLBACK TO SAVEPOINT {}", name), &[])
            .await?;
        Ok(())
    }

    /// Ping the server to check if the connection is still alive.
    ///
    /// This executes a lightweight query (`SELECT 1 FROM DUAL`) to verify
    /// the connection is responsive. Useful for connection health checks
    /// in pooling scenarios.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_oracle::Connection;
    /// # async fn example(conn: Connection) -> rust_oracle::Result<()> {
    /// if conn.ping().await.is_ok() {
    ///     println!("Connection is alive");
    /// } else {
    ///     println!("Connection is dead");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn ping(&self) -> Result<()> {
        self.ensure_ready().await?;
        // Always use SQL ping: the protocol-level FunctionCode::Ping
        // triggers a BREAK/RESET handshake on many Oracle versions (21c, 23ai)
        // and the server often closes the connection after the handshake.
        self.query("SELECT 1 FROM DUAL", &[]).await?;
        Ok(())
    }

    /// Set the current schema for the session.
    ///
    /// Equivalent to `ALTER SESSION SET CURRENT_SCHEMA = "<schema>"`. This
    /// changes the default schema for unqualified table references without
    /// requiring a reconnect.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_oracle::Connection;
    /// # async fn example() -> rust_oracle::Result<()> {
    /// let conn = Connection::connect("localhost:1521/FREEPDB1", "user", "pass").await?;
    /// conn.set_schema("HR").await?;
    /// // Now unqualified table names resolve to HR.*
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_schema(&self, schema: &str) -> Result<()> {
        // Validate schema name to prevent SQL injection
        if schema.is_empty()
            || schema.len() > 128
            || !schema
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '#')
        {
            return Err(Error::InvalidConnectionString(format!(
                "invalid schema name: \"{}\"",
                schema
            )));
        }
        let sql = format!("ALTER SESSION SET CURRENT_SCHEMA = \"{}\"", schema);
        self.execute(&sql, &[]).await?;
        Ok(())
    }

    /// Set the Oracle Edition for Edition-Based Redefinition (EBR).
    ///
    /// Oracle EBR allows online application upgrades by maintaining multiple
    /// versions (editions) of database objects. This method directs the session
    /// to use objects from the specified edition.
    ///
    /// This is equivalent to `ALTER SESSION SET EDITION = <edition>` and JDBC's
    /// `oracle.jdbc.defaultEdition` property.
    ///
    /// # Arguments
    /// * `edition` - The edition name (valid Oracle identifier)
    pub async fn set_edition(&self, edition: &str) -> Result<()> {
        if edition.is_empty()
            || edition.len() > 128
            || !edition
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '#')
        {
            return Err(Error::InvalidConnectionString(format!(
                "invalid edition name: \"{}\"",
                edition
            )));
        }
        let sql = format!("ALTER SESSION SET EDITION = \"{}\"", edition);
        self.execute(&sql, &[]).await?;
        Ok(())
    }

    /// Clear the statement cache
    ///
    /// This should be called when recycling a connection in a pool to ensure
    /// that any stale cursor state is cleared. This is useful after errors
    /// or when the connection state may be inconsistent.
    pub async fn clear_statement_cache(&self) {
        let cache_arc = {
            let inner = self.inner.lock().await;
            inner.statement_cache.clone()
        };
        if let Some(cache) = cache_arc {
            cache.lock().await.clear();
        }
    }

    /// Read data from a LOB (CLOB or BLOB)
    ///
    /// # Arguments
    /// * `locator` - The LOB locator obtained from a query result
    /// * `offset` - Starting position (1-based, in characters for CLOB, bytes for BLOB)
    /// * `amount` - Amount to read (0 for entire LOB)
    ///
    /// # Returns
    /// For CLOB: returns the text content as a String
    /// For BLOB: returns the binary content as bytes
    pub async fn read_lob(&self, locator: &LobLocator) -> Result<LobData> {
        self.ensure_ready().await?;

        // Read the entire LOB starting at offset 1
        let offset = 1u64;
        let amount = locator.size();

        self.read_lob_internal(locator, offset, amount).await
    }

    /// Read a portion of a LOB
    pub async fn read_lob_range(
        &self,
        locator: &LobLocator,
        offset: u64,
        amount: u64,
    ) -> Result<LobData> {
        self.ensure_ready().await?;
        self.read_lob_internal(locator, offset, amount).await
    }

    /// Create a streaming reader for progressive LOB access.
    ///
    /// Returns a [`LobStream`] that reads the LOB chunk by chunk without
    /// loading the entire content into memory. Equivalent to
    /// `Blob.getBinaryStream()` / `Clob.getCharacterStream()` in JDBC.
    ///
    /// # Arguments
    /// * `locator` - The LOB locator from a query result
    /// * `chunk_size` - Bytes per chunk (0 defaults to 8192)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut stream = conn.lob_stream(&locator, 8192);
    /// while let Some(chunk) = stream.next().await? {
    ///     // process chunk
    /// }
    /// ```
    pub fn lob_stream(&self, locator: &LobLocator, chunk_size: u64) -> LobStream {
        LobStream::new(self.clone(), locator.clone(), chunk_size)
    }

    /// Read a CLOB and return as String
    ///
    /// This is a convenience method for reading CLOB data directly as a String.
    /// Returns an error if the LOB is not a CLOB.
    pub async fn read_clob(&self, locator: &LobLocator) -> Result<String> {
        if locator.is_blob() || locator.is_bfile() {
            return Err(Error::Protocol(
                "Cannot read BLOB/BFILE as string, use read_blob instead".to_string(),
            ));
        }

        let data = self.read_lob(locator).await?;
        match data {
            LobData::String(s) => Ok(s),
            LobData::Bytes(_) => Err(Error::Protocol(
                "Unexpected bytes from CLOB read".to_string(),
            )),
        }
    }

    /// Read a BLOB and return as bytes
    ///
    /// This is a convenience method for reading BLOB data directly as bytes.
    /// Returns an error if the LOB is a CLOB (use read_clob instead).
    pub async fn read_blob(&self, locator: &LobLocator) -> Result<bytes::Bytes> {
        if locator.is_clob() {
            return Err(Error::Protocol(
                "Cannot read CLOB as bytes, use read_clob instead".to_string(),
            ));
        }

        let data = self.read_lob(locator).await?;
        match data {
            LobData::Bytes(b) => Ok(b),
            LobData::String(_) => Err(Error::Protocol(
                "Unexpected string from BLOB read".to_string(),
            )),
        }
    }

    /// Read a LOB in chunks, calling a callback for each chunk
    ///
    /// This is useful for processing large LOBs without loading the entire
    /// content into memory. The callback receives each chunk as it's read.
    ///
    /// # Arguments
    /// * `locator` - The LOB locator
    /// * `chunk_size` - Size of each chunk to read (0 uses the LOB's natural chunk size)
    /// * `callback` - Async function called for each chunk
    ///
    /// # Example
    /// ```ignore
    /// let mut total_size = 0;
    /// conn.read_lob_chunked(&locator, 8192, |chunk| async move {
    ///     match chunk {
    ///         LobData::Bytes(b) => total_size += b.len(),
    ///         LobData::String(s) => total_size += s.len(),
    ///     }
    ///     Ok(())
    /// }).await?;
    /// ```
    pub async fn read_lob_chunked<F, Fut>(
        &self,
        locator: &LobLocator,
        chunk_size: u64,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(LobData) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        self.ensure_ready().await?;

        let total_size = locator.size();
        if total_size == 0 {
            return Ok(());
        }

        // Use LOB's natural chunk size if not specified
        let chunk_size = if chunk_size == 0 {
            self.lob_chunk_size(locator).await?.max(8192) as u64
        } else {
            chunk_size
        };

        let mut offset = 1u64;
        while offset <= total_size {
            let remaining = total_size - offset + 1;
            let amount = std::cmp::min(remaining, chunk_size);

            let chunk = self.read_lob_internal(locator, offset, amount).await?;
            callback(chunk).await?;

            offset += amount;
        }

        Ok(())
    }

    /// Get the optimal chunk size for a LOB
    ///
    /// This returns the chunk size that Oracle recommends for efficient
    /// reading and writing to this LOB.
    pub async fn lob_chunk_size(&self, locator: &LobLocator) -> Result<u32> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for get chunk size
        let mut lob_msg = LobOpMessage::new_get_chunk_size(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB chunk size response".to_string()));
        }

        // Check for MARKER packet
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        // Parse the amount response (chunk size is returned as amount)
        ProtocolParser.parse_lob_amount_response(response.slice(PACKET_HEADER_SIZE..), locator)
            .map(|v| v as u32)
    }

    /// Internal LOB read implementation
    async fn read_lob_internal(
        &self,
        locator: &LobLocator,
        offset: u64,
        amount: u64,
    ) -> Result<LobData> {
        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for read
        let mut lob_msg = LobOpMessage::new_read(locator, offset, amount);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response (may span multiple packets for large LOBs)
        let response = inner.receive_response().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB read response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            // Skip data flags
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        // Parse LOB data response (may span multiple packets — retry on underflow)
        let big_clr = inner.capabilities.ttc_field_version
            > crate::constants::ccap_value::FIELD_VERSION_11_2;
        let mut lob_response = response;
        loop {
            let payload = lob_response.slice(PACKET_HEADER_SIZE..);
            match ProtocolParser.parse_lob_read_response(payload, locator, big_clr) {
                Ok(data) => return Ok(data),
                Err(Error::BufferUnderflow { .. }) => {
                    lob_response = inner.receive_more_data(&lob_response).await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Write data to a LOB
    ///
    /// # Arguments
    /// * `locator` - The LOB locator obtained from a query result
    /// * `offset` - Starting position (1-based, in characters for CLOB, bytes for BLOB)
    /// * `data` - Data to write (bytes for BLOB, UTF-8 encoded bytes for CLOB)
    pub async fn write_lob(&self, locator: &LobLocator, offset: u64, data: &[u8]) -> Result<()> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let sdu_size = inner.sdu_size as usize;

        // Encode data for CLOB if necessary
        let encoded_data: Vec<u8>;
        let write_data = if locator.is_clob() && locator.uses_var_length_charset() {
            // Convert UTF-8 to UTF-16 BE for CLOB with var length charset
            let text = String::from_utf8_lossy(data);
            encoded_data = text.encode_utf16().flat_map(|c| c.to_be_bytes()).collect();
            &encoded_data[..]
        } else {
            data
        };

        // Create LOB operation message for write
        let mut lob_msg = LobOpMessage::new_write(locator, offset, write_data);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build message content (without packet header or data flags)
        let message = lob_msg.build_message_only(&inner.capabilities)?;

        // Calculate if this fits in a single packet
        // Single packet max payload = SDU - header (8) - data flags (2)
        let max_single_packet_payload = sdu_size.saturating_sub(PACKET_HEADER_SIZE + 2);

        let is_multi_packet = message.len() > max_single_packet_payload;

        if is_multi_packet {
            // Needs multiple packets - use multi-packet sender
            inner.send_multi_packet(&message, 0).await?;
        } else {
            // Fits in one packet - use standard send
            let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
            inner.send(&request).await?;
        }

        // Receive and parse response
        // Use receive_response() to accumulate all packets until END_OF_RESPONSE.
        // This is necessary because Oracle may send multiple packets for the response,
        // and if we only read one packet, leftover data causes close() to hang.
        let response = inner.receive_response().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB write response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        // Parse response to check for errors
        ProtocolParser.parse_lob_simple_response(response.slice(PACKET_HEADER_SIZE..), locator)
    }

    /// Write string data to a CLOB
    pub async fn write_clob(&self, locator: &LobLocator, offset: u64, text: &str) -> Result<()> {
        if locator.is_blob() || locator.is_bfile() {
            return Err(Error::Protocol(
                "Cannot write string to BLOB/BFILE, use write_blob instead".to_string(),
            ));
        }
        self.write_lob(locator, offset, text.as_bytes()).await
    }

    /// Write binary data to a BLOB
    pub async fn write_blob(&self, locator: &LobLocator, offset: u64, data: &[u8]) -> Result<()> {
        if locator.is_clob() {
            return Err(Error::Protocol(
                "Cannot write bytes to CLOB, use write_clob instead".to_string(),
            ));
        }
        self.write_lob(locator, offset, data).await
    }

    /// Get the length of a LOB
    ///
    /// For CLOB: returns length in characters
    /// For BLOB: returns length in bytes
    pub async fn lob_length(&self, locator: &LobLocator) -> Result<u64> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for get length
        let mut lob_msg = LobOpMessage::new_get_length(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB get_length response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        // Parse response to get the length
        ProtocolParser.parse_lob_amount_response(response.slice(PACKET_HEADER_SIZE..), locator)
    }

    /// Trim a LOB to a specified length
    ///
    /// # Arguments
    /// * `locator` - The LOB locator
    /// * `new_size` - The new size (in characters for CLOB, bytes for BLOB)
    pub async fn lob_trim(&self, locator: &LobLocator, new_size: u64) -> Result<()> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for trim
        let mut lob_msg = LobOpMessage::new_trim(locator, new_size);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB trim response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        // Parse response to check for errors
        ProtocolParser.parse_lob_simple_response(response.slice(PACKET_HEADER_SIZE..), locator)
    }

    /// Create a temporary LOB on the server
    ///
    /// Creates a temporary LOB of the specified type that lives until the connection
    /// is closed or the LOB is explicitly freed.
    ///
    /// # Arguments
    /// * `oracle_type` - The LOB type to create (Clob or Blob)
    ///
    /// # Returns
    /// A `LobLocator` for the newly created temporary LOB
    ///
    /// # Example
    /// ```ignore
    /// use rust_oracle::OracleType;
    ///
    /// let locator = conn.create_temp_lob(OracleType::Clob).await?;
    /// conn.write_clob(&locator, 1, "Hello, World!").await?;
    /// // Now bind the locator to insert into a CLOB column
    /// ```
    pub async fn create_temp_lob(&self, oracle_type: OracleType) -> Result<LobLocator> {
        use crate::buffer::ReadBuffer;

        // Validate oracle_type is a LOB type
        match oracle_type {
            OracleType::Clob | OracleType::Blob => {}
            _ => {
                return Err(Error::Protocol(format!(
                    "create_temp_lob: invalid type {:?}, must be Clob or Blob",
                    oracle_type
                )));
            }
        }

        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create the CREATE_TEMP message
        let mut lob_msg = LobOpMessage::new_create_temp(oracle_type);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol(
                "Empty CREATE_TEMP LOB response".to_string(),
            ));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        // Parse response to extract the locator
        let payload = response.slice(PACKET_HEADER_SIZE..);
        let mut buf = ReadBuffer::new(payload);
        buf.skip(2)?; // Skip data flags

        let mut locator_bytes: Option<Vec<u8>> = None;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Parameter return (8) - contains the populated locator
                x if x == MessageType::Parameter as u8 => {
                    // Read the 40-byte locator (matches the 40 bytes sent in request)
                    let loc_data = buf.read_bytes_vec(40)?;
                    locator_bytes = Some(loc_data);
                    // Skip charset (variable-length ub2) and trailing flags (raw u8)
                    buf.skip_ub2()?;
                    buf.skip(1)?;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = ProtocolParser.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message =
                                msg.unwrap_or_else(|| "CREATE_TEMP LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        // Create the LobLocator from the returned bytes
        let loc_bytes = locator_bytes.ok_or_else(|| {
            Error::Protocol("CREATE_TEMP LOB response did not contain locator".to_string())
        })?;

        // Create LobLocator with size 0, chunk_size 0 (will be fetched if needed)
        let locator = LobLocator::new(
            bytes::Bytes::from(loc_bytes),
            0, // size - unknown for new temp LOB
            0, // chunk_size - unknown, can be fetched later
            oracle_type,
            1, // csfrm - 1 for CLOB, 0 for BLOB (but we store it on the locator type)
        );

        Ok(locator)
    }

    /// Free a temporary LOB created with `create_temp_lob`.
    ///
    /// Temporary LOBs are automatically freed when the session ends, but
    /// explicit cleanup is recommended for long-lived connections.
    pub async fn free_temp_lob(&self, locator: &LobLocator) -> Result<()> {
        use crate::buffer::ReadBuffer;

        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_free_temp(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty FREE_TEMP LOB response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        let payload = response.slice(PACKET_HEADER_SIZE..);
        let mut buf = ReadBuffer::new(payload);
        buf.skip(2)?;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;
            match msg_type {
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = ProtocolParser.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message =
                                msg.unwrap_or_else(|| "FREE_TEMP LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }
                x if x == MessageType::EndOfResponse as u8 => break,
                _ => continue,
            }
        }

        Ok(())
    }

    /// Check parameters and promote oversized strings to temporary CLOB binds.
    /// Returns promoted params and a list of temp LOBs to free after execution.
    /// Detect whether a SQL statement is a PL/SQL anonymous block.
    ///
    /// Returns true if the trimmed, case-insensitive statement starts with
    /// `BEGIN` or `DECLARE`.
    #[allow(dead_code)]
    fn is_plsql_context(sql: &str) -> bool {
        let trimmed = sql.trim().to_uppercase();
        trimmed.starts_with("BEGIN") || trimmed.starts_with("DECLARE")
    }

    async fn promote_params_if_needed(
        &self,
        params: &[Value],
        max_varchar: usize,
    ) -> Result<(Vec<Value>, Vec<LobLocator>)> {
        // CLOB auto-promotion via CREATE_TEMP LOB does not work on 10g (FIELD_VERSION_10_2).
        // 10g's LOB operation protocol is fundamentally incompatible — CREATE_TEMP LOB
        // and LOB writes both kill the connection.
        {
            let inner = self.inner.lock().await;
            if inner.capabilities.ttc_field_version <= crate::constants::ccap_value::FIELD_VERSION_10_2 {
                // Check if any param actually needs promotion
                for value in params {
                    if let Value::String(s) = value {
                        if s.len() > max_varchar {
                            return Err(Error::Protocol(
                                "CLOB auto-promotion is not supported on Oracle 10g. \
                                 Values larger than the VARCHAR limit cannot be bound to CLOB columns.".into()
                            ));
                        }
                    }
                }
            }
        }

        let mut needs_promotion = false;
        for value in params {
            if let Value::String(s) = value {
                if s.len() > max_varchar {
                    needs_promotion = true;
                    break;
                }
            }
        }
        if !needs_promotion {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut promoted = Vec::with_capacity(params.len());
        let mut temp_lobs = Vec::new();
        for value in params {
            if let Value::String(s) = value {
                if s.len() > max_varchar {
                    let lob = self.create_temp_lob(OracleType::Clob).await?;
                    self.write_clob(&lob, 1, s).await?;
                    temp_lobs.push(lob.clone());
                    promoted.push(Value::Lob(LobValue::Locator(lob)));
                } else {
                    promoted.push(value.clone());
                }
            } else {
                promoted.push(value.clone());
            }
        }
        Ok((promoted, temp_lobs))
    }

    /// Free a list of temporary LOBs, ignoring errors.
    async fn cleanup_temp_lobs(&self, lobs: &[LobLocator]) {
        for lob in lobs {
            let _ = self.free_temp_lob(lob).await;
        }
    }

    // ==================== BFILE Operations ====================

    /// Check if a BFILE exists on the server
    ///
    /// Returns true if the file referenced by the BFILE locator exists on the server.
    pub async fn bfile_exists(&self, locator: &LobLocator) -> Result<bool> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_exists called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_exists(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE exists response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        ProtocolParser.parse_lob_bool_response(response.slice(PACKET_HEADER_SIZE..), locator)
    }

    /// Open a BFILE for reading
    ///
    /// The BFILE must be opened before reading. After reading, close it with bfile_close.
    pub async fn bfile_open(&self, locator: &LobLocator) -> Result<()> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_open called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_open(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE open response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        ProtocolParser.parse_lob_simple_response(response.slice(PACKET_HEADER_SIZE..), locator)
    }

    /// Close a BFILE after reading
    pub async fn bfile_close(&self, locator: &LobLocator) -> Result<()> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_close called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_close(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE close response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        ProtocolParser.parse_lob_simple_response(response.slice(PACKET_HEADER_SIZE..), locator)
    }

    /// Check if a BFILE is currently open
    pub async fn bfile_is_open(&self, locator: &LobLocator) -> Result<bool> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_is_open called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_is_open(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE is_open response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = error_response.slice(PACKET_HEADER_SIZE..);
            let mut buf = crate::buffer::ReadBuffer::new(payload);
            buf.skip(2)?;
            return ProtocolParser.parse_lob_error(&mut buf);
        }

        ProtocolParser.parse_lob_bool_response(response.slice(PACKET_HEADER_SIZE..), locator)
    }

    /// Read BFILE data
    ///
    /// This is a convenience method that opens the BFILE if needed, reads all content,
    /// and returns it as bytes. For large BFILEs, consider using read_lob_chunked.
    pub async fn read_bfile(&self, locator: &LobLocator) -> Result<bytes::Bytes> {
        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "read_bfile called on non-BFILE locator".to_string(),
            ));
        }

        // Check if file is open, open if needed
        let should_close = if !self.bfile_is_open(locator).await? {
            self.bfile_open(locator).await?;
            true
        } else {
            false
        };

        // Read all data
        let result = self.read_blob(locator).await;

        // Close if we opened it
        if should_close {
            let _ = self.bfile_close(locator).await;
        }

        result
    }

    /// Close the connection.
    ///
    /// Sends a logoff message to the server and closes the underlying TCP
    /// connection. After calling close, the connection cannot be reused.
    ///
    /// If the connection is already closed, this method returns `Ok(())`
    /// without doing anything.
    ///
    /// # Note
    ///
    /// Any uncommitted transaction is rolled back by the server when the
    /// connection is closed.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_oracle::{Config, Connection};
    /// # async fn example() -> rust_oracle::Result<()> {
    /// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
    /// let conn = Connection::connect_with_config(config).await?;
    ///
    /// // Do work...
    /// conn.commit().await?;
    ///
    /// // Explicitly close when done
    /// conn.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(skip(self))]
    pub async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::Relaxed) {
            // Already closed
            return Ok(());
        }

        let mut inner = self.inner.lock().await;

        if inner.state == ConnectionState::Ready {
            // Send logoff
            let _ = self
                .send_simple_function_inner(&mut inner, FunctionCode::Logoff)
                .await;
        }

        inner.state = ConnectionState::Closed;

        // Close the TCP stream
        if let Some(stream) = inner.stream.take() {
            drop(stream);
        }

        Ok(())
    }

    /// Cancel the currently executing operation on this connection.
    ///
    /// Sends a BREAK marker to the Oracle server to interrupt the in-progress
    /// query or DML. This is useful for cancelling long-running queries or
    /// implementing query timeouts.
    ///
    /// After calling cancel, the connection remains usable — the server sends
    /// a RESET marker to re-synchronize the connection state.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use tokio::time::{timeout, Duration};
    /// # use rust_oracle::{Config, Connection};
    /// # async fn example() -> rust_oracle::Result<()> {
    /// let conn = Connection::connect("localhost:1521/FREEPDB1", "user", "pass").await?;
    ///
    /// // Use with tokio::select for timeout
    /// let result = tokio::select! {
    ///     r = conn.query("SELECT * FROM huge_table", &[]) => r,
    ///     _ = tokio::time::sleep(Duration::from_secs(30)) => {
    ///         conn.cancel().await?;
    ///         return Err(rust_oracle::Error::ConnectionTimeout(Duration::from_secs(30)));
    ///     }
    /// };
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(skip(self))]
    pub async fn cancel(&self) -> Result<()> {
        tracing::warn!("cancelling in-progress operation");
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;

        // Send BREAK marker
        self.send_marker(&mut inner, 1).await?;

        // Handle RESET protocol
        loop {
            let response = inner.receive().await?;
            if response.len() < PACKET_HEADER_SIZE + 1 {
                return Err(Error::Protocol("Cancel response too short".to_string()));
            }
            let pkt_type = response[4];
            if pkt_type == PacketType::Marker as u8 {
                if response.len() >= PACKET_HEADER_SIZE + 3 {
                    let mk_type = response[PACKET_HEADER_SIZE + 2];
                    if mk_type == 2 {
                        // Got RESET marker — connection is re-synchronized
                        break;
                    }
                }
            } else if pkt_type == PacketType::Data as u8 {
                // Got DATA packet — return it (server sent error/result)
                break;
            }
        }

        Ok(())
    }

    /// Send a marker packet to the server
    /// marker_type: 1=BREAK, 2=RESET, 3=INTERRUPT
    async fn send_marker(&self, inner: &mut ConnectionInner, marker_type: u8) -> Result<()> {
        let mut packet_buf = WriteBuffer::new();

        // Build MARKER packet header
        let packet_len = PACKET_HEADER_SIZE + 3; // Header + 3 bytes payload
        packet_buf.write_u16_be(packet_len as u16)?;
        packet_buf.write_u16_be(0)?; // Checksum
        packet_buf.write_u8(PacketType::Marker as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum

        // Marker payload: [1, 0, marker_type] per Python's _send_marker
        packet_buf.write_u8(1)?;
        packet_buf.write_u8(0)?;
        packet_buf.write_u8(marker_type)?;

        inner.send(&packet_buf.freeze()).await
    }

    async fn send_simple_function_inner(
        &self,
        inner: &mut ConnectionInner,
        function_code: FunctionCode,
    ) -> Result<()> {
        // Build function message
        let mut buf = WriteBuffer::new();

        // Get next sequence number (must be done before sending)
        let seq_num = inner.next_sequence_number();

        // Message type: Function
        buf.write_u8(MessageType::Function as u8)?;
        // Function code
        buf.write_u8(function_code as u8)?;
        // Sequence number (tracked per connection)
        buf.write_u8(seq_num)?;

        // Token number (required for TTC field version >= 18, i.e. Oracle 23ai)
        if inner.capabilities.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        // Build DATA packet
        let data_payload = buf.freeze();
        let mut packet_buf = WriteBuffer::new();
        let packet_len = PACKET_HEADER_SIZE + 2 + data_payload.len();
        packet_buf.write_u16_be(packet_len as u16)?;
        packet_buf.write_u16_be(0)?; // Checksum
        packet_buf.write_u8(PacketType::Data as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum
        packet_buf.write_u16_be(0)?; // Data flags at offset 8
        packet_buf.write_bytes(&data_payload)?;

        let packet_bytes = packet_buf.freeze();
        inner.send(&packet_bytes).await?;

        // Wait for response
        let response = inner.receive().await?;

        // Check response
        if response.len() <= 4 {
            return Err(Error::Protocol("Response too short".to_string()));
        }

        let packet_type = response[4];

        // MARKER packet (type 12) - need to handle reset protocol
        if packet_type == PacketType::Marker as u8 {
            // Check marker type
            if response.len() >= PACKET_HEADER_SIZE + 3 {
                let marker_type = response[PACKET_HEADER_SIZE + 2];

                // For BREAK marker (1), we need to do the reset protocol
                if marker_type == 1 {
                    // For Logoff, Oracle may send BREAK to indicate "connection closing"
                    // Don't try to do the full reset handshake - just return success
                    if function_code == FunctionCode::Logoff {
                        inner.state = ConnectionState::Closed;
                        return Ok(());
                    }

                    // The BREAK marker means the server is interrupting/breaking the current operation
                    // We MUST complete the reset handshake or the connection will be in a bad state

                    // Send RESET marker to server
                    if let Err(e) = self.send_marker(inner, 2).await {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }

                    // Read and discard packets until we get RESET marker
                    // This follows Python's _reset() logic
                    let mut current_packet_type: u8;
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    break;
                                }
                                current_packet_type = pkt[4];

                                if current_packet_type == PacketType::Marker as u8 {
                                    if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                        let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                        if mk_type == 2 {
                                            // Got RESET marker, exit this loop
                                            break;
                                        }
                                    }
                                } else {
                                    // Non-marker packet - unexpected during reset wait
                                    break;
                                }
                            }
                            Err(e) => {
                                inner.state = ConnectionState::Closed;
                                return Err(e);
                            }
                        }
                    }

                    // After RESET, continue reading while we still get MARKER packets
                    // Some servers send multiple RESET markers, others send DATA response
                    // Python comment: "some quit immediately" - meaning some servers close
                    // the connection right after the reset handshake
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    break;
                                }
                                current_packet_type = pkt[4];

                                if current_packet_type == PacketType::Marker as u8 {
                                    // Another marker, continue reading
                                    continue;
                                }

                                // Got a non-marker packet (probably DATA with error/status)
                                if current_packet_type == PacketType::Data as u8 {
                                    if pkt.len() > PACKET_HEADER_SIZE + 2 {
                                        let msg_type = pkt[PACKET_HEADER_SIZE + 2];
                                        if msg_type == MessageType::Error as u8 {
                                            let payload = pkt.slice(PACKET_HEADER_SIZE..);
                                            let mut buf = ReadBuffer::new(payload);
                                            buf.skip(2)?; // data flags
                                            buf.skip(1)?; // msg_type
                                            let (error_code, error_msg, _) =
                                                ProtocolParser.parse_error_info(&mut buf)?;
                                            if error_code != 0 {
                                                return Err(Error::OracleError {
                                                    code: error_code,
                                                    message: error_msg.unwrap_or_else(|| {
                                                        format!("ORA-{:05}", error_code)
                                                    }),
                                                });
                                            }
                                        }
                                    }
                                }
                                // Exit after processing non-marker packet
                                break;
                            }
                            Err(_) => {
                                // Error reading - connection might be closed
                                // Python comment says "some quit immediately" - meaning some
                                // servers close the connection after BREAK/RESET handshake.
                                // For commit/rollback/logoff, treat this as success since
                                // the operation was processed before the close.
                                if matches!(
                                    function_code,
                                    FunctionCode::Logoff
                                        | FunctionCode::Commit
                                        | FunctionCode::Rollback
                                ) {
                                    // The operation succeeded, but the server closed the connection
                                    // Mark connection as closed for future operations
                                    inner.state = ConnectionState::Closed;
                                    return Ok(());
                                }
                                // For other functions, this means connection is broken
                                inner.state = ConnectionState::Closed;
                                // Don't return error for Ping - treat as success
                                if function_code == FunctionCode::Ping {
                                    return Ok(());
                                }
                                return Ok(()); // Conservative approach - treat as success
                            }
                        }
                    }

                    return Ok(());
                }
            }
            // For non-BREAK markers, just return success
            return Ok(());
        }

        // DATA packet (type 6)
        if packet_type == PacketType::Data as u8 {
            // Parse response to check for errors
            if response.len() > PACKET_HEADER_SIZE + 2 {
                let msg_type = response[PACKET_HEADER_SIZE + 2];
                if msg_type == MessageType::Error as u8 {
                    // Parse the error info
                    let payload = response.slice(PACKET_HEADER_SIZE..);
                    let mut buf = ReadBuffer::new(payload);
                    buf.skip(2)?; // data flags
                    buf.skip(1)?; // msg_type
                    let (error_code, error_msg, _) = ProtocolParser.parse_error_info(&mut buf)?;
                    if error_code != 0 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_else(|| format!("ORA-{:05}", error_code)),
                        });
                    }
                }
            }
            return Ok(());
        }

        Err(Error::Protocol(format!(
            "Unexpected packet type {} for function call",
            packet_type
        )))
    }

    /// Ensure the connection is ready for operations
    async fn ensure_ready(&self) -> Result<()> {
        if self.is_closed() {
            return Err(Error::ConnectionClosed);
        }

        let inner = self.inner.lock().await;
        if inner.state != ConnectionState::Ready {
            return Err(Error::ConnectionNotReady);
        }

        Ok(())
    }

    /// Enable or disable auto-commit mode for this connection.
    ///
    /// When auto-commit is enabled, every DML statement (INSERT, UPDATE, DELETE, MERGE)
    /// is automatically committed after execution. When disabled (default), you must
    /// call [`commit()`][Connection::commit] explicitly.
    ///
    /// This is equivalent to `Connection.setAutoCommit()` in JDBC.
    ///
    /// # Arguments
    /// * `enabled` - `true` to enable auto-commit, `false` to disable
    pub async fn set_auto_commit(&self, enabled: bool) -> Result<()> {
        self.ensure_ready().await?;
        let mut inner = self.inner.lock().await;
        inner.auto_commit = enabled;
        Ok(())
    }

    /// Get the current auto-commit mode for this connection.
    ///
    /// Returns `true` if auto-commit is enabled, `false` otherwise.
    /// Default is `false`.
    pub fn auto_commit(&self) -> bool {
        // Non-async lookup is fine since this is AtomicBool-like in intent
        // and the worst case is a stale read during a race with set_auto_commit
        if let Ok(inner) = self.inner.try_lock() {
            inner.auto_commit
        } else {
            // If lock is held (e.g. mid-execute), assume default
            false
        }
    }

    /// Set the transaction isolation level for subsequent transactions.
    ///
    /// Oracle supports three isolation levels:
    /// - `TransactionIsolation::ReadCommitted` — Default. Each statement sees data
    ///   committed at the start of that statement.
    /// - `TransactionIsolation::Serializable` — Each transaction sees a consistent
    ///   snapshot as of the transaction start.
    /// - `TransactionIsolation::ReadOnly` — Like serializable but disallows writes.
    ///
    /// This method calls `SET TRANSACTION ISOLATION LEVEL ...` (or `SET TRANSACTION READ ONLY`)
    /// as the first statement in the transaction. It must be called before any DML
    /// in the current transaction, as per Oracle semantics.
    ///
    /// This is equivalent to `Connection.setTransactionIsolation()` in JDBC.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rust_oracle::{Connection, TransactionIsolation};
    /// # async fn example(conn: Connection) -> rust_oracle::Result<()> {
    /// conn.set_transaction_isolation(TransactionIsolation::Serializable).await?;
    /// // Subsequent DML in this transaction uses serializable isolation
    /// conn.execute("INSERT INTO logs (msg) VALUES ('audit')", &[]).await?;
    /// conn.commit().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_transaction_isolation(&self, level: TransactionIsolation) -> Result<()> {
        self.ensure_ready().await?;
        // Execute SET TRANSACTION statement outside the main execute path
        // to avoid auto-commit interaction
        self.execute(level.to_sql(), &[]).await?;
        let mut inner = self.inner.lock().await;
        inner.transaction_isolation = level;
        Ok(())
    }

    /// Get the current transaction isolation level.
    ///
    /// Returns the last isolation level set via [`set_transaction_isolation()`][Connection::set_transaction_isolation].
    /// Note that this reflects the driver-side setting; after commit/rollback the server
    /// resets to `ReadCommitted`.
    pub fn transaction_isolation(&self) -> TransactionIsolation {
        if let Ok(inner) = self.inner.try_lock() {
            inner.transaction_isolation
        } else {
            TransactionIsolation::ReadCommitted
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Only close the server-side session when the LAST Connection handle
        // is dropped. Clones (e.g. in RowStream, ScrollableCursor) share the
        // same inner; dropping a clone must not kill the parent connection.
        if Arc::strong_count(&self.inner) > 1 {
            return; // Other handles still exist
        }

        if self.closed.swap(true, Ordering::Relaxed) {
            return; // Already closed
        }

        let inner = Arc::clone(&self.inner);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut inner = inner.lock().await;
                if inner.state == ConnectionState::Ready {
                    let _ = inner.send_logoff().await;
                }
                inner.state = ConnectionState::Closed;
                drop(inner.stream.take());
            });
        }
    }
}

// =============================================================================
// Helper functions for get_type()
// =============================================================================

/// Convert an Oracle type name from data dictionary to OracleType enum
fn oracle_type_from_name(type_name: &str) -> crate::constants::OracleType {
    use crate::constants::OracleType;

    match type_name.to_uppercase().as_str() {
        "NUMBER" => OracleType::Number,
        "INTEGER" | "INT" | "SMALLINT" => OracleType::Number,
        "FLOAT" | "REAL" | "DOUBLE PRECISION" => OracleType::BinaryDouble,
        "BINARY_FLOAT" => OracleType::BinaryFloat,
        "BINARY_DOUBLE" => OracleType::BinaryDouble,
        "VARCHAR2" | "VARCHAR" | "NVARCHAR2" => OracleType::Varchar,
        "CHAR" | "NCHAR" => OracleType::Char,
        "DATE" => OracleType::Date,
        "TIMESTAMP" => OracleType::Timestamp,
        "TIMESTAMP WITH TIME ZONE" => OracleType::TimestampTz,
        "TIMESTAMP WITH LOCAL TIME ZONE" => OracleType::TimestampLtz,
        "RAW" => OracleType::Raw,
        "BLOB" => OracleType::Blob,
        "CLOB" | "NCLOB" => OracleType::Clob,
        "BOOLEAN" | "PL/SQL BOOLEAN" => OracleType::Boolean,
        "ROWID" | "UROWID" => OracleType::Rowid,
        "XMLTYPE" => OracleType::Varchar, // Treat XMLType as string for now
        _ => OracleType::Varchar,         // Default to VARCHAR for unknown types
    }
}

#[test]
fn test_is_plsql_context() {
    // PL/SQL contexts
    assert!(Connection::is_plsql_context("BEGIN INSERT INTO t VALUES (:1); END;"));
    assert!(Connection::is_plsql_context("DECLARE v NUMBER; BEGIN NULL; END;"));
    assert!(Connection::is_plsql_context("begin null; end;"));
    assert!(Connection::is_plsql_context("  BEGIN ... END;"));
    assert!(Connection::is_plsql_context("\t\n  DeClArE x INT; BEGIN NULL; END;"));

    // SQL contexts (not PL/SQL)
    assert!(!Connection::is_plsql_context("SELECT * FROM dual"));
    assert!(!Connection::is_plsql_context("INSERT INTO t VALUES (1)"));
    assert!(!Connection::is_plsql_context("UPDATE t SET x = 1"));
    assert!(!Connection::is_plsql_context("DELETE FROM t"));
    assert!(!Connection::is_plsql_context("CREATE TABLE t (x NUMBER)"));
    assert!(!Connection::is_plsql_context(""));
    assert!(!Connection::is_plsql_context("  "));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::parser::decode_nchar_bytes;
    use crate::row::Value;

    #[test]
    fn test_query_options_default() {
        let opts = QueryOptions::default();
        assert_eq!(opts.prefetch_rows, 100);
        assert_eq!(opts.array_size, 100);
        assert!(!opts.auto_commit);
    }

    #[test]
    fn test_query_result_empty() {
        let result = QueryResult::empty();
        assert!(result.is_empty());
        assert_eq!(result.column_count(), 0);
        assert_eq!(result.row_count(), 0);
        assert!(result.first().is_none());
    }

    #[test]
    fn test_query_result_with_rows() {
        let columns = vec![ColumnInfo::new("ID", crate::constants::OracleType::Number)];
        let rows = vec![Row::new(vec![Value::Integer(1)])];

        let result = QueryResult {
            columns,
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 1,
        };

        assert!(!result.is_empty());
        assert_eq!(result.column_count(), 1);
        assert_eq!(result.row_count(), 1);
        assert!(result.first().is_some());
        assert!(result.column_by_name("ID").is_some());
        assert!(result.column_by_name("id").is_some()); // Case insensitive
        assert_eq!(result.column_index("ID"), Some(0));
    }

    #[test]
    fn test_server_info_default() {
        let info = ServerInfo::default();
        assert!(info.version.is_empty());
        assert_eq!(info.session_id, 0);
    }

    #[test]
    fn test_connection_state_transitions() {
        assert_eq!(ConnectionState::Disconnected, ConnectionState::Disconnected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Ready);
    }

    #[test]
    fn test_query_result_iterator() {
        let rows = vec![
            Row::new(vec![Value::Integer(1)]),
            Row::new(vec![Value::Integer(2)]),
        ];
        let result = QueryResult {
            columns: vec![],
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
        };

        let collected: Vec<_> = result.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_query_result_into_iterator() {
        let rows = vec![
            Row::new(vec![Value::Integer(1)]),
            Row::new(vec![Value::Integer(2)]),
        ];
        let result = QueryResult {
            columns: vec![],
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
        };

        let collected: Vec<Row> = result.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_decode_al16utf16_string() {
        let bytes = [
            0x5c, 0x0f, 0x5f, 0x20, 0x00, 0x20, 0x8c, 0xc7, 0x65, 0x99, 0x5e, 0xab,
        ];
        let decoded = decode_nchar_bytes(&bytes, crate::constants::charset::UTF16).unwrap();
        assert_eq!(decoded, "小张 資料庫");
    }

    #[test]
    fn test_decode_al16utf16_surrogate_pair() {
        let bytes = [0xd8, 0x3d, 0xde, 0x0a];
        let decoded = decode_nchar_bytes(&bytes, crate::constants::charset::UTF16).unwrap();
        assert_eq!(decoded, "😊");
    }
}
