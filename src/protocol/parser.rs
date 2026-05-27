//! Oracle TTC protocol response parser
//!
//! Pure parsing functions for Oracle's TTC (Two-Task Common)
//! protocol responses. Extracted from ConnectionInner to keep
//! the connection module focused on I/O and state management.

use bytes::Bytes;
use crate::batch::BatchResult;
use crate::buffer::ReadBuffer;
use crate::capabilities::Capabilities;
use crate::connection::{PlsqlResult, QueryResult};
use crate::constants::{BindDirection, MessageType, ccap_value};
use crate::error::{Error, Result};
use crate::implicit::{ImplicitResult, ImplicitResults};
use crate::row::{Row, Value};
use crate::statement::{BindParam, ColumnInfo};
use crate::types::{LobData, LobLocator, LobValue};

/// Protocol parser for Oracle TTC responses.
///
/// All methods are pure functions that take buffers and configuration
/// as parameters — they hold no mutable state.
pub(crate) struct ProtocolParser;

impl ProtocolParser {
    pub(crate) fn parse_batch_response(
        &self,
        payload: Bytes,
        batch_size: usize,
        want_row_counts: bool,
        ttc_field_version: u8,
    ) -> Result<BatchResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Batch response too short".to_string()));
        }

        let mut buf = ReadBuffer::new(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut rows_affected: u64 = 0;
        let mut row_counts: Option<Vec<u64>> = None;
        let mut end_of_response = false;

        // Process messages until end_of_response or out of data
        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Error (4) - may contain error or success info
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, _cid, row_count) =
                        self.parse_error_info_with_rowcount(&mut buf, ttc_field_version)?;
                    rows_affected = row_count;
                    if error_code != 0 && error_code != 1403 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                }

                // Parameter (8) - return parameters (may contain row counts)
                x if x == MessageType::Parameter as u8 => {
                    if let Some(counts) =
                        self.parse_return_parameters_internal(&mut buf, want_row_counts)?
                    {
                        row_counts = Some(counts);
                    }
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // BitVector (21)
                21 => {
                    let _num_columns_sent = buf.read_ub2()?;
                    if buf.remaining() > 0 {
                        let _byte = buf.read_u8()?;
                    }
                }

                // End of Response (29) - explicit end marker
                29 => {
                    end_of_response = true;
                }

                _ => {
                    // Unknown message type - continue processing
                }
            }
        }

        let mut result = BatchResult::new();
        result.total_rows_affected = rows_affected;
        result.success_count = batch_size;
        result.row_counts = row_counts;

        Ok(result)
    }

    /// Parse fetch response to extract additional rows
    ///
    /// REF CURSOR fetch responses contain a series of messages:
    /// - RowHeader (6): Contains metadata about the following row data
    /// - RowData (7): Contains the actual row values
    /// - Error (4): Contains error info with cursor_id and row counts
    pub(crate) fn parse_fetch_response(
        &self,
        payload: Bytes,
        columns: &[ColumnInfo],
        caps: &Capabilities,
    ) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Fetch response too short".to_string()));
        }

        let mut buf = ReadBuffer::new(payload);
        let mut rows = Vec::new();
        let mut has_more_rows = false;

        // Bit vector for duplicate column optimization
        let mut bit_vector: Option<Vec<u8>> = None;
        let mut previous_row_values: Option<Vec<Value>> = None;

        // Skip data flags
        buf.skip(2)?;

        // Process multiple messages in the response
        while buf.remaining() >= 1 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::RowHeader as u8 => {
                    // Skip row header metadata (per Python's _process_row_header)
                    buf.skip(1)?; // flags
                    buf.skip_ub2()?; // num requests
                    buf.skip_ub4()?; // iteration number
                    buf.skip_ub4()?; // num iters
                    buf.skip_ub2()?; // buffer length
                    let num_bytes = buf.read_ub4()? as usize;
                    if num_bytes > 0 {
                        buf.skip(1)?; // skip repeated length
                                      // This bit vector in row header is for the following row data
                        let bv = buf.read_bytes_vec(num_bytes - 1)?;
                        bit_vector = Some(bv);
                    }
                    let rxhrid_flag = buf.read_u8()?;
                    if rxhrid_flag > 0 {
                        buf.skip_raw_bytes_chunked()?;
                    }
                }
                x if x == MessageType::RowData as u8 => {
                    // Parse actual row data with bit vector support
                    let row = self.parse_row_data_with_bitvector(
                        &mut buf,
                        columns,
                        caps,
                        bit_vector.as_deref(),
                        previous_row_values.as_ref(),
                    )?;
                    let had_bit_vector = bit_vector.is_some();
                    bit_vector = None;
                    if had_bit_vector {
                        previous_row_values = Some(row.values().to_vec());
                    } else {
                        previous_row_values = None;
                    }
                    rows.push(row);
                }
                x if x == MessageType::BitVector as u8 => {
                    // BitVector indicates which columns have actual data vs duplicates
                    let _num_columns_sent = buf.read_ub2()?;
                    let num_bytes = (columns.len() + 7) / 8; // Round up
                    if num_bytes > 0 {
                        let bv = buf.read_bytes_vec(num_bytes)?;
                        bit_vector = Some(bv);
                    }
                    // Continue processing - RowData follows
                }
                x if x == MessageType::Error as u8 => {
                    // Error message contains row count and cursor info
                    let (error_code, error_msg, more_rows) =
                        self.parse_error_message_info(&mut buf)?;
                    has_more_rows = more_rows;
                    if error_code != 0 && error_code != 1403 {
                        // 1403 = no data found
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg,
                        });
                    }
                    break; // Error message marks end of response
                }
                x if x == MessageType::Status as u8 => {
                    // Status message - usually marks end
                    break;
                }
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }
                _ => {
                    // Unknown message type - stop processing
                    break;
                }
            }
        }

        Ok(QueryResult {
            columns: columns.to_vec(),
            rows,
            rows_affected: 0,
            has_more_rows,
            cursor_id: 0,
        })
    }

    /// Parse error message info including cursor_id and row counts
    pub(crate) fn parse_error_message_info(&self, buf: &mut ReadBuffer) -> Result<(u32, String, bool)> {
        let _call_status = buf.read_ub4()?; // end of call status
        buf.skip_ub2()?; // end to end seq#
        buf.skip_ub4()?; // current row number
        buf.skip_ub2()?; // error number
        buf.skip_ub2()?; // array elem error
        buf.skip_ub2()?; // array elem error
        let _cursor_id = buf.read_ub2()?; // cursor id
        let _error_pos = buf.read_sb2()?; // error position
        buf.skip(1)?; // sql type
        buf.skip(1)?; // fatal?
        buf.skip(1)?; // flags
        buf.skip(1)?; // user cursor options
        buf.skip(1)?; // UPI parameter
        let flags = buf.read_u8()?; // flags
                                    // Skip rowid - fixed 10 bytes in Oracle format
        buf.skip(10)?; // rowid is 10 bytes
        buf.skip_ub4()?; // OS error
        buf.skip(1)?; // statement number
        buf.skip(1)?; // call number
        buf.skip_ub2()?; // padding
        buf.skip_ub4()?; // success iters
        let num_bytes = buf.read_ub4()?; // oerrdd
        if num_bytes > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip batch error codes
        let num_errors = buf.read_ub2()?;
        if num_errors > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip batch error offsets
        let num_offsets = buf.read_ub4()?;
        if num_offsets > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip batch error messages
        let temp16 = buf.read_ub2()?;
        if temp16 > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Read extended error info
        let error_num = buf.read_ub4()?;
        let row_count = buf.read_ub8()?;
        let more_rows = row_count > 0 || (flags & 0x20) != 0;

        // Read error message if present
        let error_msg = if error_num != 0 {
            buf.read_string_with_length()?.unwrap_or_default()
        } else {
            String::new()
        };

        Ok((error_num, error_msg, more_rows))
    }

    pub(crate) fn parse_query_response(&self, payload: Bytes, caps: &Capabilities) -> Result<QueryResult> {
        self.parse_query_response_with_columns(payload, caps, &[])
    }

    /// Parse query response with pre-known columns (for re-execute after define)
    pub(crate) fn parse_query_response_with_columns(
        &self,
        payload: Bytes,
        caps: &Capabilities,
        known_columns: &[ColumnInfo],
    ) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Query response too short".to_string()));
        }

        let mut buf = ReadBuffer::new(payload);

        // Skip data flags
        buf.skip(2)?;

        // Use known columns if provided, otherwise parse from describe info
        let mut columns: Vec<ColumnInfo> = known_columns.to_vec();
        let mut rows: Vec<Row> = Vec::new();
        let mut cursor_id: u16 = 0;
        let mut row_count: u64 = 0;
        let mut end_of_response = false;

        // Bit vector for duplicate column optimization
        // When Some, indicates which columns have actual data (bit=1) vs duplicates (bit=0)
        let mut bit_vector: Option<Vec<u8>> = None;
        // Previous row values for copying duplicates
        let mut previous_row_values: Option<Vec<Value>> = None;

        // Process messages until we hit end of response or run out of data
        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // DescribeInfo (16) - column metadata
                x if x == MessageType::DescribeInfo as u8 => {
                    // Skip chunked bytes first
                    buf.skip_raw_bytes_chunked()?;
                    columns = self.parse_describe_info(&mut buf, caps.ttc_field_version)?;
                }

                // RowHeader (6) - header info for rows
                x if x == MessageType::RowHeader as u8 => {
                    if let Some(bv) = self.parse_row_header(&mut buf)? {
                        bit_vector = Some(bv);
                    }
                }

                // RowData (7) - actual row values
                x if x == MessageType::RowData as u8 => {
                    let row = self.parse_row_data_with_bitvector(
                        &mut buf,
                        &columns,
                        caps,
                        bit_vector.as_deref(),
                        previous_row_values.as_ref(),
                    )?;
                    let had_bit_vector = bit_vector.is_some();
                    bit_vector = None;
                    if had_bit_vector {
                        previous_row_values = Some(row.values().to_vec());
                    } else {
                        previous_row_values = None;
                    }
                    rows.push(row);
                }

                // Error (4) - completion or error
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, cid, rc) =
                        self.parse_error_info_with_rowcount(&mut buf, caps.ttc_field_version)?;
                    row_count = rc;
                    if error_code != 0 && error_code != 1403 {
                        // 1403 is "no data found" which is not an error for queries
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    // Oracle 10g may return cursor_id > 0 even on error 1403
                    // ("no data found"), which means the cursor is truly exhausted.
                    // Zero it out so callers don't attempt another fetch_more.
                    cursor_id = if error_code == 1403 { 0 } else { cid };
                    end_of_response = true;
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    // Read call status and end-to-end seq number
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                    // Note: end_of_response only if supports_end_of_response is false
                    // For now, we assume it's not the end
                }

                x if x == MessageType::EndOfResponse as u8 => {
                    end_of_response = true;
                }

                // BitVector (21) - column presence bitmap for sparse results
                // Bit=1 means actual data is sent, bit=0 means duplicate from previous row
                21 => {
                    // Read num columns sent
                    let _num_columns_sent = buf.read_ub2()?;
                    // Read bit vector (1 byte per 8 columns, rounded up)
                    let num_bytes = (columns.len() + 7) / 8;
                    if num_bytes > 0 {
                        let bv = buf.read_bytes_vec(num_bytes)?;
                        bit_vector = Some(bv);
                    }
                }

                _ => {
                    // Unknown message type - break to avoid parsing errors
                    break;
                }
            }
        }

        // Accept partial response as complete if only a few stray bytes remain.
        // Oracle cursor re-fetch responses may end with an abbreviated error
        // message or padding instead of a full Error/EndOfResponse message.
        if !end_of_response && buf.remaining() <= 8 {
            end_of_response = true;
        }

        if !end_of_response {
            return Err(Error::BufferUnderflow {
                needed: 1,
                available: 0,
            });
        }

        Ok(QueryResult {
            columns,
            rows,
            rows_affected: row_count,
            has_more_rows: false,
            cursor_id,
        })
    }

    /// Parse a PL/SQL response containing OUT parameter values
    ///
    /// PL/SQL responses may contain:
    /// - IoVector (11): bind directions for each parameter
    /// - RowData (7): OUT parameter values
    /// - FlushOutBinds (19): signals end of OUT bind data
    /// - Error (4): completion status
    pub(crate) fn parse_plsql_response(
        &self,
        payload: Bytes,
        caps: &Capabilities,
        params: &[BindParam],
    ) -> Result<PlsqlResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("PL/SQL response too short".to_string()));
        }

        let mut buf = ReadBuffer::new(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut out_values: Vec<Value> = Vec::new();
        let mut _out_indices: Vec<usize> = Vec::new();
        let mut row_count: u64 = 0;
        let mut cursor_id: Option<u16> = None;
        let mut end_of_response = false;
        let mut implicit_results = ImplicitResults::new();

        // Create column infos for OUT params based on their oracle types
        let mut out_columns: Vec<ColumnInfo> = Vec::new();

        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // IoVector (11) - bind directions from server
                x if x == MessageType::IoVector as u8 => {
                    let (indices, cols) = self.parse_io_vector(&mut buf, params)?;
                    _out_indices = indices;
                    out_columns = cols;
                }

                // RowHeader (6)
                x if x == MessageType::RowHeader as u8 => {
                    self.parse_row_header(&mut buf)?;
                }

                // RowData (7) - OUT parameter values
                x if x == MessageType::RowData as u8 => {
                    if !out_columns.is_empty() {
                        let row = self.parse_row_data_single(&mut buf, &out_columns, caps)?;
                        // Extract values from the row into out_values
                        for (idx, value) in row.into_values().into_iter().enumerate() {
                            // Check if this is a cursor
                            if let Value::Cursor(cursor) = &value {
                                if cursor_id.is_none() && cursor.cursor_id() != 0 {
                                    cursor_id = Some(cursor.cursor_id());
                                }
                            }
                            // Map back to original param position if we have indices
                            if idx < out_values.len() {
                                out_values[idx] = value;
                            } else {
                                out_values.push(value);
                            }
                        }
                    } else {
                        // Skip the row data if we don't have column info
                        // This shouldn't normally happen
                        break;
                    }
                }

                // DescribeInfo (16) - for REF CURSOR describe
                x if x == MessageType::DescribeInfo as u8 => {
                    buf.skip_raw_bytes_chunked()?;
                    let cursor_columns =
                        self.parse_describe_info(&mut buf, caps.ttc_field_version)?;
                    // Store cursor columns if needed
                    let _ = cursor_columns; // For now, just skip
                }

                // FlushOutBinds (19) - signals end of OUT bind data
                x if x == MessageType::FlushOutBinds as u8 => {
                    // This indicates that OUT bind data is done
                    // Just continue to get the error/completion status
                }

                // Error (4) - completion or error
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, _cid, rc) =
                        self.parse_error_info_with_rowcount(&mut buf, caps.ttc_field_version)?;
                    row_count = rc;
                    if error_code != 0 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    end_of_response = true;
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }

                // Status (9)
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // ImplicitResultset (27) - result sets from DBMS_SQL.RETURN_RESULT
                x if x == MessageType::ImplicitResultset as u8 => {
                    let parsed_results = self.parse_implicit_results(&mut buf, caps)?;
                    implicit_results = parsed_results;
                }

                _ => {
                    // Unknown message type - break to avoid parsing errors
                    break;
                }
            }
        }

        // If no IoVector was received, all params might be IN-only
        // In that case, out_values should be empty
        Ok(PlsqlResult {
            out_values,
            rows_affected: row_count,
            cursor_id,
            implicit_results,
        })
    }

    /// Parse implicit result sets from DBMS_SQL.RETURN_RESULT
    ///
    /// Format per Python base.pyx _process_implicit_result:
    /// - num_results: ub4 (number of implicit result sets)
    /// - For each result:
    ///   - num_bytes: ub1 + raw bytes (metadata to skip)
    ///   - describe_info: column metadata
    ///   - cursor_id: ub2
    pub(crate) fn parse_implicit_results(
        &self,
        buf: &mut ReadBuffer,
        caps: &Capabilities,
    ) -> Result<ImplicitResults> {
        let num_results = buf.read_ub4()?;
        let mut results = ImplicitResults::new();

        for _ in 0..num_results {
            // Skip metadata bytes
            let num_bytes = buf.read_u8()?;
            if num_bytes > 0 {
                buf.skip(num_bytes as usize)?;
            }

            // Parse column metadata for this result set
            let columns = self.parse_describe_info(buf, caps.ttc_field_version)?;

            // Read cursor ID
            let cursor_id = buf.read_ub2()?;

            // Create implicit result with metadata but no rows yet
            // Rows will be fetched separately using fetch_implicit_result
            let result = ImplicitResult::new(cursor_id, columns, Vec::new());
            results.add(result);
        }

        Ok(results)
    }

    /// Parse IO Vector message to get bind directions
    ///
    /// Returns a tuple of:
    /// - indices of OUT/INOUT parameters in the params list
    /// - column infos for parsing OUT values
    pub(crate) fn parse_io_vector(
        &self,
        buf: &mut ReadBuffer,
        params: &[BindParam],
    ) -> Result<(Vec<usize>, Vec<ColumnInfo>)> {
        // I/O vector format (from Python reference):
        // - skip 1 byte (flag)
        // - read ub2 (num requests)
        // - read ub4 (num iters)
        // - num_binds = num_iters * 256 + num_requests
        // - skip ub4 (num iters this time)
        // - skip ub2 (uac buffer length)
        // - read ub2 (num_bytes for bit vector), skip if > 0
        // - read ub2 (num_bytes for rowid), skip if > 0
        // - for each bind: read ub1 (bind_dir)

        buf.skip(1)?; // flag
        let num_requests = buf.read_ub2()? as u32;
        let num_iters = buf.read_ub4()?;
        let num_binds = num_iters * 256 + num_requests;
        let _ = buf.read_ub4()?; // num iters this time (discard)
        let _ = buf.read_ub2()?; // uac buffer length (discard)

        // Bit vector
        let num_bytes = buf.read_ub2()? as usize;
        if num_bytes > 0 {
            buf.skip(num_bytes)?;
        }

        // Rowid (raw bytes, not length-prefixed here)
        let num_bytes = buf.read_ub4()? as usize;
        if num_bytes > 0 {
            buf.skip_raw_bytes_chunked()?; // Skip rowid bytes using chunked read
        }

        // Read bind directions
        let mut out_indices = Vec::new();
        let mut out_columns = Vec::new();

        for i in 0..(num_binds as usize).min(params.len()) {
            let dir_byte = buf.read_u8()?;
            let dir = BindDirection::try_from(dir_byte).unwrap_or(BindDirection::Input);

            // If this is not an INPUT-only parameter, it has OUT data
            if dir != BindDirection::Input {
                out_indices.push(i);

                // Create a column info for parsing the OUT value
                let param = &params[i];
                let mut col = ColumnInfo::new(format!("OUT_{}", i), param.oracle_type);
                col.buffer_size = param.buffer_size;
                col.data_size = param.buffer_size;
                col.nullable = true;

                // For collection OUT params, extract element type from the placeholder
                if let Some(Value::Collection(ref placeholder)) = param.value {
                    if let Some(Value::Integer(elem_type_code)) = placeholder.get("_element_type") {
                        col.element_type =
                            crate::constants::OracleType::try_from(*elem_type_code as u8).ok();
                    }
                }

                out_columns.push(col);
            }
        }

        Ok((out_indices, out_columns))
    }

    /// Parse row header (TNS_MSG_TYPE_ROW_HEADER = 6)
    pub(crate) fn parse_row_header(&self, buf: &mut ReadBuffer) -> Result<Option<Vec<u8>>> {
        buf.skip_ub1()?; // flags
        buf.skip_ub2()?; // num requests
        buf.skip_ub4()?; // iteration number
        buf.skip_ub4()?; // num iters
        buf.skip_ub2()?; // buffer length
        let num_bytes = buf.read_ub4()? as usize;
        let bit_vector = if num_bytes > 0 {
            buf.skip_ub1()?; // skip repeated length
            Some(buf.read_bytes_vec(num_bytes - 1)?)
        } else {
            None
        };
        let rxhrid_flag = buf.read_u8()?;
        if rxhrid_flag > 0 {
            buf.skip_raw_bytes_chunked()?; // rxhrid
        }
        Ok(bit_vector)
    }

    /// Parse return parameters (TNS_MSG_TYPE_PARAMETER = 8)
    pub(crate) fn parse_return_parameters(&self, buf: &mut ReadBuffer) -> Result<()> {
        self.parse_return_parameters_internal(buf, false)
            .map(|_| ())
    }

    /// Parse return parameters with optional row counts extraction
    /// When `want_row_counts` is true, attempts to read arraydmlrowcounts from the response.
    pub(crate) fn parse_return_parameters_internal(
        &self,
        buf: &mut ReadBuffer,
        want_row_counts: bool,
    ) -> Result<Option<Vec<u64>>> {
        // Per Python's _process_return_parameters
        let num_params = buf.read_ub2()?; // al8o4l (ignored)
        for _ in 0..num_params {
            buf.skip_ub4()?;
        }

        let al8txl = buf.read_ub2()?; // al8txl (ignored)
        if al8txl > 0 {
            buf.skip(al8txl as usize)?;
        }

        // key/value pairs
        let num_pairs = buf.read_ub2()?;
        for _ in 0..num_pairs {
            let text_len = buf.read_ub4()?;
            if text_len > 0 {
                buf.skip_raw_bytes_chunked()?;
            }
            let bin_len = buf.read_ub4()?;
            if bin_len > 0 {
                buf.skip_raw_bytes_chunked()?;
            }
            buf.skip_ub4()?;
        }

        // queryID / registration
        let num_bytes = buf.read_ub4()? as usize;
        if num_bytes > 0 {
            buf.skip(num_bytes)?;
        }

        // If arraydmlrowcounts was requested, parse the row counts
        if want_row_counts && buf.remaining() >= 4 {
            let num_rows = buf.read_ub4()? as usize;
            let mut row_counts = Vec::with_capacity(num_rows);
            for _ in 0..num_rows {
                let count = buf.read_ub8()?;
                row_counts.push(count);
            }
            Ok(Some(row_counts))
        } else {
            Ok(None)
        }
    }

    /// Parse a single row of data
    pub(crate) fn parse_row_data_single(
        &self,
        buf: &mut ReadBuffer,
        columns: &[ColumnInfo],
        caps: &Capabilities,
    ) -> Result<Row> {
        let mut values = Vec::with_capacity(columns.len());

        for col in columns {
            let value = self.parse_column_value(buf, col, caps)?;
            values.push(value);
        }

        Ok(Row::new(values))
    }

    /// Parse a single row of data with bit vector support for duplicate column optimization
    ///
    /// Oracle sends a BitVector message before RowData when some columns have the same
    /// value as the previous row. Bits that are SET (1) indicate data is sent in the buffer;
    /// bits that are CLEAR (0) indicate the value should be copied from the previous row.
    pub(crate) fn parse_row_data_with_bitvector(
        &self,
        buf: &mut ReadBuffer,
        columns: &[ColumnInfo],
        caps: &Capabilities,
        bit_vector: Option<&[u8]>,
        previous_values: Option<&Vec<Value>>,
    ) -> Result<Row> {
        let mut values = Vec::with_capacity(columns.len());

        for (col_idx, col) in columns.iter().enumerate() {
            // Check if this column is a duplicate (bit=0 means duplicate)
            let is_duplicate = if let Some(bv) = bit_vector {
                let byte_num = col_idx / 8;
                let bit_num = col_idx % 8;
                if byte_num < bv.len() {
                    // If bit is 0, it's a duplicate
                    (bv[byte_num] & (1 << bit_num)) == 0
                } else {
                    false
                }
            } else {
                false
            };

            if is_duplicate {
                // Copy value from previous row
                if let Some(prev) = previous_values {
                    if col_idx < prev.len() {
                        values.push(prev[col_idx].clone());
                    } else {
                        // Shouldn't happen, but fallback to null
                        values.push(Value::Null);
                    }
                } else {
                    // No previous row (shouldn't happen for duplicate), fallback to null
                    values.push(Value::Null);
                }
            } else {
                // Read actual value from buffer
                let value = self.parse_column_value(buf, col, caps)?;
                values.push(value);
            }
        }

        Ok(Row::new(values))
    }

    /// Parse a single column value from the buffer
    pub(crate) fn parse_column_value(
        &self,
        buf: &mut ReadBuffer,
        col: &ColumnInfo,
        caps: &Capabilities,
    ) -> Result<Value> {
        use crate::constants::{csfrm, OracleType};

        // Handle LOB columns specially - they have a different format
        if col.is_lob() {
            // 10g (ttc_fv <= 5) does not support LOB prefetch.
            // Without prefetch, the locator is returned as raw length-prefixed bytes
            // instead of the {UB4 count, UB8 size, UB4 chunk, locator} prefetch format.
            if caps.ttc_field_version <= ccap_value::FIELD_VERSION_10_2 {
                let data = buf.read_bytes_with_length()?;
                return match data {
                    None => Ok(Value::Lob(LobValue::Null)),
                    Some(bytes) if bytes.is_empty() => Ok(Value::Lob(LobValue::Empty)),
                    Some(bytes) => {
                        let locator = LobLocator::new(
                            bytes::Bytes::from(bytes),
                            0, // unknown size (can be fetched via LOB ops)
                            0, // unknown chunk_size
                            col.oracle_type,
                            col.csfrm,
                        );
                        Ok(Value::Lob(LobValue::locator(locator)))
                    }
                };
            }
            return self.parse_lob_value(buf, col);
        }

        // Handle CURSOR type - REF CURSOR from PL/SQL
        if col.oracle_type == OracleType::Cursor {
            return self.parse_cursor_value(buf, caps);
        }

        // Handle Object type - collections (VARRAY, Nested Table) and UDTs
        if col.oracle_type == OracleType::Object {
            return self.parse_object_value(buf, col);
        }

        // Read the value based on the column type
        // First, check if it's NULL
        let data = buf.read_bytes_with_length()?;

        match data {
            None => Ok(Value::Null),
            Some(bytes) if bytes.is_empty() => Ok(Value::Null),
            Some(bytes) => {
                // Decode based on oracle type
                match col.oracle_type {
                    OracleType::Number => {
                        // Fast path: try direct i64/f64 decode, skip String alloc
                        if let Some((val, is_int)) =
                            crate::types::try_decode_number_fast(&bytes)
                        {
                            if is_int && val >= (i64::MIN as f64) && val <= (i64::MAX as f64) {
                                Ok(Value::Integer(val as i64))
                            } else {
                                Ok(Value::Float(val))
                            }
                        } else {
                            let num = crate::types::decode_oracle_number(&bytes)?;
                            Ok(Value::String(num.value))
                        }
                    }
                    OracleType::Varchar | OracleType::Char | OracleType::Long => {
                        let s = if col.csfrm == csfrm::NCHAR {
                            decode_nchar_bytes(&bytes, caps.ncharset_id)?
                        } else {
                            // Fast path: from_utf8 reuses Vec alloc for valid UTF-8
                            String::from_utf8(bytes)
                                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
                        };
                        Ok(Value::String(s))
                    }
                    OracleType::Raw | OracleType::LongRaw => {
                        // bytes is already Vec<u8>, no need for to_vec()
                        Ok(Value::Bytes(bytes))
                    }
                    OracleType::Date => {
                        // Oracle DATE format - 7 bytes
                        let date = crate::types::decode_oracle_date(&bytes)?;
                        Ok(Value::Date(date))
                    }
                    OracleType::Timestamp | OracleType::TimestampLtz => {
                        // Oracle TIMESTAMP format - 11 bytes (date + fractional seconds)
                        let ts = crate::types::decode_oracle_timestamp(&bytes)?;
                        Ok(Value::Timestamp(ts))
                    }
                    OracleType::TimestampTz => {
                        // Oracle TIMESTAMP WITH TIME ZONE - 13 bytes
                        let ts = crate::types::decode_oracle_timestamp(&bytes)?;
                        Ok(Value::Timestamp(ts))
                    }
                    OracleType::IntervalYm => {
                        let interval = crate::types::decode_interval_ym(&bytes)?;
                        Ok(Value::IntervalYm(interval))
                    }
                    OracleType::IntervalDs => {
                        let interval = crate::types::decode_interval_ds(&bytes)?;
                        Ok(Value::IntervalDs(interval))
                    }
                    _ => {
                        // Default: try fast UTF-8 decode first
                        let s = if col.csfrm == csfrm::NCHAR {
                            decode_nchar_bytes(&bytes, caps.ncharset_id)?
                        } else {
                            String::from_utf8(bytes)
                                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
                        };
                        Ok(Value::String(s))
                    }
                }
            }
        }
    }

    /// Parse a REF CURSOR value from the buffer
    ///
    /// Per Python base.pyx lines 1038-1046:
    /// - Skip 1 byte (length indicator - fixed value)
    /// - Read describe info (column metadata for the cursor)
    /// - Read cursor_id (UB2)
    pub(crate) fn parse_cursor_value(&self, buf: &mut ReadBuffer, caps: &Capabilities) -> Result<Value> {
        use crate::types::RefCursor;

        // Skip length indicator (fixed value for cursors)
        let _length = buf.read_u8()?;

        // Read column metadata for this cursor
        let cursor_columns = self.parse_describe_info(buf, caps.ttc_field_version)?;

        // Read the cursor ID
        let cursor_id = buf.read_ub2()?;

        // Create RefCursor with the metadata
        let ref_cursor = RefCursor::new(cursor_id, cursor_columns);

        Ok(Value::Cursor(ref_cursor))
    }

    /// Parse an Object/Collection value from the buffer
    ///
    /// Object format from Oracle (per Python packet.pyx read_dbobject):
    /// - UB4: type OID length, then type OID bytes if > 0
    /// - UB4: OID length, then OID bytes if > 0
    /// - UB4: snapshot length, then snapshot bytes if > 0 (discarded)
    /// - UB2: version (skip)
    /// - UB4: packed data length
    /// - UB2: flags (skip)
    /// - Bytes: packed data (pickle format)
    pub(crate) fn parse_object_value(&self, buf: &mut ReadBuffer, col: &ColumnInfo) -> Result<Value> {
        use crate::dbobject::{CollectionType, DbObject, DbObjectType};
        use crate::types::decode_collection;

        // Read type OID
        let toid_len = buf.read_ub4()?;
        let _toid = if toid_len > 0 {
            Some(buf.read_bytes_vec(toid_len as usize)?)
        } else {
            None
        };

        // Read OID
        let oid_len = buf.read_ub4()?;
        let _oid = if oid_len > 0 {
            Some(buf.read_bytes_vec(oid_len as usize)?)
        } else {
            None
        };

        // Read and discard snapshot
        let snapshot_len = buf.read_ub4()?;
        if snapshot_len > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip version (length-prefixed UB2)
        let _version = buf.read_ub2()?;

        // Read packed data length
        let data_len = buf.read_ub4()?;

        // Skip flags (length-prefixed UB2)
        let _flags = buf.read_ub2()?;

        if data_len == 0 {
            return Ok(Value::Null);
        }

        // Read packed data (chunked format like other byte sequences)
        let packed_data = buf.read_bytes_with_length()?;

        match packed_data {
            None => Ok(Value::Null),
            Some(data) if data.is_empty() => Ok(Value::Null),
            Some(data) => {
                // Create a placeholder type based on column info
                let type_name = col
                    .type_name
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                // Try to determine if this is a collection based on the pickle data
                // The first byte contains flags - check for IS_COLLECTION (0x08)
                let is_collection = !data.is_empty() && (data[0] & 0x08) != 0;

                if is_collection {
                    // Get element type from column info or default to VARCHAR
                    let element_type = col
                        .element_type
                        .unwrap_or(crate::constants::OracleType::Varchar);

                    // Determine collection type from pickle flags
                    // Collection flags are after header - but we'll default for now
                    let collection_type = CollectionType::Varray;

                    let obj_type = DbObjectType::collection(
                        &col.type_schema.clone().unwrap_or_default(),
                        &type_name,
                        collection_type,
                        element_type,
                    );

                    match decode_collection(&obj_type, &data) {
                        Ok(collection) => Ok(Value::Collection(collection)),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to decode collection: {}, data: {:02x?}",
                                e,
                                &data[..std::cmp::min(20, data.len())]
                            );
                            // Return raw bytes as fallback
                            Ok(Value::Bytes(data))
                        }
                    }
                } else {
                    // Regular object type - not yet fully implemented
                    let mut obj = DbObject::new(&type_name);
                    // Store raw pickle data for later inspection
                    obj.set("_raw_data", Value::Bytes(data));
                    Ok(Value::Collection(obj))
                }
            }
        }
    }

    /// Parse a LOB column value from the buffer
    ///
    /// LOB format from Oracle (per Python's read_lob_with_length):
    /// - UB4: num_bytes (indicator that LOB data follows)
    /// - If num_bytes > 0:
    ///   - For non-BFILE: UB8 size, UB4 chunk_size
    ///   - Bytes: LOB locator (chunked format)
    ///
    /// The actual LOB content must be fetched separately using LOB operations.
    /// For JSON columns, the data is OSON-encoded and decoded directly.
    /// For VECTOR columns, the data is decoded from Oracle's vector binary format.
    pub(crate) fn parse_lob_value(&self, buf: &mut ReadBuffer, col: &ColumnInfo) -> Result<Value> {
        use crate::constants::OracleType;
        use crate::types::{decode_vector, OsonDecoder};

        // Read length indicator
        let num_bytes = buf.read_ub4()?;

        if num_bytes == 0 {
            // For JSON, null is Value::Json(serde_json::Value::Null)
            if col.oracle_type == OracleType::Json || col.is_json {
                return Ok(Value::Json(serde_json::Value::Null));
            }
            // For VECTOR, null is Value::Null
            if col.oracle_type == OracleType::Vector {
                return Ok(Value::Null);
            }
            return Ok(Value::Lob(LobValue::Null));
        }

        // For BFILE, there's no size/chunk_size metadata
        let (size, chunk_size) = if col.oracle_type == OracleType::Bfile {
            (0u64, 0u32)
        } else {
            // Read LOB size and chunk size
            let size = buf.read_ub8()?;
            let chunk_size = buf.read_ub4()?;
            (size, chunk_size)
        };

        // Read LOB data (could be locator or inline data depending on size)
        let data_bytes = buf.read_bytes_with_length()?;

        // Handle JSON columns - decode OSON format
        // JSON is sent as a LOB with prefetched data + a LOB locator that must be consumed
        if col.oracle_type == OracleType::Json || col.is_json {
            // Read and discard the LOB locator
            let _locator = buf.read_bytes_with_length()?;

            if let Some(data) = data_bytes {
                if !data.is_empty() {
                    // Decode OSON to JSON
                    match OsonDecoder::decode(bytes::Bytes::from(data)) {
                        Ok(json_value) => return Ok(Value::Json(json_value)),
                        Err(e) => {
                            tracing::warn!("Failed to decode OSON: {}", e);
                            return Ok(Value::Json(serde_json::Value::Null));
                        }
                    }
                }
            }
            return Ok(Value::Json(serde_json::Value::Null));
        }

        // Handle VECTOR columns - decode vector binary format
        if col.oracle_type == OracleType::Vector {
            // Read and discard LOB locator (not needed for VECTOR)
            let _locator = buf.read_bytes_with_length()?;

            if let Some(data) = data_bytes {
                if !data.is_empty() {
                    match decode_vector(&data) {
                        Ok(vector) => return Ok(Value::Vector(vector)),
                        Err(e) => {
                            tracing::warn!("Failed to decode VECTOR: {}", e);
                            return Ok(Value::Null);
                        }
                    }
                }
            }
            return Ok(Value::Null);
        }

        // Create a LOB locator for fetching the data later
        if let Some(locator_data) = data_bytes {
            if !locator_data.is_empty() {
                let locator = LobLocator::new(
                    bytes::Bytes::from(locator_data),
                    size,
                    chunk_size,
                    col.oracle_type,
                    col.csfrm,
                );
                return Ok(Value::Lob(LobValue::locator(locator)));
            }
        }

        // If we have size but no locator, it might be an empty LOB
        if size == 0 {
            return Ok(Value::Lob(LobValue::Empty));
        }

        // Empty LOB (shouldn't normally reach here)
        Ok(Value::Lob(LobValue::Empty))
    }

    /// Parse error info message and extract cursor_id
    /// Format per Python's _process_error_info in base.pyx
    pub(crate) fn parse_error_info(&self, buf: &mut ReadBuffer) -> Result<(u32, Option<String>, u16)> {
        // Delegate to the version-aware parser, using a safe default (oldest supported)
        // This function is called from contexts where capabilities aren't available,
        // so we use FIELD_VERSION_11_2 to ensure the most compatible parsing.
        let (code, msg, cid, _row_count) = self.parse_error_info_with_rowcount(
            buf,
            ccap_value::FIELD_VERSION_11_2,
        )?;
        Ok((code, msg, cid))
    }

    /// Parse error response packet (received after marker reset)
    pub(crate) fn parse_error_response(&self, payload: Bytes) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Error response too short".to_string()));
        }

        let mut buf = ReadBuffer::new(payload);

        // Skip data flags
        buf.skip(2)?;

        // Read message type
        let msg_type = buf.read_u8()?;

        // Check for error message type (4)
        if msg_type == MessageType::Error as u8 {
            let (error_code, error_msg, _cursor_id) = self.parse_error_info(&mut buf)?;

            return Err(Error::OracleError {
                code: error_code,
                message: error_msg.unwrap_or_else(|| format!("ORA-{:05}", error_code)),
            });
        }

        // If not an error message type, return generic error
        Err(Error::Protocol(format!(
            "Expected error message type 4, got {}",
            msg_type
        )))
    }

    /// Parse DML response to extract rows affected
    pub(crate) fn parse_dml_response(&self, payload: Bytes, ttc_field_version: u8) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("DML response too short".to_string()));
        }

        let mut buf = ReadBuffer::new(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut rows_affected: u64 = 0;
        let mut cursor_id: u16 = 0;
        let mut end_of_response = false;

        // Process messages until end_of_response or out of data
        // Note: If supports_end_of_response is true, we must continue until msg type 29
        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Error (4) - may contain error or success info
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, cid, row_count) =
                        self.parse_error_info_with_rowcount(&mut buf, ttc_field_version)?;
                    cursor_id = cid;
                    rows_affected = row_count;
                    if error_code != 0 && error_code != 1403 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    // Only end if server doesn't support end_of_response
                    // Otherwise, continue until we get msg type 29
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // BitVector (21)
                21 => {
                    let _num_columns_sent = buf.read_ub2()?;
                    // No columns for DML, but read the byte if present
                    if buf.remaining() > 0 {
                        let _byte = buf.read_u8()?;
                    }
                }

                // End of Response (29) - explicit end marker
                29 => {
                    end_of_response = true;
                }

                _ => {
                    // Unknown message type - continue processing
                }
            }
        }

        Ok(QueryResult {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_affected,
            has_more_rows: false,
            cursor_id,
        })
    }

    /// Parse error info and return (error_code, error_msg, cursor_id, row_count)
    pub(crate) fn parse_error_info_with_rowcount(
        &self,
        buf: &mut ReadBuffer,
        ttc_field_version: u8,
    ) -> Result<(u32, Option<String>, u16, u64)> {
        use crate::constants::ccap_value;

        // End of call status
        let _call_status = buf.read_ub4()?;
        // End to end seq#
        buf.skip_ub2()?;
        // Current row number (used as row_count for Oracle 11g)
        let cur_row_number = buf.read_ub4()? as u64;
        // Error number (short form) — used as error code for Oracle 11g
        let error_num_short = buf.read_ub2()?;
        // Array elem error
        buf.skip_ub2()?;
        // Array elem error
        buf.skip_ub2()?;
        // Cursor ID
        let cursor_id = buf.read_ub2()?;
        // Error position (UB2 in go-ora, not fixed SB2)
        buf.skip_ub2()?;
        // SQL type (19c and earlier)
        buf.skip_ub1()?;
        // Fatal?
        buf.skip_ub1()?;
        // Flags
        buf.skip_ub1()?;
        // User cursor options
        buf.skip_ub1()?;
        // UPI parameter
        buf.skip_ub1()?;
        // Flags (second)
        buf.skip_ub1()?;
        // Rowid (rba, partition_id, skip 1, block_num, slot_num)
        buf.skip_ub4()?; // rba
        buf.skip_ub2()?; // partition_id
        buf.skip_ub1()?; // skip
        buf.skip_ub4()?; // block_num
        buf.skip_ub2()?; // slot_num
        // OS error
        buf.skip_ub4()?;
        // Statement number
        buf.skip_ub1()?;
        // Call number
        buf.skip_ub1()?;
        // Padding (u8 for 10g/11g TTC<7, UB2 for 12c+)
        if ttc_field_version < 7 {
            buf.skip_ub1()?;
        } else {
            buf.skip_ub2()?;
        }
        // Success iters
        buf.skip_ub4()?;
        // oerrdd (logical rowid)
        let oerrdd_len = buf.read_ub4()?;
        if oerrdd_len > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        let (error_code, row_count);

        if ttc_field_version >= ccap_value::FIELD_VERSION_12_1 {
            // Oracle 12.1+ (TTC >= 7): batch errors + extended error + row count
            let num_batch_errors = buf.read_ub2()?;
            if num_batch_errors > 0 {
                buf.skip_ub1()?;
                for _ in 0..num_batch_errors {
                    buf.skip_ub2()?;
                }
            }
            let num_offsets = buf.read_ub4()?;
            if num_offsets > 0 {
                buf.skip_ub1()?;
                for _ in 0..num_offsets {
                    buf.skip_ub4()?;
                }
            }
            let num_batch_msgs = buf.read_ub2()?;
            if num_batch_msgs > 0 {
                buf.skip_ub1()?;
                for _ in 0..num_batch_msgs {
                    buf.skip_ub2()?;
                    buf.read_string_with_length()?;
                    buf.skip(2)?;
                }
            }
            error_code = buf.read_ub4()?;
            row_count = buf.read_ub8()?;

            if ttc_field_version >= ccap_value::FIELD_VERSION_21_1 {
                buf.skip_ub4()?; // sql_type
                buf.skip_ub4()?; // server_checksum
            }
        } else {
            // Oracle 11g (TTC < 7): 3 DLC values, no extended error/row count
            let len = buf.read_ub4()?;
            if len > 0 {
                buf.skip_raw_bytes_chunked()?;
            }
            let len = buf.read_ub4()?;
            if len > 0 {
                buf.skip_raw_bytes_chunked()?;
            }
            let len = buf.read_ub4()?;
            if len > 0 {
                buf.skip_raw_bytes_chunked()?;
            }
            error_code = error_num_short as u32;
            row_count = cur_row_number;
        }

        // Error message
        let error_msg = if error_code != 0 {
            buf.read_string_with_length()?.map(|s| s.trim().to_string())
        } else {
            None
        };

        Ok((error_code, error_msg, cursor_id, row_count))
    }

    /// Parse describe info from response to extract column metadata
    ///
    /// Per Python's _process_describe_info, the format is:
    /// - UB4: max row size (skip)
    /// - UB4: number of columns
    /// - If num_columns > 0: UB1 (skip one byte)
    /// - For each column: metadata fields
    /// - After columns: current date, dcb flags, etc.
    /// Parse DescribeInfo for Oracle 10g (ttc_fv <= 5) using go-ora compatible format.
    ///
    /// The 10g format differs from 11g+ in several key ways:
    /// - Scale is UB2 for NUMBER types (not u8)
    /// - ContFlag is UB4 (not UB8)
    /// - OID uses GetDlc format (UB4 + CLR), not TNS bytes_with_length
    /// - Column names use GetDlc format, not read_string_with_ub4_length
    /// - No oaccollid, no uds_flags for 10g
    /// - Post-column data uses GetDlc + 4× UB4 (no dcbqcky)
    pub(crate) fn parse_describe_info_10g(
        &self,
        buf: &mut ReadBuffer,
    ) -> Result<Vec<ColumnInfo>> {
        use crate::constants::OracleType;

        // Step 1: skip chunked preamble is done by caller (skip_raw_bytes_chunked)

        // Step 2: maxRowSize
        buf.skip_ub4()?;

        // Step 3: columnCount
        let num_columns = buf.read_ub4()? as usize;
        if num_columns == 0 {
            // Still need to skip post-column data even with 0 columns
            let dlc_len = buf.read_ub4()?;
            if dlc_len > 0 {
                let _ = buf.read_bytes_with_length()?;
            }
            buf.skip_ub4()?;
            buf.skip_ub4()?;
            buf.skip_ub4()?;
            buf.skip_ub4()?;
            return Ok(Vec::new());
        }

        // Step 4: skip one byte
        buf.skip_ub1()?;

        let mut columns = Vec::with_capacity(num_columns);

        for col_idx in 0..num_columns {
            // Step 5a: dataType
            let ora_type_num = buf.read_u8()?;
            let oracle_type = OracleType::try_from(ora_type_num).unwrap_or(OracleType::Varchar);

            // Step 5b: flag
            buf.skip_ub1()?;

            // Step 5c: precision
            let mut precision = buf.read_u8()? as i16;

            // Step 5d: scale — UB2 for NUMBER/TIMESTAMP types, u8 for others
            let mut scale: i16 = match oracle_type {
                OracleType::Number
                | OracleType::Timestamp
                | OracleType::TimestampTz
                | OracleType::TimestampLtz
                | OracleType::IntervalDs
                | OracleType::IntervalYm => {
                    let s = buf.read_sb2()?;
                    if s == -127 {
                        precision = (precision as f64 * 0.30103).ceil() as i16;
                        0xFFi16
                    } else {
                        s as i16
                    }
                }
                _ => buf.read_u8()? as i16,
            };

            if oracle_type == OracleType::Number && precision == 0 && (scale == 0 || scale == 0xFF) {
                precision = 38;
                scale = 0xFF;
            }

            // Step 5e: maxLen
            let buffer_size = buf.read_ub4()?;

            // Step 5f: maxNoOfArrayElements
            buf.skip_ub4()?;

            // Step 5g: contFlag (UB4 for ttc_fv < 10)
            buf.skip_ub4()?;

            // Step 5h: toID/OID (GetDlc = UB4 length + if > 0: CLR)
            let oid_len = buf.read_ub4()?;
            if oid_len > 0 {
                let _ = buf.read_bytes_with_length()?;
            }

            // Step 5i: version
            buf.skip_ub2()?;

            // Step 5j: charsetID
            buf.skip_ub2()?;

            // Step 5k: charsetForm
            let csfrm = buf.read_u8()?;

            // Step 5l: maxCharLen (max_size)
            let max_size = buf.read_ub4()?;

            // Step 5m: nulls_allowed
            let nulls_allowed = buf.read_u8()?;

            // Step 5n: v7 length of name
            buf.skip_ub1()?;

            // Step 5o: column name (GetDlc)
            let name = self.read_dlc_string(buf)?.unwrap_or_else(|| format!("COL{}", col_idx + 1));

            // Step 5p: schema name (GetDlc)
            let _schema = self.read_dlc_string(buf)?;

            // Step 5q: type name (GetDlc)
            let _type_name = self.read_dlc_string(buf)?;

            // Step 5r: column position
            buf.skip_ub2()?;

            let mut col = ColumnInfo::new(&name, oracle_type);
            col.data_size = if max_size > 0 { max_size } else { buffer_size };
            col.max_size = max_size;
            col.precision = precision;
            col.scale = scale;
            col.csfrm = csfrm;
            col.nullable = nulls_allowed != 0;
            if let Some(schema) = _schema {
                col.type_schema = Some(schema);
            }
            if let Some(type_name) = _type_name {
                col.type_name = Some(type_name);
            }
            columns.push(col);
        }

        // Step 6: GetDlc() — extra data after columns
        let dlc_len = buf.read_ub4()?;
        if dlc_len > 0 {
            let _ = buf.read_bytes_with_length()?;
        }

        // Step 7: ttcVersion >= 3 — 2 × UB4
        buf.skip_ub4()?;
        buf.skip_ub4()?;

        // Step 8: ttcVersion >= 4 — 2 × UB4
        buf.skip_ub4()?;
        buf.skip_ub4()?;

        // ttcVersion < 5: no GetDlc() here

        Ok(columns)
    }

    /// Read a string stored in GetDlc format (UB4 length + CLR bytes)
    fn read_dlc_string(&self, buf: &mut ReadBuffer) -> Result<Option<String>> {
        let len = buf.read_ub4()?;
        if len == 0 {
            return Ok(None);
        }
        match buf.read_bytes_with_length()? {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|e| Error::DataConversionError(e.to_string())),
        }
    }

    pub(crate) fn parse_describe_info(
        &self,
        buf: &mut ReadBuffer,
        ttc_field_version: u8,
    ) -> Result<Vec<ColumnInfo>> {
        use crate::constants::ccap_value;

        // Oracle 10g (ttc_fv <= 5) uses a different DescribeInfo format
        if ttc_field_version <= ccap_value::FIELD_VERSION_10_2 {
            return self.parse_describe_info_10g(buf);
        }

        // Skip max row size
        buf.skip_ub4()?;

        // Read number of columns
        let num_columns = buf.read_ub4()? as usize;
        if num_columns == 0 {
            return Ok(Vec::new());
        }

        // Skip one byte if we have columns
        buf.skip_ub1()?;

        let mut columns = Vec::with_capacity(num_columns);

        for _col_idx in 0..num_columns {
            // Parse column metadata per Python's _process_metadata
            let ora_type_num = buf.read_u8()?;
            buf.skip_ub1()?; // flags
            let precision = buf.read_u8()?; // precision as SB1
            let scale = buf.read_u8()?; // scale as SB1
            let buffer_size = buf.read_ub4()?;

            buf.skip_ub4()?; // max_num_array_elements
            buf.skip_ub8()?; // cont_flags
            let _oid = buf.read_bytes_with_length()?; // OID
            buf.skip_ub2()?; // version
            buf.skip_ub2()?; // charset_id
            let csfrm = buf.read_u8()?; // charset form
            let max_size = buf.read_ub4()?;

            // For TTC field version >= 12.2 (8), skip oaccolid
            if ttc_field_version >= ccap_value::FIELD_VERSION_12_2 {
                buf.skip_ub4()?; // oaccolid
            }

            let _nulls_allowed = buf.read_u8()?;
            buf.skip_ub1()?; // v7 length of name
            let name = buf.read_string_with_ub4_length()?.unwrap_or_default();
            let _schema = buf.read_string_with_ub4_length()?; // schema
            let _type_name = buf.read_string_with_ub4_length()?; // type_name
            buf.skip_ub2()?; // column position
            buf.skip_ub4()?; // uds_flags

            // For TTC field version >= 23.1 (17), read domain fields
            if ttc_field_version >= ccap_value::FIELD_VERSION_23_1 {
                let _domain_schema = buf.read_string_with_ub4_length()?;
                let _domain_name = buf.read_string_with_ub4_length()?;
            }

            // For TTC field version >= 20 (23.1_EXT_3), read annotations
            if ttc_field_version >= 20 {
                let num_annotations = buf.read_ub4()?;
                if num_annotations > 0 {
                    buf.skip_ub1()?;
                    // Read the actual annotations count (yes, it's read twice in Python)
                    let actual_num = buf.read_ub4()?;
                    buf.skip_ub1()?;
                    for _ in 0..actual_num {
                        // Skip annotation key and value (both are string with UB4 length)
                        let _key = buf.read_string_with_ub4_length()?;
                        let _value = buf.read_string_with_ub4_length()?;
                        buf.skip_ub4()?; // flags per annotation
                    }
                    buf.skip_ub4()?; // final flags
                }
            }

            // For TTC field version >= 24 (23.4), read vector fields
            if ttc_field_version >= ccap_value::FIELD_VERSION_23_4 {
                buf.skip_ub4()?; // vector_dimensions
                buf.skip_ub1()?; // vector_format
                buf.skip_ub1()?; // vector_flags
            }

            // Convert data type to OracleType
            let oracle_type = crate::constants::OracleType::try_from(ora_type_num)
                .unwrap_or(crate::constants::OracleType::Varchar);

            let mut col = ColumnInfo::new(&name, oracle_type);
            col.data_size = if max_size > 0 { max_size } else { buffer_size };
            col.max_size = max_size;
            col.precision = precision as i16;
            col.scale = scale as i16;
            col.csfrm = csfrm;
            columns.push(col);
        }

        // After columns: skip remaining describe info fields
        // Python's _process_describe_info uses:
        //   buf.read_ub4(&num_bytes)
        //   if num_bytes > 0:
        //       buf.skip_raw_bytes_chunked()    # current date
        //   buf.skip_ub4()                      # dcbflag
        //   buf.skip_ub4()                      # dcbmdbz
        //   buf.skip_ub4()                      # dcbmnpr
        //   buf.skip_ub4()                      # dcbmxpr
        //   buf.read_ub4(&num_bytes)
        //   if num_bytes > 0:
        //       buf.skip_raw_bytes_chunked()    # dcbqcky

        // current_date - read UB4 indicator first, then skip chunked bytes if > 0
        let current_date_indicator = buf.read_ub4()?;
        if current_date_indicator > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // dcb* fields as UB4
        buf.skip_ub4()?; // dcbflag
        buf.skip_ub4()?; // dcbmdbz
        buf.skip_ub4()?; // dcbmnpr
        buf.skip_ub4()?; // dcbmxpr

        // dcbqcky - read UB4 indicator first, then skip chunked bytes if > 0
        let dcbqcky_indicator = buf.read_ub4()?;
        if dcbqcky_indicator > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // After dcbqcky, the next message (RowHeader) follows directly
        // No additional fields to skip here

        Ok(columns)
    }

    pub(crate) fn parse_lob_read_response(&self, payload: Bytes, locator: &LobLocator, big_clr: bool) -> Result<LobData> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::new(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut lob_data: Option<Vec<u8>> = None;

        // Process messages until end of response
        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // LobData message (14)
                x if x == MessageType::LobData as u8 => {
                    // Read LOB data with length
                    let data = buf.read_raw_bytes_chunked_ext(big_clr)?;
                    lob_data = Some(data);
                }

                // Parameter return (8) - contains updated locator and amount
                x if x == MessageType::Parameter as u8 => {
                    // Skip the updated locator (same length as original)
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;

                    // Read back the amount (ub8)
                    let _returned_amount = buf.read_ub8()?;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    // Parse error info - code 0 means success
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                        // code 0 = success, continue processing
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                // Skip other message types
                _ => {
                    // Try to skip unknown messages
                    continue;
                }
            }
        }

        // Convert to appropriate type based on LOB type
        match lob_data {
            Some(data) => {
                if locator.is_blob() || locator.is_bfile() {
                    Ok(LobData::Bytes(bytes::Bytes::from(data)))
                } else {
                    // CLOB - decode based on encoding
                    let text = if locator.uses_var_length_charset() {
                        // UTF-16 BE encoding
                        let chars: Vec<u16> = data
                            .chunks_exact(2)
                            .map(|c| u16::from_be_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&chars)
                    } else {
                        // UTF-8 encoding
                        String::from_utf8_lossy(&data).into_owned()
                    };
                    Ok(LobData::String(text))
                }
            }
            None => {
                // Empty LOB
                if locator.is_blob() || locator.is_bfile() {
                    Ok(LobData::Bytes(bytes::Bytes::new()))
                } else {
                    Ok(LobData::String(String::new()))
                }
            }
        }
    }

    pub(crate) fn parse_lob_bool_response(&self, payload: Bytes, locator: &LobLocator) -> Result<bool> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::new(payload);
        buf.skip(2)?; // Skip data flags

        let mut bool_result: bool = false;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Parameter return (8) - contains updated locator and bool flag
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    // Boolean flag is a single byte, > 0 means true
                    let flag = buf.read_u8()?;
                    bool_result = flag > 0;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
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

        Ok(bool_result)
    }

    /// Parse a simple LOB operation response (write, trim)
    pub(crate) fn parse_lob_simple_response(&self, payload: Bytes, locator: &LobLocator) -> Result<()> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::new(payload);
        buf.skip(2)?; // Skip data flags

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Parameter return (8) - contains updated locator and possibly amount
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    // After locator, there may be amount (ub8) if send_amount was true
                    // We just skip any remaining bytes until we hit Error or EndOfResponse
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
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

        Ok(())
    }

    /// Parse a LOB operation response that returns an amount (get_length, get_chunk_size)
    pub(crate) fn parse_lob_amount_response(&self, payload: Bytes, locator: &LobLocator) -> Result<u64> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::new(payload);
        buf.skip(2)?; // Skip data flags

        let mut returned_amount: u64 = 0;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Parameter return (8) - contains updated locator and amount
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    returned_amount = buf.read_ub8()?;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
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

        Ok(returned_amount)
    }

    /// Parse LOB error response
    pub(crate) fn parse_lob_error<T>(&self, buf: &mut crate::buffer::ReadBuffer) -> Result<T> {
        // Try to extract error info
        if let Ok((code, msg, _)) = self.parse_error_info(buf) {
            let message = msg.unwrap_or_else(|| "Unknown LOB error".to_string());
            Err(Error::OracleError { code, message })
        } else {
            Err(Error::Protocol("LOB operation failed".to_string()))
        }
    }
}

/// Parse a type name into (schema, name), using the default schema
/// if the type name doesn't include one.
pub(crate) fn parse_type_name(type_name: &str, default_schema: &str) -> (String, String) {
    let parts: Vec<&str> = type_name.split('.').collect();
    match parts.len() {
        1 => (default_schema.to_uppercase(), parts[0].to_uppercase()),
        2 => (parts[0].to_uppercase(), parts[1].to_uppercase()),
        _ => {
            // Multiple dots - take first as schema, rest as name
            (parts[0].to_uppercase(), parts[1..].join(".").to_uppercase())
        }
    }
}

/// Decode NCHAR bytes based on the NLS_NCHAR_CHARACTERSET ID.
///
/// Handles AL16UTF16 (UTF-16 BE) and UTF-8 based character sets.
/// For unknown character sets, falls back to lossy UTF-8 decoding.
pub(crate) fn decode_nchar_bytes(bytes: &[u8], ncharset_id: u16) -> Result<String> {
    match ncharset_id {
        crate::constants::charset::UTF16 => {
            if bytes.len() % 2 != 0 {
                return Err(Error::DataConversionError(
                    "Invalid AL16UTF16 string: odd byte length".to_string(),
                ));
            }
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect();
            String::from_utf16(&units)
                .map_err(|e| Error::DataConversionError(format!("Invalid AL16UTF16 string: {e}")))
        }
        crate::constants::charset::AL16UTF8 | crate::constants::charset::UTF8 => {
            String::from_utf8(bytes.to_vec())
                .map_err(|e| Error::DataConversionError(format!("Invalid UTF-8 string: {e}")))
        }
        _ => Ok(String::from_utf8_lossy(bytes).into_owned()),
    }
}
