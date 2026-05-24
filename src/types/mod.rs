//! Oracle data type encoding and decoding
//!
//! This module provides functions for encoding Rust types to Oracle's wire format
//! and decoding Oracle wire format to Rust types.

mod binary;
mod cursor;
mod date;
mod interval;
mod lob;
mod number;
mod oson;
mod pickle;
mod rowid;
mod vector;

pub use binary::{
    decode_binary_double, decode_binary_float, encode_binary_double, encode_binary_float,
};
pub use cursor::RefCursor;
pub use date::{
    decode_oracle_date, decode_oracle_timestamp, encode_oracle_date, encode_oracle_timestamp,
    OracleDate, OracleTimestamp,
};
pub use interval::{
    decode_interval_ds, decode_interval_ym, encode_interval_ds, encode_interval_ym,
    IntervalDayToSecond, IntervalYearToMonth,
};
pub use lob::{LobData, LobLocator, LobValue};
pub use number::{decode_oracle_number, encode_oracle_number, try_decode_number_fast, OracleNumber};
pub use oson::{OsonDecoder, OsonEncoder};
pub use pickle::{decode_collection, encode_collection};
pub use rowid::{decode_rowid, parse_rowid_string, RowId, MAX_ROWID_LENGTH};
pub use vector::{
    decode_vector, encode_vector, OracleVector, SparseVector, VectorData, VectorFormat,
    VECTOR_MAX_LENGTH,
};
