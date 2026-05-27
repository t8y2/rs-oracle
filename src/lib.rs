#![warn(missing_docs)]

//! # oracle-rs
//!
//! A pure Rust driver for Oracle databases. No OCI or ODPI-C dependencies required.
//!
//! This crate implements the Oracle TNS (Transparent Network Substrate) protocol
//! entirely in Rust, enabling Oracle database connectivity without installing any
//! Oracle client libraries.
//!
//! ## Features
//!
//! - **Pure Rust** - No Oracle client libraries required
//! - **Async/await** - Built on Tokio for modern async applications
//! - **TLS/SSL** - Secure connections with certificate and wallet support
//! - **Statement Caching** - LRU cache for prepared statements
//! - **Comprehensive Type Support** - Including LOBs, JSON, VECTORs, and more
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rust_oracle::{Config, Connection};
//!
//! #[tokio::main]
//! async fn main() -> rust_oracle::Result<()> {
//!     // Connect to Oracle
//!     let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
//!     let conn = Connection::connect_with_config(config).await?;
//!
//!     // Execute a query
//!     let result = conn.query("SELECT id, name FROM users", &[]).await?;
//!
//!     for row in &result.rows {
//!         let id = row.get_i64(0).unwrap_or(0);
//!         let name = row.get_string(1).unwrap_or("");
//!         println!("User {}: {}", id, name);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Connection Options
//!
//! ### Basic Connection
//!
//! ```rust,no_run
//! use rust_oracle::{Config, Connection};
//!
//! # async fn example() -> rust_oracle::Result<()> {
//! let config = Config::new("hostname", 1521, "service_name", "username", "password");
//! let conn = Connection::connect_with_config(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### TLS/SSL Connection
//!
//! ```rust,no_run
//! use rust_oracle::{Config, Connection};
//!
//! # async fn example() -> rust_oracle::Result<()> {
//! let config = Config::new("hostname", 2484, "service_name", "username", "password")
//!     .with_tls()?;
//!
//! let conn = Connection::connect_with_config(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Oracle Wallet
//!
//! ```rust,no_run
//! use rust_oracle::{Config, Connection};
//!
//! # async fn example() -> rust_oracle::Result<()> {
//! let config = Config::new("hostname", 2484, "service_name", "username", "password")
//!     .with_wallet("/path/to/wallet", Some("wallet_password"))?;
//!
//! let conn = Connection::connect_with_config(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Query Execution
//!
//! ### SELECT Queries
//!
//! ```rust,no_run
//! use rust_oracle::{Connection, Value};
//!
//! # async fn example(conn: Connection) -> rust_oracle::Result<()> {
//! // Simple query
//! let result = conn.query("SELECT * FROM employees", &[]).await?;
//!
//! // With bind parameters
//! let result = conn.query(
//!     "SELECT * FROM employees WHERE department_id = :1 AND salary > :2",
//!     &[10.into(), 50000.0.into()]
//! ).await?;
//!
//! // Access rows
//! for row in &result.rows {
//!     let name = row.get_by_name("employee_name").and_then(|v| v.as_str()).unwrap_or("");
//!     let salary = row.get_by_name("salary").and_then(|v| v.as_f64()).unwrap_or(0.0);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### DML Operations
//!
//! ```rust,no_run
//! use rust_oracle::{Connection, Value};
//!
//! # async fn example(conn: Connection) -> rust_oracle::Result<()> {
//! // INSERT
//! let result = conn.execute(
//!     "INSERT INTO users (id, name) VALUES (:1, :2)",
//!     &[1.into(), "Alice".into()]
//! ).await?;
//! println!("Rows inserted: {}", result.rows_affected);
//!
//! // Commit the transaction
//! conn.commit().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Batch Operations
//!
//! ```rust,no_run
//! use rust_oracle::{Connection, Value};
//!
//! # async fn example(conn: Connection) -> rust_oracle::Result<()> {
//! let rows = vec![
//!     vec![Value::Integer(1), Value::String("Alice".into())],
//!     vec![Value::Integer(2), Value::String("Bob".into())],
//!     vec![Value::Integer(3), Value::String("Charlie".into())],
//! ];
//!
//! let result = conn.execute_batch("INSERT INTO users (id, name) VALUES (:1, :2)", &rows).await?;
//! conn.commit().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Transactions
//!
//! ```rust,no_run
//! use rust_oracle::{Connection, Value};
//!
//! # async fn example(conn: Connection) -> rust_oracle::Result<()> {
//! // Auto-commit is off by default
//! conn.execute("INSERT INTO accounts (id, balance) VALUES (:1, :2)", &[1.into(), 100.0.into()]).await?;
//! conn.execute("UPDATE accounts SET balance = balance - :1 WHERE id = :2", &[50.0.into(), 1.into()]).await?;
//!
//! // Commit the transaction
//! conn.commit().await?;
//!
//! // Or rollback on error
//! // conn.rollback().await?;
//!
//! // Savepoints
//! conn.savepoint("before_update").await?;
//! conn.execute("UPDATE accounts SET balance = 0 WHERE id = :1", &[1.into()]).await?;
//! conn.rollback_to_savepoint("before_update").await?;  // Undo the update
//! # Ok(())
//! # }
//! ```
//!
//! ## Data Types
//!
//! | Oracle Type | Rust Type |
//! |-------------|-----------|
//! | NUMBER | `i8`, `i16`, `i32`, `i64`, `f32`, `f64`, `String` |
//! | VARCHAR2, CHAR | `String`, `&str` |
//! | DATE | `chrono::NaiveDateTime` |
//! | TIMESTAMP | `chrono::NaiveDateTime` |
//! | TIMESTAMP WITH TIME ZONE | `chrono::DateTime<FixedOffset>` |
//! | RAW | `Vec<u8>`, `&[u8]` |
//! | CLOB, NCLOB | `String` |
//! | BLOB | `Vec<u8>` |
//! | BOOLEAN | `bool` |
//! | JSON | `serde_json::Value` |
//! | VECTOR | `Vec<f32>`, `Vec<f64>`, `Vec<i8>` |
//!
//! ## Connection Pooling
//!
//! Use the companion [`deadpool-oracle`](https://crates.io/crates/deadpool-oracle) crate
//! for connection pooling.
//!
//! ## Minimum Oracle Version
//!
//! Oracle Database 10g Release 2 (10.2) or later. Some features require newer versions:
//!
//! - **Native BOOLEAN**: Oracle 23c (emulated on earlier versions)
//! - **JSON type**: Oracle 21c
//! - **VECTOR type**: Oracle 23ai

pub mod batch;
pub mod buffer;
pub mod capabilities;
pub mod config;
pub mod connection;
pub mod constants;
pub mod crypto;
pub mod cursor;
pub mod dbobject;
pub mod drcp;
pub mod error;
pub mod implicit;
pub mod lob_stream;
pub mod messages;
pub mod metadata;
pub mod packet;
pub mod pool;
pub(crate) mod protocol;
pub mod row;
pub mod statement;
pub mod statement_cache;
pub mod stream;
pub mod transport;
pub mod types;

// Re-export commonly used types
pub use batch::{BatchBinds, BatchBuilder, BatchError, BatchOptions, BatchResult};
pub use capabilities::Capabilities;
pub use config::{Config, TlsMode};
pub use connection::{
    Connection, ConnectionState, PlsqlResult, QueryOptions, QueryResult, ServerInfo,
    TransactionIsolation,
};
pub use constants::FetchOrientation;
pub use constants::{BindDirection, OracleType};
pub use cursor::{ScrollMode, ScrollResult, ScrollableCursor, ScrollableCursorOptions};
pub use dbobject::{CollectionType, DbObject, DbObjectAttr, DbObjectType};
pub use drcp::{DrcpOptions, DrcpSession, ReleaseMode, SessionPurity};
pub use error::{Error, Result};
pub use implicit::{ImplicitResult, ImplicitResults};
pub use lob_stream::LobStream;
pub use metadata::{
    MetadataColumn, MetadataForeignKey, MetadataIndex, MetadataProcedure, MetadataTrigger,
    SchemaInfo, TableInfo, ViewInfo,
};
pub use pool::{Pool, PoolBuilder, PoolStats, PooledConnection};
pub use row::{Row, RowDataDecoder, Value};
pub use statement::{BindInfo, BindParam, ColumnInfo, Statement, StatementType};
pub use statement_cache::StatementCache;
pub use stream::RowStream;
pub use transport::{Protocol, TlsConfig};
pub use types::{
    IntervalDayToSecond, IntervalYearToMonth, LobData, LobLocator, LobValue, OracleVector,
    OsonDecoder, OsonEncoder, RefCursor, SparseVector, VectorData, VectorFormat,
};

// Re-export serde_json for users working with JSON columns
pub use serde_json;
