//! Streaming query results.
//!
//! The [`RowStream`] type provides async row-by-row iteration over query
//! results. Rows are fetched in batches from the server using FunCode=5
//! (Fetch from cursor) and yielded one at a time from a local buffer.
//!
//! # Example
//!
//! ```rust,no_run
//! use rust_oracle::Connection;
//!
//! # async fn example() -> rust_oracle::Result<()> {
//! let conn = Connection::connect("localhost:1521/FREEPDB1", "user", "pass").await?;
//!
//! let mut stream = conn.query_stream("SELECT * FROM large_table", &[], 500).await?;
//! while let Some(row) = stream.next().await {
//!     let row = row?;
//!     println!("{:?}", row.get_string(0));
//! }
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use crate::connection::Connection;
use crate::error::Result;
use crate::row::Row;
use crate::statement::ColumnInfo;

/// A streaming result set from a query.
///
/// Rows are fetched in batches from the Oracle server using cursor re-fetch
/// (FunCode=5). Each batch is buffered locally and yielded one row at a time.
/// When the buffer is exhausted, another batch is fetched transparently.
pub struct RowStream {
    /// Cached connection for fetching more rows
    conn: Connection,
    /// Remaining rows in the current batch (in reverse order for efficient pop)
    buffer: Vec<Row>,
    /// Column metadata for this result set
    columns: Arc<Vec<ColumnInfo>>,
    /// Cursor ID for fetching more rows (0 = exhausted)
    cursor_id: u16,
    /// Number of rows to fetch per batch
    fetch_size: u32,
    /// Whether there are more rows server-side
    has_more: bool,
}

impl RowStream {
    /// Create a new row stream from an initial query result.
    ///
    /// The stream will lazily fetch more rows using `fetch_more` as needed.
    pub(crate) fn new(
        conn: Connection,
        columns: Vec<ColumnInfo>,
        cursor_id: u16,
        mut rows: Vec<Row>,
        has_more_rows: bool,
        fetch_size: u32,
    ) -> Self {
        rows.reverse();
        Self {
            conn,
            buffer: rows,
            columns: Arc::new(columns),
            cursor_id,
            fetch_size,
            has_more: has_more_rows,
        }
    }

    /// Get column metadata for this result set.
    pub fn columns(&self) -> &[ColumnInfo] {
        &self.columns
    }

    /// Get the next row from the stream, or `None` if exhausted.
    ///
    /// When the local buffer is empty and there are more rows server-side,
    /// a `fetch_more` call is made to get the next batch.
    pub async fn next(&mut self) -> Option<Result<Row>> {
        // If buffer is empty, try to fetch more
        if self.buffer.is_empty() && self.cursor_id > 0 {
            match self
                .conn
                .fetch_more(self.cursor_id, &self.columns, self.fetch_size)
                .await
            {
                Ok(mut more) => {
                    more.rows.reverse();
                    self.buffer = more.rows;
                    self.cursor_id = more.cursor_id;
                    self.has_more = more.has_more_rows;
                }
                Err(e) => {
                    self.cursor_id = 0;
                    self.has_more = false;
                    return Some(Err(e));
                }
            }
        }

        self.buffer.pop().map(Ok)
    }

    /// Collect all remaining rows into a `Vec`.
    pub async fn collect(mut self) -> Result<Vec<Row>> {
        let mut rows: Vec<Row> = Vec::with_capacity(self.buffer.len());
        while let Some(row) = self.next().await {
            rows.push(row?);
        }
        Ok(rows)
    }

    /// Close the stream early. No explicit cursor close is needed —
    /// the server will close the cursor when the next query is executed.
    pub async fn close(&mut self) -> Result<()> {
        self.buffer.clear();
        self.cursor_id = 0;
        self.has_more = false;
        Ok(())
    }
}
