//! Database metadata / introspection methods.
//!
//! These methods query Oracle data dictionary views to discover schemas, tables,
//! columns, indexes, foreign keys, triggers, procedures, and DDL.

use crate::error::Result;
use crate::Connection;

/// Schema information
#[derive(Debug, Clone)]
pub struct SchemaInfo {
    /// Schema (owner) name
    pub name: String,
}

/// Table information
#[derive(Debug, Clone)]
pub struct TableInfo {
    /// Owner / schema name
    pub owner: String,
    /// Table name
    pub table_name: String,
    /// Whether this is a temporary table
    pub temporary: bool,
    /// Tablespace name
    pub tablespace_name: Option<String>,
}

/// View information
#[derive(Debug, Clone)]
pub struct ViewInfo {
    /// Owner / schema name
    pub owner: String,
    /// View name
    pub view_name: String,
}

/// Column information for a table or view
#[derive(Debug, Clone)]
pub struct MetadataColumn {
    /// Column name
    pub column_name: String,
    /// Oracle data type (e.g. "VARCHAR2", "NUMBER")
    pub data_type: String,
    /// Data length
    pub data_length: Option<i64>,
    /// Data precision (for NUMBER)
    pub data_precision: Option<i64>,
    /// Data scale (for NUMBER)
    pub data_scale: Option<i64>,
    /// Whether the column is nullable
    pub nullable: bool,
    /// Column ID (ordinal position)
    pub column_id: i64,
    /// Default value expression
    pub data_default: Option<String>,
}

/// Index information
#[derive(Debug, Clone)]
pub struct MetadataIndex {
    /// Index name
    pub index_name: String,
    /// Index type (NORMAL, BITMAP, etc.)
    pub index_type: Option<String>,
    /// Whether this is a unique index
    pub uniqueness: String,
    /// Column name in the index
    pub column_name: String,
    /// Column position in the index
    pub column_position: i64,
    /// Whether the column is sorted descending
    pub descend: bool,
}

/// Foreign key information
#[derive(Debug, Clone)]
pub struct MetadataForeignKey {
    /// Constraint name
    pub constraint_name: String,
    /// Column name in the source table
    pub column_name: String,
    /// Referenced schema (owner)
    pub referenced_owner: String,
    /// Referenced table name
    pub referenced_table: String,
    /// Referenced column name
    pub referenced_column: String,
}

/// Trigger information
#[derive(Debug, Clone)]
pub struct MetadataTrigger {
    /// Trigger name
    pub trigger_name: String,
    /// Triggering event (INSERT, UPDATE, DELETE)
    pub triggering_event: Option<String>,
    /// Trigger type (BEFORE/AFTER STATEMENT/ROW)
    pub trigger_type: Option<String>,
    /// Whether the trigger is enabled
    pub status: Option<String>,
}

/// Stored procedure / function / package information
#[derive(Debug, Clone)]
pub struct MetadataProcedure {
    /// Object name
    pub object_name: String,
    /// Object type (PROCEDURE, FUNCTION, PACKAGE, etc.)
    pub object_type: String,
    /// Whether the object is valid
    pub status: Option<String>,
}

impl Connection {
    /// List all accessible schemas.
    ///
    /// Queries `ALL_USERS` for schemas visible to the current user.
    pub async fn list_schemas(&self) -> Result<Vec<SchemaInfo>> {
        let result = self
            .query(
                "SELECT DISTINCT username FROM all_users ORDER BY username",
                &[],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .filter_map(|r| {
                r.get_string(0).map(|s| SchemaInfo {
                    name: s.to_string(),
                })
            })
            .collect())
    }

    /// List all tables in the given schema.
    pub async fn list_tables(&self, schema: &str) -> Result<Vec<TableInfo>> {
        let result = self
            .query(
                "SELECT owner, table_name, temporary, tablespace_name \
                 FROM all_tables WHERE owner = :1 ORDER BY table_name",
                &[schema.to_string().into()],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .map(|r| TableInfo {
                owner: r.get_string(0).unwrap_or("").to_string(),
                table_name: r.get_string(1).unwrap_or("").to_string(),
                temporary: r.get_string(2).map(|s| s == "Y").unwrap_or(false),
                tablespace_name: r.get_string(3).map(|s| s.to_string()),
            })
            .collect())
    }

    /// List all views in the given schema.
    pub async fn list_views(&self, schema: &str) -> Result<Vec<ViewInfo>> {
        let result = self
            .query(
                "SELECT owner, view_name FROM all_views WHERE owner = :1 ORDER BY view_name",
                &[schema.to_string().into()],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .map(|r| ViewInfo {
                owner: r.get_string(0).unwrap_or("").to_string(),
                view_name: r.get_string(1).unwrap_or("").to_string(),
            })
            .collect())
    }

    /// List all columns for a table or view.
    pub async fn list_columns(&self, schema: &str, table: &str) -> Result<Vec<MetadataColumn>> {
        let result = self
            .query(
                "SELECT column_name, data_type, data_length, data_precision, \
                 data_scale, nullable, column_id, data_default \
                 FROM all_tab_columns WHERE owner = :1 AND table_name = :2 \
                 ORDER BY column_id",
                &[schema.to_string().into(), table.to_string().into()],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .map(|r| MetadataColumn {
                column_name: r.get_string(0).unwrap_or("").to_string(),
                data_type: r.get_string(1).unwrap_or("").to_string(),
                data_length: r.get_i64(2),
                data_precision: r.get_i64(3),
                data_scale: r.get_i64(4),
                nullable: r.get_string(5).map(|s| s == "Y").unwrap_or(false),
                column_id: r.get_i64(6).unwrap_or(0),
                data_default: r.get_string(7).map(|s| s.to_string()),
            })
            .collect())
    }

    /// List indexes for a table.
    pub async fn list_indexes(&self, schema: &str, table: &str) -> Result<Vec<MetadataIndex>> {
        let result = self
            .query(
                "SELECT i.index_name, i.index_type, i.uniqueness, \
                 c.column_name, c.column_position, c.descend \
                 FROM all_indexes i \
                 JOIN all_ind_columns c ON i.index_name = c.index_name AND i.owner = c.index_owner \
                 WHERE i.owner = :1 AND i.table_name = :2 \
                 ORDER BY i.index_name, c.column_position",
                &[schema.to_string().into(), table.to_string().into()],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .map(|r| MetadataIndex {
                index_name: r.get_string(0).unwrap_or("").to_string(),
                index_type: r.get_string(1).map(|s| s.to_string()),
                uniqueness: r.get_string(2).unwrap_or("").to_string(),
                column_name: r.get_string(3).unwrap_or("").to_string(),
                column_position: r.get_i64(4).unwrap_or(0),
                descend: r.get_string(5).map(|s| s == "DESC").unwrap_or(false),
            })
            .collect())
    }

    /// List foreign keys for a table.
    pub async fn list_foreign_keys(
        &self,
        schema: &str,
        table: &str,
    ) -> Result<Vec<MetadataForeignKey>> {
        let result = self
            .query(
                "SELECT acc.constraint_name, acc.column_name, \
                 acc2.owner AS r_owner, acc2.table_name AS r_table_name, \
                 acc2.column_name AS r_column_name \
                 FROM all_cons_columns acc \
                 JOIN all_constraints ac ON acc.constraint_name = ac.constraint_name \
                   AND acc.owner = ac.owner \
                 JOIN all_cons_columns acc2 ON ac.r_constraint_name = acc2.constraint_name \
                   AND ac.r_owner = acc2.owner \
                 WHERE ac.constraint_type = 'R' \
                   AND acc.owner = :1 AND ac.table_name = :2 \
                 ORDER BY acc.constraint_name, acc.position",
                &[schema.to_string().into(), table.to_string().into()],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .map(|r| MetadataForeignKey {
                constraint_name: r.get_string(0).unwrap_or("").to_string(),
                column_name: r.get_string(1).unwrap_or("").to_string(),
                referenced_owner: r.get_string(2).unwrap_or("").to_string(),
                referenced_table: r.get_string(3).unwrap_or("").to_string(),
                referenced_column: r.get_string(4).unwrap_or("").to_string(),
            })
            .collect())
    }

    /// List triggers for a table.
    pub async fn list_triggers(&self, schema: &str, table: &str) -> Result<Vec<MetadataTrigger>> {
        let result = self
            .query(
                "SELECT trigger_name, triggering_event, trigger_type, status \
                 FROM all_triggers WHERE owner = :1 AND table_name = :2 \
                 ORDER BY trigger_name",
                &[schema.to_string().into(), table.to_string().into()],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .map(|r| MetadataTrigger {
                trigger_name: r.get_string(0).unwrap_or("").to_string(),
                triggering_event: r.get_string(1).map(|s| s.to_string()),
                trigger_type: r.get_string(2).map(|s| s.to_string()),
                status: r.get_string(3).map(|s| s.to_string()),
            })
            .collect())
    }

    /// List stored procedures, functions, and packages for a schema.
    pub async fn list_procedures(&self, schema: &str) -> Result<Vec<MetadataProcedure>> {
        let result = self
            .query(
                "SELECT object_name, object_type, status \
                 FROM all_procedures WHERE owner = :1 ORDER BY object_type, object_name",
                &[schema.to_string().into()],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .map(|r| MetadataProcedure {
                object_name: r.get_string(0).unwrap_or("").to_string(),
                object_type: r.get_string(1).unwrap_or("").to_string(),
                status: r.get_string(2).map(|s| s.to_string()),
            })
            .collect())
    }

    /// Get the DDL for a database object using `DBMS_METADATA.GET_DDL`.
    ///
    /// Returns the CLOB content as a string. Requires `DBMS_METADATA` privilege.
    pub async fn get_object_ddl(&self, schema: &str, name: &str, obj_type: &str) -> Result<String> {
        let result = self
            .query(
                "SELECT dbms_metadata.get_ddl(:1, :2, :3) FROM DUAL",
                &[
                    obj_type.to_string().into(),
                    name.to_string().into(),
                    schema.to_string().into(),
                ],
            )
            .await?;
        Ok(result
            .rows
            .first()
            .and_then(|r| r.get_string(0))
            .unwrap_or("")
            .to_string())
    }

    /// Get the source code for a stored procedure, function, or package.
    pub async fn get_object_source(
        &self,
        schema: &str,
        name: &str,
        obj_type: &str,
    ) -> Result<String> {
        let result = self
            .query(
                "SELECT text FROM all_source \
                 WHERE owner = :1 AND name = :2 AND type = :3 \
                 ORDER BY line",
                &[
                    schema.to_string().into(),
                    name.to_string().into(),
                    obj_type.to_string().into(),
                ],
            )
            .await?;
        Ok(result
            .rows
            .iter()
            .filter_map(|r| r.get_string(0))
            .collect::<Vec<&str>>()
            .join(""))
    }
}
