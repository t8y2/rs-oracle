# rust-oracle

纯 Rust 实现的 Oracle 数据库驱动，无需 OCI 或 ODPI-C 依赖。

[English](README.md)

## 特性

- **纯 Rust** — 无需安装 Oracle 客户端库
- **Async/Await** — 基于 Tokio 构建，支持现代异步应用
- **TLS/SSL** — 支持证书和 Oracle Wallet 安全连接
- **SYSDBA / SYSOPER** — 支持管理员认证模式
- **连接池** — 通过 `deadpool-oracle` crate 提供
- **语句缓存** — LRU 缓存预编译语句
- **丰富的类型支持** — 包括 LOB、JSON、VECTOR 等

## 快速开始

在 `Cargo.toml` 中添加：

```toml
[dependencies]
rust-oracle = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

基本用法：

```rust
use oracle_rs::{Config, Connection};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
    let conn = Connection::connect_with_config(config).await?;

    let result = conn.query("SELECT id, name FROM users WHERE active = :1", &[&1]).await?;

    for row in result.rows() {
        let id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        println!("User {}: {}", id, name);
    }

    Ok(())
}
```

## SYSDBA 连接

```rust
use oracle_rs::{Config, Connection};

let mut config = Config::new("localhost", 1521, "XEPDB1", "sys", "password");
config.sysdba = true;
let conn = Connection::connect_with_config(config).await?;
```

## 连接方式

### TLS/SSL 连接

```rust
let config = Config::new("hostname", 2484, "service_name", "user", "password")
    .with_tls()?;
```

### Oracle Wallet

```rust
let config = Config::new("hostname", 2484, "service_name", "user", "password")
    .with_wallet("/path/to/wallet", Some("wallet_password"))?;
```

### DRCP 连接池

```rust
let config = Config::new("hostname", 1521, "service_name", "user", "password")
    .with_drcp("connection_class", "purity");
```

## 查询操作

### SELECT 查询

```rust
let result = conn.query("SELECT * FROM employees", &[]).await?;

// 带绑定参数
let result = conn.query(
    "SELECT * FROM employees WHERE department_id = :1 AND salary > :2",
    &[&10, &50000.0]
).await?;

for row in result.rows() {
    let name: String = row.get("employee_name")?;
    let salary: f64 = row.get("salary")?;
}
```

### DML 操作

```rust
// INSERT
let result = conn.execute(
    "INSERT INTO users (id, name) VALUES (:1, :2)",
    &[&1, &"Alice"]
).await?;

// UPDATE
conn.execute("UPDATE users SET name = :1 WHERE id = :2", &[&"Bob", &1]).await?;

// DELETE
conn.execute("DELETE FROM users WHERE id = :1", &[&1]).await?;
```

### 事务

```rust
conn.execute("INSERT INTO accounts (id, balance) VALUES (:1, :2)", &[&1, &100.0]).await?;
conn.commit().await?;

// 回滚
conn.rollback().await?;

// 保存点
conn.savepoint("before_update").await?;
conn.rollback_to_savepoint("before_update").await?;
```

## 支持的数据类型

| Oracle 类型 | Rust 类型 |
|-------------|-----------|
| NUMBER | `i8`, `i16`, `i32`, `i64`, `f32`, `f64`, `String` |
| VARCHAR2, CHAR | `String`, `&str` |
| DATE | `chrono::NaiveDateTime` |
| TIMESTAMP | `chrono::NaiveDateTime` |
| TIMESTAMP WITH TIME ZONE | `chrono::DateTime<FixedOffset>` |
| RAW | `Vec<u8>`, `&[u8]` |
| CLOB, NCLOB | `String` |
| BLOB | `Vec<u8>` |
| BOOLEAN | `bool` |
| JSON | `serde_json::Value` |
| VECTOR | `Vec<f32>`, `Vec<f64>`, `Vec<i8>` |

## 最低 Oracle 版本

Oracle Database 10g Release 2 (10.2) 或更高版本。部分特性需要更新版本：

- **原生 BOOLEAN**: Oracle 23c
- **JSON 类型**: Oracle 21c
- **VECTOR 类型**: Oracle 23ai

## 许可证

双许可，任选其一：

- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
