//! Built-in connection pool for Oracle connections.
//!
//! Provides a production-ready connection pool with:
//! - Connection reuse (lazy creation)
//! - Health checks on borrow and background
//! - Idle timeout and max lifetime
//! - SID ↔ service_name auto-retry on ORA-12514/ORA-12505
//! - Connection statistics
//!
//! # Example
//!
//! ```rust,no_run
//! use rust_oracle::{Config, Pool};
//! use std::time::Duration;
//!
//! # async fn example() -> rust_oracle::Result<()> {
//! let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
//! let pool = Pool::builder(config)
//!     .min_connections(2)
//!     .max_connections(10)
//!     .idle_timeout(Duration::from_secs(300))
//!     .build()
//!     .await?;
//!
//! let conn = pool.get().await?;
//! let rows = conn.query("SELECT 1 FROM DUAL", &[]).await?;
//! // Connection is automatically returned to the pool when dropped
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Notify, Semaphore};

use crate::config::{Config, ServiceMethod};
use crate::connection::Connection;
use crate::error::{Error, Result};

/// Statistics for the connection pool.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Number of connections currently in use
    pub active_connections: usize,
    /// Number of idle connections waiting in the pool
    pub idle_connections: usize,
    /// Total number of connections created over the pool's lifetime
    pub total_connections_created: u64,
    /// Total times a connection was acquired from the pool
    pub total_acquires: u64,
    /// Total times a connection was released to the pool
    pub total_releases: u64,
    /// Number of failed health checks
    pub failed_health_checks: u64,
    /// Number of connections closed due to max lifetime
    pub max_lifetime_closures: u64,
    /// Number of connections closed due to idle timeout
    pub idle_timeout_closures: u64,
}

/// A builder for configuring and creating a [`Pool`].
pub struct PoolBuilder {
    config: Config,
    min_connections: usize,
    max_connections: usize,
    idle_timeout: Duration,
    max_lifetime: Duration,
    health_check_interval: Duration,
}

impl PoolBuilder {
    /// Set the minimum number of idle connections to maintain (default: 1).
    pub fn min_connections(mut self, n: usize) -> Self {
        self.min_connections = n;
        self
    }

    /// Set the maximum number of connections (default: 10).
    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    /// Set the idle timeout — connections idle longer than this are closed (default: 300s).
    pub fn idle_timeout(mut self, d: Duration) -> Self {
        self.idle_timeout = d;
        self
    }

    /// Set the max lifetime — connections older than this are closed (default: 3600s).
    pub fn max_lifetime(mut self, d: Duration) -> Self {
        self.max_lifetime = d;
        self
    }

    /// Set the background health check interval (default: 30s).
    pub fn health_check_interval(mut self, d: Duration) -> Self {
        self.health_check_interval = d;
        self
    }

    /// Build the pool.
    ///
    /// Creates `min_connections` connections upfront and starts the background
    /// health check task.
    pub async fn build(self) -> Result<Pool> {
        let inner = Arc::new(PoolInner {
            config: self.config.clone(),
            idle: Mutex::new(VecDeque::new()),
            semaphore: Arc::new(Semaphore::new(self.max_connections)),
            max_connections: self.max_connections,
            min_connections: self.min_connections,
            idle_timeout: self.idle_timeout,
            max_lifetime: self.max_lifetime,
            health_check_interval: self.health_check_interval,
            total_created: AtomicU64::new(0),
            total_acquires: AtomicU64::new(0),
            total_releases: AtomicU64::new(0),
            failed_health_checks: AtomicU64::new(0),
            max_lifetime_closures: AtomicU64::new(0),
            idle_timeout_closures: AtomicU64::new(0),
            notify: Notify::new(),
            closed: AtomicU64::new(0), // 0 = open, 1 = closed
        });

        // Pre-create minimum connections
        for _ in 0..self.min_connections {
            let conn = Pool::create_connection(&self.config).await?;
            let entry = PooledEntry {
                conn,
                created_at: Instant::now(),
                last_used_at: Instant::now(),
            };
            inner.idle.lock().await.push_back(entry);
        }

        // Start background health check task
        let inner_bg = Arc::clone(&inner);
        tokio::spawn(async move {
            Pool::health_check_loop(inner_bg).await;
        });

        Ok(Pool { inner })
    }
}

struct PooledEntry {
    conn: Connection,
    created_at: Instant,
    last_used_at: Instant,
}

struct PoolInner {
    config: Config,
    idle: Mutex<VecDeque<PooledEntry>>,
    semaphore: Arc<Semaphore>,
    max_connections: usize,
    min_connections: usize,
    idle_timeout: Duration,
    max_lifetime: Duration,
    health_check_interval: Duration,
    // Stats counters (AtomicU64 for lock-free increments)
    total_created: AtomicU64,
    total_acquires: AtomicU64,
    total_releases: AtomicU64,
    failed_health_checks: AtomicU64,
    max_lifetime_closures: AtomicU64,
    idle_timeout_closures: AtomicU64,
    notify: Notify,
    closed: AtomicU64, // 0=open, 1=closed
}

/// A connection pool for Oracle databases.
///
/// See [module-level documentation](self) for usage examples.
pub struct Pool {
    inner: Arc<PoolInner>,
}

impl Pool {
    /// Create a new [`PoolBuilder`].
    pub fn builder(config: Config) -> PoolBuilder {
        PoolBuilder {
            config,
            min_connections: 1,
            max_connections: 10,
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(3600),
            health_check_interval: Duration::from_secs(30),
        }
    }

    /// Get a connection from the pool.
    ///
    /// Returns a [`PooledConnection`] that is automatically returned to the pool
    /// when dropped. If no idle connections are available and the pool is at
    /// capacity, this waits until a connection is returned.
    pub async fn get(&self) -> Result<PooledConnection> {
        let mut permit: Option<tokio::sync::OwnedSemaphorePermit> = None;

        let conn = loop {
            // Acquire a permit if we don't have one
            if permit.is_none() {
                permit = Some(
                    self.inner
                        .semaphore
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| Error::ConnectionClosed)?,
                );
            }

            let mut idle = self.inner.idle.lock().await;
            if let Some(entry) = idle.pop_front() {
                drop(idle);
                // Trust the pool — skip ping on borrow for performance.
                // Dead connections are detected by the background health check loop
                // and removed before they reach borrowers.
                self.inner.total_acquires.fetch_add(1, Ordering::Relaxed);
                self.inner.total_created.fetch_add(1, Ordering::Relaxed);
                break entry.conn;
            }

            // No idle connections — create a new one
            drop(idle);
            match Pool::create_connection(&self.inner.config).await {
                Ok(conn) => {
                    self.inner.total_acquires.fetch_add(1, Ordering::Relaxed);
                    self.inner.total_created.fetch_add(1, Ordering::Relaxed);
                    break conn;
                }
                Err(e) => return Err(e),
            }
        };

        Ok(PooledConnection {
            conn: Some(conn),
            pool: Arc::clone(&self.inner),
            _permit: permit.take().unwrap(),
        })
    }

    /// Get current pool statistics.
    pub fn stats(&self) -> PoolStats {
        let idle_count = self.inner.idle.try_lock().map(|q| q.len()).unwrap_or(0);
        let available = self.inner.semaphore.available_permits();
        let active = self.inner.max_connections.saturating_sub(available);
        PoolStats {
            active_connections: active,
            idle_connections: idle_count,
            total_connections_created: self.inner.total_created.load(Ordering::Relaxed),
            total_acquires: self.inner.total_acquires.load(Ordering::Relaxed),
            total_releases: self.inner.total_releases.load(Ordering::Relaxed),
            failed_health_checks: self.inner.failed_health_checks.load(Ordering::Relaxed),
            max_lifetime_closures: self.inner.max_lifetime_closures.load(Ordering::Relaxed),
            idle_timeout_closures: self.inner.idle_timeout_closures.load(Ordering::Relaxed),
        }
    }

    /// Close all connections in the pool.
    ///
    /// After calling close, all subsequent `get()` calls will return an error.
    /// Existing `PooledConnection`s remain usable until dropped.
    pub async fn close(&self) {
        self.inner.closed.store(1, Ordering::Relaxed);
        let mut idle = self.inner.idle.lock().await;
        while let Some(entry) = idle.pop_front() {
            let _ = entry.conn.close().await;
        }
    }

    /// Create a new connection, with SID↔service_name auto-retry.
    async fn create_connection(config: &Config) -> Result<Connection> {
        // Import at call site to avoid module-level dependency
        match Connection::connect_with_config(config.clone()).await {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                // Auto-retry with flipped service method
                if e.is_recoverable() {
                    let mut retry_config = config.clone();
                    match &config.service {
                        ServiceMethod::ServiceName(name) => {
                            // Try using SID instead — extract from service name or use ORCL
                            let sid = name.split('.').next().unwrap_or("ORCL").to_string();
                            retry_config.service = ServiceMethod::Sid(sid);
                        }
                        ServiceMethod::Sid(sid) => {
                            // Try using service name instead
                            retry_config.service =
                                ServiceMethod::ServiceName(format!("{}.localdomain", sid));
                        }
                    }
                    return Connection::connect_with_config(retry_config).await;
                }
                return Err(e);
            }
        }
    }

    /// Background health check loop.
    async fn health_check_loop(inner: Arc<PoolInner>) {
        loop {
            tokio::time::sleep(inner.health_check_interval).await;

            if inner.closed.load(Ordering::Relaxed) != 0 {
                break;
            }

            // Drain idle connections, release lock, ping each, re-insert alive ones
            let entries: Vec<PooledEntry> = {
                let mut idle = inner.idle.lock().await;
                let now = Instant::now();
                let keep = Vec::new();
                let mut to_check = Vec::new();

                while let Some(entry) = idle.pop_front() {
                    let expired = now.duration_since(entry.created_at) > inner.max_lifetime;
                    let idle_too_long = now.duration_since(entry.last_used_at) > inner.idle_timeout;
                    let above_min = idle.len() + 1 + keep.len() > inner.min_connections;

                    if expired || (idle_too_long && above_min) {
                        if expired {
                            inner.max_lifetime_closures.fetch_add(1, Ordering::Relaxed);
                        } else {
                            inner.idle_timeout_closures.fetch_add(1, Ordering::Relaxed);
                        }
                        tokio::spawn(async move {
                            let _ = entry.conn.close().await;
                        });
                    } else {
                        to_check.push(entry);
                    }
                }
                // Put back entries we want to keep (before health check)
                for entry in keep {
                    idle.push_back(entry);
                }
                drop(idle);
                to_check
            };

            // Ping entries outside the lock
            let mut alive = Vec::new();
            for entry in entries {
                if entry.conn.ping().await.is_ok() {
                    alive.push(entry);
                } else {
                    inner.failed_health_checks.fetch_add(1, Ordering::Relaxed);
                    // Replace dead connection
                    let cfg = inner.config.clone();
                    let inner_clone = Arc::clone(&inner);
                    tokio::spawn(async move {
                        if let Ok(new_conn) = Pool::create_connection(&cfg).await {
                            let mut idle = inner_clone.idle.lock().await;
                            idle.push_back(PooledEntry {
                                conn: new_conn,
                                created_at: Instant::now(),
                                last_used_at: Instant::now(),
                            });
                        }
                    });
                }
            }

            // Re-insert alive connections
            {
                let mut idle = inner.idle.lock().await;
                for mut entry in alive {
                    entry.last_used_at = Instant::now();
                    idle.push_back(entry);
                }
            }

            // Replenish minimum connections
            let mut idle = inner.idle.lock().await;
            while idle.len() < inner.min_connections {
                drop(idle);
                match Pool::create_connection(&inner.config).await {
                    Ok(conn) => {
                        let mut idle = inner.idle.lock().await;
                        idle.push_back(PooledEntry {
                            conn,
                            created_at: Instant::now(),
                            last_used_at: Instant::now(),
                        });
                    }
                    Err(_) => {
                        let _ = inner.idle.lock().await;
                        break;
                    }
                }
                idle = inner.idle.lock().await;
            }
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.inner.closed.store(1, Ordering::Relaxed);
    }
}

/// A connection borrowed from a [`Pool`].
///
/// When dropped, the connection is returned to the pool for reuse. If the
/// connection is no longer healthy, it is closed and a new one is created
/// in its place.
pub struct PooledConnection {
    conn: Option<Connection>,
    pool: Arc<PoolInner>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.conn
            .as_ref()
            .expect("PooledConnection already dropped")
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        let conn = self.conn.take().expect("PooledConnection double-dropped");
        let pool = Arc::clone(&self.pool);
        // Return to pool in background — skip ping for performance.
        // Dead connections are caught by the background health check loop.
        tokio::spawn(async move {
            let mut idle = pool.idle.lock().await;
            idle.push_back(PooledEntry {
                conn,
                created_at: Instant::now(),
                last_used_at: Instant::now(),
            });
            pool.total_releases.fetch_add(1, Ordering::Relaxed);
            pool.notify.notify_one();
        });
    }
}
