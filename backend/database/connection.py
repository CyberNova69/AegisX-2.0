"""Database connection configuration for AegisX.

Provides connection pool management for PostgreSQL 16+. Uses environment
variables for configuration (no secrets in source code).

In development/testing, this module provides a mock connection context
that allows the backend to function without a running PostgreSQL instance.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AegisX.Database")


def _run_sync(coro):
    """Run an async coroutine synchronously from any thread or event loop context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


@dataclass
class DatabaseConfig:
    """Database connection configuration.

    Reads from environment variables with sensible development defaults.
    No secrets are stored in source code.
    """
    host: str = ""
    port: int = 5432
    database: str = "aegisx"
    user: str = ""
    password: str = ""  # Read from env only, never stored
    min_connections: int = 2
    max_connections: int = 10
    ssl_mode: str = "prefer"
    statement_timeout_ms: int = 30000

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Load configuration from environment variables."""
        return cls(
            host=os.environ.get("AEGISX_DB_HOST", "localhost"),
            port=int(os.environ.get("AEGISX_DB_PORT", "5432")),
            database=os.environ.get("AEGISX_DB_NAME", "aegisx"),
            user=os.environ.get("AEGISX_DB_USER", ""),
            password=os.environ.get("AEGISX_DB_PASSWORD", ""),
            min_connections=int(os.environ.get("AEGISX_DB_MIN_CONN", "2")),
            max_connections=int(os.environ.get("AEGISX_DB_MAX_CONN", "10")),
            ssl_mode=os.environ.get("AEGISX_DB_SSL_MODE", "prefer"),
        )

    @property
    def dsn(self) -> str:
        """PostgreSQL connection string (DSN)."""
        return (
            f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}"
            f"/{self.database}?sslmode={self.ssl_mode}"
        )

    @property
    def is_configured(self) -> bool:
        """Check if database credentials are properly configured."""
        return bool(self.host and self.user)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize (without password) for logging/display."""
        return {
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "user": self.user,
            "min_connections": self.min_connections,
            "max_connections": self.max_connections,
            "ssl_mode": self.ssl_mode,
            "is_configured": self.is_configured,
        }


class DatabasePool:
    """Database connection pool manager.

    Wraps asyncpg (if available) for async connection pooling.
    Falls back to a stub in development/testing without PostgreSQL.

    Usage:
        pool = DatabasePool(config)
        await pool.initialize()
        rows = await pool.fetch("SELECT * FROM alerts")
        await pool.close()
    """

    def __init__(self, config: Optional[DatabaseConfig] = None, pool_instance: Optional[Any] = None):
        self.config = config or DatabaseConfig.from_env()
        self._pool = pool_instance
        self._initialized = pool_instance is not None

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    async def initialize(self) -> bool:
        """Initialize the connection pool.

        Returns True if successfully connected, False if database
        is not available (graceful degradation for development).
        """
        if self._pool is not None:
            self._initialized = True
            return True

        if not self.config.is_configured:
            logger.warning(
                "Database not configured. Set AEGISX_DB_HOST and AEGISX_DB_USER "
                "environment variables. Running in development mode without database."
            )
            return False

        try:
            import asyncpg
            self._pool = await asyncpg.create_pool(
                dsn=self.config.dsn,
                min_size=self.config.min_connections,
                max_size=self.config.max_connections,
                command_timeout=self.config.statement_timeout_ms / 1000.0,
            )
            self._initialized = True
            logger.info(
                "Database pool initialized: %s@%s:%d/%s",
                self.config.user, self.config.host,
                self.config.port, self.config.database,
            )
            return True
        except ImportError:
            logger.warning(
                "asyncpg not installed. Install with: pip install asyncpg. "
                "Running in development mode without database."
            )
            return False
        except Exception as exc:
            logger.error("Failed to initialize database pool: %s", exc)
            return False

    async def close(self):
        """Close the connection pool."""
        if self._pool and hasattr(self._pool, "close"):
            await self._pool.close()
        self._initialized = False
        logger.info("Database pool closed.")

    def acquire(self):
        """Acquire a raw connection context manager from the underlying pool."""
        if not self._initialized or not self._pool:
            raise RuntimeError("Database pool is not initialized")
        return self._pool.acquire()

    async def fetch(self, query: str, *args) -> List[Any]:
        """Fetch multiple rows asynchronously."""
        if not self._initialized or not self._pool:
            return []
        async with self._pool.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow(self, query: str, *args) -> Optional[Any]:
        """Fetch a single row asynchronously."""
        if not self._initialized or not self._pool:
            return None
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def fetchval(self, query: str, *args) -> Any:
        """Fetch a single scalar value asynchronously."""
        if not self._initialized or not self._pool:
            return None
        async with self._pool.acquire() as conn:
            return await conn.fetchval(query, *args)

    async def execute(self, query: str, *args) -> str:
        """Execute a query/command asynchronously."""
        if not self._initialized or not self._pool:
            return ""
        async with self._pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def executemany(self, query: str, args_list: List[Any]) -> None:
        """Execute a command against multiple argument sequences asynchronously."""
        if not self._initialized or not self._pool or not args_list:
            return
        async with self._pool.acquire() as conn:
            await conn.executemany(query, args_list)

    # Synchronous query helpers (safe for sync agents/tools)
    def fetch_sync(self, query: str, *args) -> List[Any]:
        """Fetch multiple rows synchronously."""
        if not self._initialized:
            return []
        return _run_sync(self.fetch(query, *args))

    def fetchrow_sync(self, query: str, *args) -> Optional[Any]:
        """Fetch a single row synchronously."""
        if not self._initialized:
            return None
        return _run_sync(self.fetchrow(query, *args))

    def fetchval_sync(self, query: str, *args) -> Any:
        """Fetch a single scalar value synchronously."""
        if not self._initialized:
            return None
        return _run_sync(self.fetchval(query, *args))

    def execute_sync(self, query: str, *args) -> str:
        """Execute a query/command synchronously."""
        if not self._initialized:
            return ""
        return _run_sync(self.execute(query, *args))

    def executemany_sync(self, query: str, args_list: List[Any]) -> None:
        """Execute a command against multiple argument sequences synchronously."""
        if not self._initialized:
            return
        return _run_sync(self.executemany(query, args_list))

    async def health_check(self) -> Dict[str, Any]:
        """Check database connectivity."""
        if not self._initialized or not self._pool:
            return {"status": "disconnected", "configured": self.config.is_configured}

        try:
            async with self._pool.acquire() as conn:
                result = await conn.fetchval("SELECT 1")
                pool_size = self._pool.get_size() if hasattr(self._pool, "get_size") else 1
                pool_idle = self._pool.get_idle_size() if hasattr(self._pool, "get_idle_size") else 1
                return {
                    "status": "healthy",
                    "pool_size": pool_size,
                    "pool_idle": pool_idle,
                }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Module-level singleton
_db_pool: Optional[DatabasePool] = None


def get_db_pool(config: Optional[DatabaseConfig] = None) -> DatabasePool:
    """Get or create the database pool singleton."""
    global _db_pool
    if _db_pool is None:
        _db_pool = DatabasePool(config)
    return _db_pool


def reset_db_pool() -> None:
    """Reset the database pool singleton (for testing)."""
    global _db_pool
    _db_pool = None
