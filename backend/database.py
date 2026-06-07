"""
database.py – Async SQLite persistence layer for the Host Security Monitoring Platform.

Provides:
* Schema creation for all 14 tables on first init.
* Generic insert / query / update / delete helpers per table.
* Pagination support (page + page_size).
* A singleton ``Database`` instance obtained via ``get_database()``.

All public methods are async and safe for concurrent access from
multiple coroutines within a single event-loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

import aiosqlite

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default database path (relative to project root)
# ---------------------------------------------------------------------------
_DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")

# ---------------------------------------------------------------------------
# SQL Schema
# ---------------------------------------------------------------------------
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    event_id    INTEGER NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'low',
    pid         INTEGER,
    ppid        INTEGER,
    image       TEXT,
    commandline TEXT,
    username    TEXT,
    host        TEXT,
    raw_data    TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT    NOT NULL,
    severity     TEXT    NOT NULL DEFAULT 'medium',
    timestamp    TEXT    NOT NULL,
    mitre        TEXT,
    tactic       TEXT,
    score        INTEGER DEFAULT 0,
    source       TEXT,
    details      TEXT,
    acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER NOT NULL,
    action_type TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    details     TEXT,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS processes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pid         INTEGER NOT NULL,
    ppid        INTEGER,
    image       TEXT,
    commandline TEXT,
    username    TEXT,
    timestamp   TEXT    NOT NULL,
    status      TEXT    DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS process_tree (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pid         INTEGER NOT NULL,
    ppid        INTEGER,
    image       TEXT,
    commandline TEXT,
    timestamp   TEXT    NOT NULL,
    depth       INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS network_connections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    pid         INTEGER,
    process     TEXT,
    protocol    TEXT,
    local_ip    TEXT,
    local_port  INTEGER,
    remote_ip   TEXT,
    remote_port INTEGER,
    status      TEXT
);

CREATE TABLE IF NOT EXISTS firewall_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL,
    action    TEXT,
    protocol  TEXT,
    src_ip    TEXT,
    src_port  INTEGER,
    dst_ip    TEXT,
    dst_port  INTEGER,
    direction TEXT
);

CREATE TABLE IF NOT EXISTS resource_usage (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    cpu_percent      REAL,
    memory_percent   REAL,
    disk_read_bytes  INTEGER,
    disk_write_bytes INTEGER,
    thread_count     INTEGER
);

CREATE TABLE IF NOT EXISTS ioc_hits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    ioc_type        TEXT,
    ioc_value       TEXT,
    source_event_id INTEGER,
    details         TEXT
);

CREATE TABLE IF NOT EXISTS yara_hits (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_name TEXT,
    file_path TEXT,
    details   TEXT
);

CREATE TABLE IF NOT EXISTS mitre_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id       INTEGER,
    technique_id   TEXT,
    technique_name TEXT,
    tactic         TEXT,
    timestamp      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_scores (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id  INTEGER,
    score     INTEGER DEFAULT 0,
    factors   TEXT,
    severity  TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_info (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT    NOT NULL UNIQUE,
    value      TEXT,
    updated_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT    NOT NULL UNIQUE,
    value      TEXT,
    updated_at TEXT    NOT NULL
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source      ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_severity    ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_event_id    ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp   ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre       ON alerts(mitre);
CREATE INDEX IF NOT EXISTS idx_network_timestamp  ON network_connections(timestamp);
CREATE INDEX IF NOT EXISTS idx_firewall_timestamp ON firewall_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_resource_timestamp ON resource_usage(timestamp);
CREATE INDEX IF NOT EXISTS idx_processes_pid      ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_process_tree_pid   ON process_tree(pid);
CREATE INDEX IF NOT EXISTS idx_process_tree_ppid  ON process_tree(ppid);
"""


class Database:
    """Async SQLite database wrapper with table-level CRUD helpers."""

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def init(self) -> None:
        """Open the connection and create tables if they don't exist."""
        if self._db is not None:
            return
        logger.info("Opening database at %s", self.db_path)
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.execute("PRAGMA foreign_keys=ON;")
        await self._db.executescript(_SCHEMA_SQL)
        await self._db.commit()
        logger.info("Database initialized – all tables ready.")

    async def close(self) -> None:
        """Gracefully close the database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None
            logger.info("Database connection closed.")

    @property
    def connection(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Database not initialised – call await db.init() first.")
        return self._db

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------
    async def execute(
        self, sql: str, params: tuple[Any, ...] | list[Any] = ()
    ) -> aiosqlite.Cursor:
        """Execute a single SQL statement."""
        async with self._lock:
            cursor = await self.connection.execute(sql, params)
            await self.connection.commit()
            return cursor

    async def fetch_one(
        self, sql: str, params: tuple[Any, ...] | list[Any] = ()
    ) -> Optional[dict[str, Any]]:
        """Fetch a single row as a dict (or None)."""
        async with self._lock:
            cursor = await self.connection.execute(sql, params)
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def fetch_all(
        self, sql: str, params: tuple[Any, ...] | list[Any] = ()
    ) -> list[dict[str, Any]]:
        """Fetch all rows as a list of dicts."""
        async with self._lock:
            cursor = await self.connection.execute(sql, params)
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Generic CRUD builders
    # ------------------------------------------------------------------
    async def insert(self, table: str, data: dict[str, Any]) -> int:
        """Insert a row into *table* from a dict. Returns ``lastrowid``."""
        cols = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"
        cursor = await self.execute(sql, tuple(data.values()))
        row_id: int = cursor.lastrowid  # type: ignore[assignment]
        logger.debug("Inserted row %d into %s", row_id, table)
        return row_id

    async def query(
        self,
        table: str,
        *,
        filters: Optional[dict[str, Any]] = None,
        order_by: str = "id DESC",
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """
        Query *table* with optional equality filters and pagination.

        Returns ``{"items": [...], "total": N, "page": P, "page_size": S}``.
        """
        where_parts: list[str] = []
        params: list[Any] = []
        if filters:
            for col, val in filters.items():
                if val is not None:
                    where_parts.append(f"{col} = ?")
                    params.append(val)

        where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""

        # Total count
        count_sql = f"SELECT COUNT(*) as cnt FROM {table} {where_clause}"
        count_row = await self.fetch_one(count_sql, tuple(params))
        total = count_row["cnt"] if count_row else 0

        # Page of data
        offset = (page - 1) * page_size
        data_sql = (
            f"SELECT * FROM {table} {where_clause} "
            f"ORDER BY {order_by} LIMIT ? OFFSET ?"
        )
        items = await self.fetch_all(data_sql, tuple(params) + (page_size, offset))

        return {"items": items, "total": total, "page": page, "page_size": page_size}

    async def query_with_range(
        self,
        table: str,
        *,
        filters: Optional[dict[str, Any]] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        date_column: str = "timestamp",
        order_by: str = "id DESC",
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """
        Query with optional date-range filter on *date_column*.
        """
        where_parts: list[str] = []
        params: list[Any] = []

        if filters:
            for col, val in filters.items():
                if val is not None:
                    where_parts.append(f"{col} = ?")
                    params.append(val)

        if date_from:
            where_parts.append(f"{date_column} >= ?")
            params.append(date_from)
        if date_to:
            where_parts.append(f"{date_column} <= ?")
            params.append(date_to)

        where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""

        count_sql = f"SELECT COUNT(*) as cnt FROM {table} {where_clause}"
        count_row = await self.fetch_one(count_sql, tuple(params))
        total = count_row["cnt"] if count_row else 0

        offset = (page - 1) * page_size
        data_sql = (
            f"SELECT * FROM {table} {where_clause} "
            f"ORDER BY {order_by} LIMIT ? OFFSET ?"
        )
        items = await self.fetch_all(data_sql, tuple(params) + (page_size, offset))

        return {"items": items, "total": total, "page": page, "page_size": page_size}

    async def update(
        self, table: str, row_id: int, data: dict[str, Any]
    ) -> int:
        """Update row by primary-key *id*. Returns number of rows changed."""
        set_clause = ", ".join(f"{col} = ?" for col in data.keys())
        sql = f"UPDATE {table} SET {set_clause} WHERE id = ?"
        cursor = await self.execute(sql, tuple(data.values()) + (row_id,))
        return cursor.rowcount  # type: ignore[return-value]

    async def delete(self, table: str, row_id: int) -> int:
        """Delete a single row by primary-key *id*."""
        cursor = await self.execute(f"DELETE FROM {table} WHERE id = ?", (row_id,))
        return cursor.rowcount  # type: ignore[return-value]

    async def get_by_id(self, table: str, row_id: int) -> Optional[dict[str, Any]]:
        """Fetch one row by id."""
        return await self.fetch_one(f"SELECT * FROM {table} WHERE id = ?", (row_id,))

    # ------------------------------------------------------------------
    # Table-specific convenience methods
    # ------------------------------------------------------------------

    # ---- events ----
    async def insert_event(self, event: dict[str, Any]) -> int:
        """Insert a normalized event."""
        data = {
            "timestamp": event.get("timestamp", _now()),
            "source": event.get("source", "unknown"),
            "event_id": event.get("event_id", 0),
            "severity": event.get("severity", "low"),
            "pid": event.get("pid"),
            "ppid": event.get("ppid"),
            "image": event.get("image"),
            "commandline": event.get("commandline"),
            "username": event.get("username"),
            "host": event.get("host"),
            "raw_data": json.dumps(event.get("raw_data")) if event.get("raw_data") else None,
        }
        return await self.insert("events", data)

    async def get_events(
        self,
        *,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        event_id: Optional[int] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        if source:
            filters["source"] = source
        if severity:
            filters["severity"] = severity
        if event_id is not None:
            filters["event_id"] = event_id
        return await self.query_with_range(
            "events",
            filters=filters,
            date_from=date_from,
            date_to=date_to,
            page=page,
            page_size=page_size,
        )

    # ---- alerts ----
    async def insert_alert(self, alert: dict[str, Any]) -> int:
        data = {
            "title": alert.get("title", ""),
            "severity": alert.get("severity", "medium"),
            "timestamp": alert.get("timestamp", _now()),
            "mitre": alert.get("mitre"),
            "tactic": alert.get("tactic"),
            "score": alert.get("score", 0),
            "source": alert.get("source"),
            "details": alert.get("details"),
            "acknowledged": 0,
        }
        return await self.insert("alerts", data)

    async def get_alerts(
        self,
        *,
        severity: Optional[str] = None,
        mitre: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        if severity:
            filters["severity"] = severity
        if mitre:
            filters["mitre"] = mitre
        return await self.query_with_range(
            "alerts",
            filters=filters,
            date_from=date_from,
            date_to=date_to,
            page=page,
            page_size=page_size,
        )

    async def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged. Returns True if a row was updated."""
        n = await self.update("alerts", alert_id, {"acknowledged": 1})
        return n > 0

    # ---- actions ----
    async def insert_action(self, action: dict[str, Any]) -> int:
        data = {
            "alert_id": action["alert_id"],
            "action_type": action.get("action_type", "manual"),
            "timestamp": action.get("timestamp", _now()),
            "details": action.get("details"),
        }
        return await self.insert("actions", data)

    async def get_actions_for_alert(self, alert_id: int) -> list[dict[str, Any]]:
        return await self.fetch_all(
            "SELECT * FROM actions WHERE alert_id = ? ORDER BY timestamp DESC",
            (alert_id,),
        )

    # ---- processes ----
    async def insert_process(self, proc: dict[str, Any]) -> int:
        data = {
            "pid": proc["pid"],
            "ppid": proc.get("ppid"),
            "image": proc.get("image"),
            "commandline": proc.get("commandline"),
            "username": proc.get("username"),
            "timestamp": proc.get("timestamp", _now()),
            "status": proc.get("status", "running"),
        }
        return await self.insert("processes", data)

    # ---- process_tree ----
    async def insert_process_tree_node(self, node: dict[str, Any]) -> int:
        data = {
            "pid": node["pid"],
            "ppid": node.get("ppid"),
            "image": node.get("image"),
            "commandline": node.get("commandline"),
            "timestamp": node.get("timestamp", _now()),
            "depth": node.get("depth", 0),
        }
        return await self.insert("process_tree", data)

    async def get_process_tree(
        self, root_pid: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """Return full tree or subtree rooted at *root_pid*."""
        if root_pid is not None:
            return await self.fetch_all(
                "SELECT * FROM process_tree WHERE pid = ? OR ppid = ? ORDER BY depth",
                (root_pid, root_pid),
            )
        return await self.fetch_all(
            "SELECT * FROM process_tree ORDER BY depth, timestamp DESC"
        )

    # ---- network_connections ----
    async def insert_network_connection(self, conn: dict[str, Any]) -> int:
        data = {
            "timestamp": conn.get("timestamp", _now()),
            "pid": conn.get("pid"),
            "process": conn.get("process"),
            "protocol": conn.get("protocol"),
            "local_ip": conn.get("local_ip"),
            "local_port": conn.get("local_port"),
            "remote_ip": conn.get("remote_ip"),
            "remote_port": conn.get("remote_port"),
            "status": conn.get("status"),
        }
        return await self.insert("network_connections", data)

    async def get_network_connections(
        self, *, page: int = 1, page_size: int = 50
    ) -> dict[str, Any]:
        return await self.query(
            "network_connections", page=page, page_size=page_size
        )

    # ---- firewall_events ----
    async def insert_firewall_event(self, evt: dict[str, Any]) -> int:
        data = {
            "timestamp": evt.get("timestamp", _now()),
            "action": evt.get("action"),
            "protocol": evt.get("protocol"),
            "src_ip": evt.get("src_ip"),
            "src_port": evt.get("src_port"),
            "dst_ip": evt.get("dst_ip"),
            "dst_port": evt.get("dst_port"),
            "direction": evt.get("direction"),
        }
        return await self.insert("firewall_events", data)

    async def get_firewall_events(
        self,
        *,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        return await self.query_with_range(
            "firewall_events",
            date_from=date_from,
            date_to=date_to,
            page=page,
            page_size=page_size,
        )

    # ---- resource_usage ----
    async def insert_resource_usage(self, usage: dict[str, Any]) -> int:
        data = {
            "timestamp": usage.get("timestamp", _now()),
            "cpu_percent": usage.get("cpu_percent"),
            "memory_percent": usage.get("memory_percent"),
            "disk_read_bytes": usage.get("disk_read_bytes"),
            "disk_write_bytes": usage.get("disk_write_bytes"),
            "thread_count": usage.get("thread_count"),
        }
        return await self.insert("resource_usage", data)

    async def get_resource_usage(
        self,
        *,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> dict[str, Any]:
        return await self.query_with_range(
            "resource_usage",
            date_from=date_from,
            date_to=date_to,
            page=page,
            page_size=page_size,
        )

    # ---- ioc_hits ----
    async def insert_ioc_hit(self, hit: dict[str, Any]) -> int:
        data = {
            "timestamp": hit.get("timestamp", _now()),
            "ioc_type": hit.get("ioc_type"),
            "ioc_value": hit.get("ioc_value"),
            "source_event_id": hit.get("source_event_id"),
            "details": hit.get("details"),
        }
        return await self.insert("ioc_hits", data)

    # ---- yara_hits ----
    async def insert_yara_hit(self, hit: dict[str, Any]) -> int:
        data = {
            "timestamp": hit.get("timestamp", _now()),
            "rule_name": hit.get("rule_name"),
            "file_path": hit.get("file_path"),
            "details": hit.get("details"),
        }
        return await self.insert("yara_hits", data)

    # ---- mitre_events ----
    async def insert_mitre_event(self, evt: dict[str, Any]) -> int:
        data = {
            "event_id": evt.get("event_id"),
            "technique_id": evt.get("technique_id"),
            "technique_name": evt.get("technique_name"),
            "tactic": evt.get("tactic"),
            "timestamp": evt.get("timestamp", _now()),
        }
        return await self.insert("mitre_events", data)

    # ---- threat_scores ----
    async def insert_threat_score(self, score: dict[str, Any]) -> int:
        data = {
            "event_id": score.get("event_id"),
            "score": score.get("score", 0),
            "factors": json.dumps(score.get("factors")) if isinstance(score.get("factors"), (dict, list)) else score.get("factors"),
            "severity": score.get("severity"),
            "timestamp": score.get("timestamp", _now()),
        }
        return await self.insert("threat_scores", data)

    # ---- system_info ----
    async def upsert_system_info(self, key: str, value: str) -> None:
        """Insert or replace a system_info key/value pair."""
        now = _now()
        await self.execute(
            "INSERT INTO system_info (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, now),
        )

    async def get_all_system_info(self) -> dict[str, str]:
        rows = await self.fetch_all("SELECT key, value FROM system_info")
        return {r["key"]: r["value"] for r in rows}

    # ---- settings ----
    async def upsert_setting(self, key: str, value: str) -> None:
        now = _now()
        await self.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, now),
        )

    async def get_setting(self, key: str) -> Optional[str]:
        row = await self.fetch_one("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else None

    async def get_all_settings(self) -> dict[str, str]:
        rows = await self.fetch_all("SELECT key, value FROM settings")
        return {r["key"]: r["value"] for r in rows}

    # ------------------------------------------------------------------
    # Statistics / Dashboard
    # ------------------------------------------------------------------
    async def get_stats(self) -> dict[str, Any]:
        """Return dashboard-level statistics."""
        results: dict[str, Any] = {}

        # Total counts
        for table in ("events", "alerts", "network_connections", "firewall_events"):
            row = await self.fetch_one(f"SELECT COUNT(*) as cnt FROM {table}")
            results[f"total_{table}"] = row["cnt"] if row else 0

        # Severity breakdown for events
        sev_rows = await self.fetch_all(
            "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
        )
        results["events_by_severity"] = {r["severity"]: r["cnt"] for r in sev_rows}

        # Severity breakdown for alerts
        alert_sev = await self.fetch_all(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        )
        results["alerts_by_severity"] = {r["severity"]: r["cnt"] for r in alert_sev}

        # Acknowledged vs unacknowledged alerts
        ack_row = await self.fetch_one(
            "SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged = 1"
        )
        results["alerts_acknowledged"] = ack_row["cnt"] if ack_row else 0
        results["alerts_unacknowledged"] = (
            results["total_alerts"] - results["alerts_acknowledged"]
        )

        # Action type counts
        action_rows = await self.fetch_all(
            "SELECT action_type, COUNT(*) as cnt FROM actions GROUP BY action_type"
        )
        results["actions_by_type"] = {r["action_type"]: r["cnt"] for r in action_rows}

        return results


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_db_instance: Optional[Database] = None

def _get_database_internal(db_path: str = _DEFAULT_DB_PATH) -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path)
    return _db_instance

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def _now() -> str:
    """Current UTC time as ISO 8601 string."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

class _DBProxy:
    async def __aenter__(self):
        db = _get_database_internal()
        await db.init()
        return db
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    def __await__(self):
        async def _get():
            db = _get_database_internal()
            await db.init()
            return db
        return _get().__await__()
    def __getattr__(self, name):
        return getattr(_get_database_internal(), name)

def get_database(db_path: str = _DEFAULT_DB_PATH):
    return _DBProxy()

def get_db():
    return _DBProxy()

async def insert_event(*args) -> int:
    return await _get_database_internal().insert_event(args[-1])

async def insert_alert(*args) -> int:
    return await _get_database_internal().insert_alert(args[-1])

async def insert_action(*args) -> int:
    return await _get_database_internal().insert_action(args[-1])

async def insert_process(*args) -> int:
    return await _get_database_internal().insert_process(args[-1])

async def insert_process_tree_node(*args) -> int:
    return await _get_database_internal().insert_process_tree_node(args[-1])

async def insert_network_connection(*args) -> int:
    return await _get_database_internal().insert_network_connection(args[-1])

async def insert_firewall_event(*args) -> int:
    return await _get_database_internal().insert_firewall_event(args[-1])

async def insert_resource_usage(*args) -> int:
    return await _get_database_internal().insert_resource_usage(args[-1])

async def insert_ioc_hit(*args) -> int:
    return await _get_database_internal().insert_ioc_hit(args[-1])

async def insert_yara_hit(*args) -> int:
    return await _get_database_internal().insert_yara_hit(args[-1])

async def insert_mitre_event(*args) -> int:
    return await _get_database_internal().insert_mitre_event(args[-1])

async def insert_threat_score(*args) -> int:
    return await _get_database_internal().insert_threat_score(args[-1])

