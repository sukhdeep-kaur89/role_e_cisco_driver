"""SQLite record of every block, so expiry still works after a restart."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device      TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    acl         TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    alert_id    TEXT,
    reason      TEXT,
    created_at  REAL    NOT NULL,
    expires_at  REAL    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active',  -- active / expired / removed / replaced
    ended_at    REAL,
    ended_by    TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_block ON blocks(device, ip) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS blocks_by_expiry ON blocks(status, expires_at);
CREATE TABLE IF NOT EXISTS changes (
    device TEXT NOT NULL,
    ts     REAL NOT NULL
);
"""


def iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


@dataclass
class BlockRecord:
    id: int
    device: str
    ip: str
    acl: str
    seq: int
    alert_id: Optional[str]
    reason: Optional[str]
    created_at: float
    expires_at: float
    status: str
    ended_at: Optional[float]
    ended_by: Optional[str]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["created_at_utc"] = iso(self.created_at)
        data["expires_at_utc"] = iso(self.expires_at)
        data["ended_at_utc"] = iso(self.ended_at)
        return data


class BlockStore:
    def __init__(self, path: Union[str, Path]):
        # check_same_thread=False + our own lock: the expiry worker thread shares it.
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _rows(self, sql: str, params: tuple = ()) -> List[BlockRecord]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [BlockRecord(**dict(r)) for r in rows]

    def _one(self, sql: str, params: tuple = ()) -> Optional[BlockRecord]:
        rows = self._rows(sql, params)
        return rows[0] if rows else None

    # ---- blocks

    def add(self, device: str, ip: str, acl: str, seq: int, alert_id: str, reason: str,
            created_at: float, expires_at: float) -> BlockRecord:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO blocks (device, ip, acl, seq, alert_id, reason, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (device, ip, acl, seq, alert_id, reason, created_at, expires_at),
            )
            new_id = cur.lastrowid
        record = self._one("SELECT * FROM blocks WHERE id = ?", (new_id,))
        if record is None:
            raise RuntimeError("Block record could not be read back after insert")
        return record

    def get_active(self, device: str, ip: str) -> Optional[BlockRecord]:
        return self._one(
            "SELECT * FROM blocks WHERE device = ? AND ip = ? AND status = 'active'", (device, ip)
        )

    def list_active(self, device: Optional[str] = None) -> List[BlockRecord]:
        if device is None:
            return self._rows("SELECT * FROM blocks WHERE status = 'active' ORDER BY expires_at")
        return self._rows(
            "SELECT * FROM blocks WHERE status = 'active' AND device = ? ORDER BY expires_at", (device,)
        )

    def history(self, limit: int = 50) -> List[BlockRecord]:
        return self._rows("SELECT * FROM blocks ORDER BY id DESC LIMIT ?", (limit,))

    def due(self, now: float) -> List[BlockRecord]:
        return self._rows(
            "SELECT * FROM blocks WHERE status = 'active' AND expires_at <= ? ORDER BY expires_at", (now,)
        )

    def count_active(self, device: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM blocks WHERE status = 'active' AND device = ?", (device,)
            ).fetchone()
        return int(row[0])

    def extend(self, record_id: int, expires_at: float, alert_id: Optional[str] = None) -> None:
        """Push the expiry later. alert_id, if given, becomes the latest alert for this block."""
        with self._lock:
            if alert_id:
                self._conn.execute("UPDATE blocks SET expires_at = ?, alert_id = ? WHERE id = ?",
                                   (expires_at, alert_id, record_id))
            else:
                self._conn.execute("UPDATE blocks SET expires_at = ? WHERE id = ?", (expires_at, record_id))

    def end(self, record_id: int, status: str, by: str, now: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE blocks SET status = ?, ended_by = ?, ended_at = ? WHERE id = ? AND status = 'active'",
                (status, by, now, record_id),
            )

    # ---- rate limiting (stored, so separate CLI runs share the limit)

    def record_change(self, device: str, now: float) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO changes (device, ts) VALUES (?, ?)", (device, now))
            self._conn.execute("DELETE FROM changes WHERE ts < ?", (now - 3600,))

    def changes_since(self, device: str, since: float) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM changes WHERE device = ? AND ts > ?", (device, since)
            ).fetchone()
        return int(row[0])
