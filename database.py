"""
database.py — PyShield Dashboard
SQLite persistence layer for risk score history and event log.

Schema:
  risk_snapshots  : periodic SIEM snapshots (score, level, timestamp)
  events          : individual triggered events per snapshot
"""

import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "data" / "pyshield.db"

logger = logging.getLogger(__name__)


# ── Bootstrap ─────────────────────────────────────────────────────────────────
def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS risk_snapshots (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT    NOT NULL,          -- ISO-8601 from SIEM report
                recorded_at   TEXT    NOT NULL,          -- wall-clock insert time
                risk_score    INTEGER NOT NULL,
                risk_level    TEXT    NOT NULL           -- LOW / MEDIUM / HIGH / CRITICAL
            );

            CREATE TABLE IF NOT EXISTS events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id   INTEGER NOT NULL REFERENCES risk_snapshots(id),
                event_name    TEXT    NOT NULL,          -- e.g. "live_port_scan_detected"
                source        TEXT    NOT NULL DEFAULT 'siem'
            );

            CREATE TABLE IF NOT EXISTS summary_lines (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id   INTEGER NOT NULL REFERENCES risk_snapshots(id),
                line          TEXT    NOT NULL
            );

            -- Fast range queries on the trend chart
            CREATE INDEX IF NOT EXISTS idx_snapshots_recorded_at
                ON risk_snapshots(recorded_at);
        """)
    logger.info("Database initialised at %s", DB_PATH)


# ── Write ──────────────────────────────────────────────────────────────────────
def insert_snapshot(siem_data: dict) -> int:
    """
    Persist one SIEM cycle.

    Args:
        siem_data: parsed siem_final_report.json dict

    Returns:
        snapshot_id (int)
    """
    now = datetime.utcnow().isoformat(timespec="seconds")

    with _get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO risk_snapshots (timestamp, recorded_at, risk_score, risk_level)
            VALUES (?, ?, ?, ?)
            """,
            (
                siem_data.get("timestamp", now),
                now,
                int(siem_data.get("total_risk_score", 0)),
                siem_data.get("risk_level", "UNKNOWN"),
            ),
        )
        snapshot_id = cur.lastrowid

        # Bulk-insert triggered events
        triggered = siem_data.get("triggered_events", [])
        if triggered:
            conn.executemany(
                "INSERT INTO events (snapshot_id, event_name, source) VALUES (?, ?, 'siem')",
                [(snapshot_id, name) for name in triggered],
            )

        # Bulk-insert summary lines
        summary = siem_data.get("summary", [])
        if summary:
            conn.executemany(
                "INSERT INTO summary_lines (snapshot_id, line) VALUES (?, ?)",
                [(snapshot_id, line) for line in summary],
            )

    logger.debug("Snapshot #%d inserted (score=%d, level=%s)",
                 snapshot_id,
                 siem_data.get("total_risk_score", 0),
                 siem_data.get("risk_level"))
    return snapshot_id


# ── Read ───────────────────────────────────────────────────────────────────────
def get_risk_history(limit: int = 60) -> list[dict]:
    """
    Fetch the last `limit` snapshots for the trend line chart.

    Returns list of dicts: [{recorded_at, risk_score, risk_level}, ...]
    ordered oldest → newest.
    """
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT recorded_at, risk_score, risk_level
            FROM   risk_snapshots
            ORDER  BY id DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()

    # Reverse so chart reads left-to-right chronologically
    return [dict(r) for r in reversed(rows)]


def get_latest_snapshot() -> dict | None:
    """
    Return the most recent full snapshot with its events and summary lines,
    or None if the table is empty.
    """
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT id, timestamp, recorded_at, risk_score, risk_level
            FROM   risk_snapshots
            ORDER  BY id DESC
            LIMIT  1
            """
        ).fetchone()

        if row is None:
            return None

        snap = dict(row)

        snap["triggered_events"] = [
            r["event_name"]
            for r in conn.execute(
                "SELECT event_name FROM events WHERE snapshot_id = ? ORDER BY id",
                (snap["id"],),
            ).fetchall()
        ]

        snap["summary"] = [
            r["line"]
            for r in conn.execute(
                "SELECT line FROM summary_lines WHERE snapshot_id = ? ORDER BY id",
                (snap["id"],),
            ).fetchall()
        ]

    return snap


def get_event_type_counts(limit_snapshots: int = 20) -> dict[str, int]:
    """
    Aggregate event_name frequencies across the last N snapshots.
    Used by the donut chart.

    Returns: {"live_port_scan_detected": 5, "brute_force_attack": 3, ...}
    """
    with _get_conn() as conn:
        # Subquery: ids of last N snapshots
        rows = conn.execute(
            """
            SELECT e.event_name, COUNT(*) AS cnt
            FROM   events e
            WHERE  e.snapshot_id IN (
                SELECT id FROM risk_snapshots ORDER BY id DESC LIMIT ?
            )
            GROUP  BY e.event_name
            ORDER  BY cnt DESC
            """,
            (limit_snapshots,),
        ).fetchall()

    return {r["event_name"]: r["cnt"] for r in rows}


# ── Internals ──────────────────────────────────────────────────────────────────
@contextmanager
def _get_conn():
    """Yield a thread-safe connection with row_factory set."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent readers
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
