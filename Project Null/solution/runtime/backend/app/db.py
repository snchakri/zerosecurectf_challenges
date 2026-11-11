from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .config import DB_PATH


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=10000;")
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
          session_id TEXT PRIMARY KEY,
          current_layer INTEGER NOT NULL DEFAULT 1,
          final_ready INTEGER NOT NULL DEFAULT 0,
          completed INTEGER NOT NULL DEFAULT 0,
          false_positive_count INTEGER NOT NULL DEFAULT 0,
          cooldown_until TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activations (
          session_id TEXT NOT NULL,
          layer INTEGER NOT NULL,
          nonce TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          used INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          PRIMARY KEY (session_id, layer),
          FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );

        CREATE TABLE IF NOT EXISTS submissions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id TEXT NOT NULL,
          layer INTEGER NOT NULL,
          key_submitted TEXT NOT NULL,
          status TEXT NOT NULL,
          submitted_at TEXT NOT NULL,
          FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );

        CREATE TABLE IF NOT EXISTS fragments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id TEXT NOT NULL,
          layer INTEGER NOT NULL,
          fragment_id TEXT NOT NULL,
          kind TEXT NOT NULL,
          awarded_at TEXT NOT NULL,
          UNIQUE(session_id, layer, kind),
          FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        );
        """
    )
    conn.commit()
    conn.close()
