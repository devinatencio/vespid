from __future__ import annotations

import logging
import sqlite3
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Saved query helpers ────────────────────────────────────────────────


def get_saved_queries(db: sqlite3.Connection, user_id: int) -> list[dict]:
    rows = db.execute(
        "SELECT id, name, query, created_at, updated_at FROM saved_queries WHERE user_id = ? ORDER BY updated_at DESC",
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def save_query(db: sqlite3.Connection, user_id: int, name: str, query: str) -> dict:
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute(
        "INSERT INTO saved_queries (user_id, name, query, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, name, query, now, now),
    )
    db.commit()
    from app.db_compat import MySQLConnectionWrapper

    is_mysql = isinstance(db, MySQLConnectionWrapper)
    row_id_func = "LAST_INSERT_ID()" if is_mysql else "last_insert_rowid()"
    return dict(
        db.execute(
            "SELECT id, name, query, created_at, updated_at FROM saved_queries WHERE id = ("
            + row_id_func
            + ")"
        ).fetchone()
    )


def update_saved_query(
    db: sqlite3.Connection, query_id: int, user_id: int, name: str, query_text: str
) -> bool:
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    c = db.execute(
        "UPDATE saved_queries SET name = ?, query = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (name, query_text, now, query_id, user_id),
    )
    db.commit()
    return c.rowcount > 0


def delete_saved_query(db: sqlite3.Connection, query_id: int, user_id: int) -> bool:
    c = db.execute(
        "DELETE FROM saved_queries WHERE id = ? AND user_id = ?",
        (query_id, user_id),
    )
    db.commit()
    return c.rowcount > 0
