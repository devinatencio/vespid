from __future__ import annotations

import logging
import sqlite3

from .db_core import _row_to_dict

logger = logging.getLogger(__name__)

# ── Feed catalog helpers ─────────────────────────────────────────────────


def list_feed_catalog(
    db: sqlite3.Connection,
    category: str | None = None,
) -> list[dict]:
    """List all feeds in the catalog.

    Args:
        db: An open SQLite connection.
        category: Optional category filter.

    Returns:
        A list of feed dicts ordered by category then name.
    """
    where_clauses: list[str] = []
    params: list = []

    if category:
        where_clauses.append("category = ?")
        params.append(category)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    rows = db.execute(
        f"SELECT * FROM feed_catalog {where_sql} ORDER BY category, name",
        params,
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_feed_catalog_entry(
    db: sqlite3.Connection,
    feed_id: int,
) -> dict | None:
    """Get a single feed catalog entry by id."""
    row = db.execute("SELECT * FROM feed_catalog WHERE id = ?", (feed_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_feed_by_name(
    db: sqlite3.Connection,
    name: str,
) -> dict | None:
    """Get a single feed catalog entry by name."""
    row = db.execute("SELECT * FROM feed_catalog WHERE name = ?", (name,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def add_feed_to_catalog(
    db: sqlite3.Connection,
    name: str,
    url: str,
    description: str,
    fmt: str,
    refresh_seconds: int,
    category: str,
    created_by: str,
    provider: str = "",
    confidence: str = "medium",
    detects: str = "",
    recommended_usage: str = "",
) -> int:
    """Add a custom feed to the catalog.

    Returns:
        The id of the new feed.
    """
    cursor = db.execute(
        "INSERT INTO feed_catalog "
        "(name, url, description, format, refresh_seconds, category, "
        "provider, confidence, detects, recommended_usage, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            name,
            url,
            description,
            fmt,
            refresh_seconds,
            category,
            provider,
            confidence,
            detects,
            recommended_usage,
            created_by,
        ),
    )
    db.commit()
    return cursor.lastrowid


def remove_feed_from_catalog(
    db: sqlite3.Connection,
    feed_id: int,
) -> bool:
    """Remove a feed from the catalog.

    Returns:
        True if the feed was found and deleted.
    """
    row = db.execute("SELECT id FROM feed_catalog WHERE id = ?", (feed_id,)).fetchone()
    if row is None:
        return False
    db.execute("DELETE FROM feed_catalog WHERE id = ?", (feed_id,))
    db.commit()
    return True


def get_feed_catalog_categories(db: sqlite3.Connection) -> list[str]:
    """Return distinct categories from the feed catalog."""
    rows = db.execute("SELECT DISTINCT category FROM feed_catalog ORDER BY category").fetchall()
    return [row["category"] for row in rows]
