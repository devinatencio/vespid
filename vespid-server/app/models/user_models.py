"""User CRUD helpers."""

from __future__ import annotations

import sqlite3

from werkzeug.security import generate_password_hash

from .db_core import _row_to_dict


def create_user(
    db: sqlite3.Connection,
    username: str,
    password: str,
    role: str,
    display_name: str = "",
) -> int:
    password_hash = generate_password_hash(password)
    cursor = db.execute(
        "INSERT INTO users (username, password_hash, role, display_name) VALUES (?, ?, ?, ?)",
        (username, password_hash, role, display_name),
    )
    db.commit()
    return cursor.lastrowid


def get_user_by_username(
    db: sqlite3.Connection,
    username: str,
) -> dict | None:
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_user_by_id(
    db: sqlite3.Connection,
    user_id: int,
) -> dict | None:
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def update_user_role(
    db: sqlite3.Connection,
    user_id: int,
    new_role: str,
) -> None:
    db.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        (new_role, user_id),
    )
    db.commit()


def update_user_display_name(
    db: sqlite3.Connection,
    user_id: int,
    display_name: str,
) -> None:
    db.execute(
        "UPDATE users SET display_name = ? WHERE id = ?",
        (display_name[:128], user_id),
    )
    db.commit()


def update_user_theme(
    db: sqlite3.Connection,
    user_id: int,
    theme: str,
) -> None:
    db.execute(
        "UPDATE users SET theme = ? WHERE id = ?",
        (theme, user_id),
    )
    db.commit()


def change_user_password(
    db: sqlite3.Connection,
    user_id: int,
    new_password: str,
) -> None:
    password_hash = generate_password_hash(new_password)
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (password_hash, user_id),
    )
    db.commit()


def reset_user_onboarding(
    db: sqlite3.Connection,
    user_id: int,
) -> None:
    db.execute(
        "UPDATE users SET onboarding_dismissed = 0 WHERE id = ?",
        (user_id,),
    )
    db.commit()


def update_brand_beam_enabled(
    db: sqlite3.Connection,
    user_id: int,
    enabled: bool,
) -> None:
    db.execute(
        "UPDATE users SET brand_beam_enabled = ? WHERE id = ?",
        (1 if enabled else 0, user_id),
    )
    db.commit()


def list_users(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute(
        "SELECT id, username, role, created_at, last_login_at, display_name, theme "
        "FROM users ORDER BY id ASC"
    ).fetchall()
    return [_row_to_dict(r) for r in rows]
