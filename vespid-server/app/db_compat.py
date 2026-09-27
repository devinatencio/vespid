"""Database compatibility layer for MariaDB/MySQL support.

Provides placeholder translation, row wrapping, and connection/cursor wrappers
so that application code can use sqlite3-style ? placeholders and dict-like row
access regardless of the underlying database backend.

The mysql.connector driver is imported lazily (inside functions/methods) so that
SQLite-only deployments do not require the package to be installed.
"""

from __future__ import annotations

import re as _re
from collections.abc import Iterator
from datetime import UTC
from typing import Any

# Pattern matching ISO-8601 timestamps with T separator that need normalization
# for MySQL DATETIME columns. Matches strings like:
#   "2026-05-09T19:50:13Z"
#   "2026-05-09T19:50:13.670199Z"
#   "2026-05-09T19:50:13"
#   "2026-08-02T16:42:19.075801+00:00"
_ISO_TIMESTAMP_RE = _re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
)


def _normalize_param(value: Any) -> Any:
    """Normalize a parameter value for MySQL compatibility.

    Converts ISO-8601 timestamp strings (with T separator, microseconds,
    Z suffix, or numeric timezone offset) to a naive UTC MySQL
    DATETIME-compatible format (space separator, no microseconds,
    no timezone designator).

    "2026-05-09T19:50:13.670199Z" → "2026-05-09 19:50:13"
    "2026-05-09T19:50:13Z" → "2026-05-09 19:50:13"
    "2026-08-02T16:42:19.075801+00:00" → "2026-08-02 16:42:19"

    Non-timestamp strings and non-string values are returned unchanged.
    """
    if not isinstance(value, str):
        return value
    if "T" not in value:
        return value
    if not _ISO_TIMESTAMP_RE.match(value):
        return value
    try:
        from datetime import datetime

        # Normalize the timezone designator so fromisoformat works on all
        # supported Python versions: "Z" → "+00:00" and "+0530" → "+05:30".
        parsed = value.replace("Z", "+00:00")
        if _re.search(r"[+-]\d{4}$", parsed):
            parsed = parsed[:-4] + parsed[-4:-2] + ":" + parsed[-2:]
        dt = datetime.fromisoformat(parsed)
        if dt.tzinfo is not None:
            # MySQL DATETIME columns are timezone-naive; store UTC.
            dt = dt.astimezone(UTC).replace(tzinfo=None)
        normalized = dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        # Fall back to string-level normalization for odd-but-valid inputs.
        normalized = value.rstrip("Z").replace("T", " ")
        dot_idx = normalized.rfind(".")
        if dot_idx > 10:  # Only strip if it's after the date portion
            normalized = normalized[:dot_idx]
    return normalized


def translate_placeholders(sql: str) -> str:
    """Convert sqlite3-style ? placeholders to MySQL %s format.

    Walks the string character by character, tracking whether we are inside
    a single-quoted string literal (handling escaped quotes via '').

    Outside quotes:
      - ? is replaced with %s
      - % is replaced with %% (so the MySQL driver doesn't treat it as a format specifier)

    Inside single-quoted literals:
      - Characters are passed through unchanged.

    Also translates SQLite-only syntax:
      - INSERT OR IGNORE → INSERT IGNORE
      - INSERT OR REPLACE → REPLACE

    Args:
        sql: SQL query string with ? placeholders.

    Returns:
        Translated SQL string with %s placeholders suitable for mysql.connector.
    """
    # SQLite-only syntax translations (before placeholder conversion)
    _sql_upper = sql.strip().upper()
    if _sql_upper.startswith("INSERT OR IGNORE"):
        sql = "INSERT IGNORE" + sql[16:]
    elif _sql_upper.startswith("INSERT OR REPLACE"):
        sql = "REPLACE" + sql[16:]

    result: list[str] = []
    in_quote = False
    i = 0
    length = len(sql)

    while i < length:
        ch = sql[i]

        if in_quote:
            if ch == "'" and i + 1 < length and sql[i + 1] == "'":
                # Escaped single quote inside a literal — pass both through
                result.append("''")
                i += 2
                continue
            elif ch == "'":
                # End of quoted literal
                in_quote = False
                result.append(ch)
            else:
                result.append(ch)
        else:
            if ch == "'":
                # Start of quoted literal
                in_quote = True
                result.append(ch)
            elif ch == "?":
                result.append("%s")
            elif ch == "%":
                result.append("%%")
            else:
                result.append(ch)

        i += 1

    return "".join(result)


class RowWrapper:
    """Makes MySQL result rows accessible by both index and column name.

    Supports:
      - row[0], row[1], ... (index-based access)
      - row["column_name"] (name-based access)
      - dict(row) (conversion to a standard Python dict)
      - len(row) (number of columns)
      - iter(row) (iterate over values)
      - row.keys() (list of column names)
    """

    def __init__(self, data: tuple, columns: list[str]) -> None:
        self._data = data
        self._columns = columns
        self._column_map: dict[str, int] = {name: idx for idx, name in enumerate(columns)}

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._data[key]
        if isinstance(key, str):
            try:
                idx = self._column_map[key]
            except KeyError as exc:
                raise KeyError(key) from exc
            return self._data[idx]
        raise TypeError(f"indices must be integers or strings, not {type(key).__name__}")

    def keys(self) -> list[str]:
        """Return column names (enables dict(row) conversion)."""
        return list(self._columns)

    def __iter__(self) -> Iterator:
        """Iterate over row values."""
        return iter(self._data)

    def __len__(self) -> int:
        """Return the number of columns."""
        return len(self._data)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RowWrapper):
            return self._data == other._data and self._columns == other._columns
        return NotImplemented

    def __repr__(self) -> str:
        pairs = ", ".join(f"{k}={v!r}" for k, v in zip(self._columns, self._data, strict=False))
        return f"RowWrapper({pairs})"


class CursorWrapper:
    """Wraps a mysql.connector cursor to provide sqlite3-compatible interface.

    Translates ? placeholders to %s and escapes literal % characters before
    passing queries to the underlying MySQL cursor. Wraps result rows in
    RowWrapper for dict-like access.
    """

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def execute(self, sql: str, params: Any = None) -> CursorWrapper:
        """Execute a query with optional parameters.

        Translates ? → %s and % → %% in the SQL string before execution.
        Also replaces SQLite's strftime('%Y-%m-%dT%H:%M:%SZ', 'now') with
        a literal UTC timestamp string for MySQL compatibility.
        """
        import re
        from datetime import datetime

        # Replace SQLite strftime('...', 'now') with a literal timestamp value
        _strftime_now_pattern = r"strftime\(\s*'%Y-%m-%dT%H:%M:%SZ'\s*,\s*'now'\s*\)"
        if "strftime(" in sql:
            now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
            sql = re.sub(_strftime_now_pattern, f"'{now_str}'", sql)

        # Replace SQLite datetime('now', '<modifier>') with MySQL-compatible syntax
        # e.g. datetime('now', '-30 days') → NOW() - INTERVAL 30 DAY
        if "datetime(" in sql and "'now'" in sql:

            def _replace_datetime_now(m: re.Match) -> str:
                modifier = m.group(1)
                if not modifier:
                    return "NOW()"
                # Parse modifier like '-30 days', '-1 day', '+7 days'
                m2 = re.match(
                    r"\s*([+-])\s*(\d+)\s+(day|days|hour|hours|minute|minutes|month|months|year|years)\s*",
                    modifier,
                )
                if m2:
                    sign = "-" if m2.group(1) == "-" else "+"
                    num = m2.group(2)
                    unit = m2.group(3).upper()
                    return f"NOW() {sign} INTERVAL {num} {unit}"
                return f"(NOW() {modifier})"

            sql = re.sub(
                r"datetime\(\s*'now'\s*(?:,\s*'([^']+)'\s*)?\)",
                _replace_datetime_now,
                sql,
            )

        translated = translate_placeholders(sql)
        if params is None:
            self._cursor.execute(translated)
        else:
            # Convert params to tuple if it's a list for mysql.connector
            if isinstance(params, list):
                params = tuple(params)
            # Normalize ISO-8601 timestamp strings for MySQL DATETIME columns.
            # MySQL doesn't accept 'T' separator, microseconds, or 'Z' suffix.
            # Convert "2026-05-09T19:50:13.670199Z" → "2026-05-09 19:50:13"
            params = tuple(_normalize_param(p) for p in params)
            self._cursor.execute(translated, params)
        return self

    def executemany(self, sql: str, params_list: Any) -> CursorWrapper:
        """Execute a query with multiple parameter sets.

        Translates ? → %s and % → %% in the SQL string before execution.
        """
        translated = translate_placeholders(sql)
        # Ensure each param set is a tuple and normalize timestamps
        converted = [
            tuple(_normalize_param(p) for p in (tuple(ps) if isinstance(ps, list) else ps))
            for ps in params_list
        ]
        self._cursor.executemany(translated, converted)
        return self

    def executescript(self, sql: str) -> None:
        """Execute multiple SQL statements separated by semicolons.

        Splits the script on ';' and executes each non-empty statement
        individually. No placeholder translation is performed since scripts
        typically contain DDL without parameters.
        """
        statements = sql.split(";")
        for stmt in statements:
            stmt = stmt.strip()
            if stmt:
                self._cursor.execute(stmt)

    def fetchone(self) -> RowWrapper | None:
        """Fetch the next row, wrapped in RowWrapper for dict-like access."""
        row = self._cursor.fetchone()
        if row is None:
            return None
        columns = self._get_columns()
        return RowWrapper(tuple(row), columns)

    def fetchall(self) -> list[RowWrapper]:
        """Fetch all remaining rows, each wrapped in RowWrapper."""
        rows = self._cursor.fetchall()
        columns = self._get_columns()
        return [RowWrapper(tuple(r), columns) for r in rows]

    @property
    def lastrowid(self) -> int:
        """Return the last inserted row ID."""
        return self._cursor.lastrowid

    @property
    def rowcount(self) -> int:
        """Return the number of rows affected by the last operation."""
        return self._cursor.rowcount

    @property
    def description(self) -> list:
        """Return cursor description (column metadata)."""
        return self._cursor.description

    def _get_columns(self) -> list[str]:
        """Extract column names from cursor.description."""
        if self._cursor.description is None:
            return []
        return [desc[0] for desc in self._cursor.description]

    def close(self) -> None:
        """Close the underlying cursor."""
        self._cursor.close()

    def __iter__(self) -> Iterator:
        """Iterate over result rows."""
        columns = self._get_columns()
        for row in self._cursor:
            yield RowWrapper(tuple(row), columns)


class MySQLConnectionWrapper:
    """Wraps a mysql.connector connection to provide sqlite3-compatible interface.

    Provides execute(), executemany(), executescript(), commit(), rollback(),
    close(), start_transaction(), and a row_factory property for compatibility
    with code that expects a sqlite3.Connection-like object.
    """

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self._row_factory = None

    def start_transaction(self, isolation_level: str = "READ COMMITTED") -> None:
        """Begin an explicit transaction.

        The session isolation level is already set to READ COMMITTED at
        connection-creation time (see get_db in models.py).  Calling
        SET TRANSACTION ISOLATION LEVEL here would fail with MySQL error
        1568 when autocommit=False because an implicit transaction is
        always in progress.

        Args:
            isolation_level: Accepted for API compatibility with callers
                that expect a sqlite3.Connection-like interface.  Ignored
                because the session default is already correct.
        """
        cursor = self._connection.cursor()
        cursor.execute("START TRANSACTION")
        cursor.close()

    def execute(self, sql: str, params: Any = None) -> CursorWrapper:
        """Create a cursor, execute the query, and return the wrapped cursor.

        Translates ? → %s and % → %% in the SQL string.
        """
        import mysql.connector  # noqa: F401 — lazy import

        cursor = self._connection.cursor()
        wrapper = CursorWrapper(cursor)
        wrapper.execute(sql, params)
        return wrapper

    def executemany(self, sql: str, params_list: Any) -> CursorWrapper:
        """Create a cursor, execute the query with multiple param sets.

        Translates ? → %s and % → %% in the SQL string.
        """
        import mysql.connector  # noqa: F401 — lazy import

        cursor = self._connection.cursor()
        wrapper = CursorWrapper(cursor)
        wrapper.executemany(sql, params_list)
        return wrapper

    def executescript(self, sql: str) -> None:
        """Execute multiple SQL statements separated by semicolons.

        Splits on ';' and executes each non-empty statement individually.
        """
        import mysql.connector  # noqa: F401 — lazy import

        cursor = self._connection.cursor()
        statements = sql.split(";")
        for stmt in statements:
            stmt = stmt.strip()
            if stmt:
                cursor.execute(stmt)
        cursor.close()
        self._connection.commit()

    def commit(self) -> None:
        """Commit the current transaction."""
        self._connection.commit()

    def rollback(self) -> None:
        """Roll back the current transaction."""
        self._connection.rollback()

    def close(self) -> None:
        """Close the underlying connection."""
        self._connection.close()

    @property
    def row_factory(self) -> Any:
        """Row factory property for sqlite3 compatibility.

        Not used for MySQL (RowWrapper handles row access), but provided
        so that code checking conn.row_factory does not raise AttributeError.
        """
        return self._row_factory

    @row_factory.setter
    def row_factory(self, value: Any) -> None:
        """Set row_factory (accepted for compatibility, not used internally)."""
        self._row_factory = value

    def cursor(self) -> CursorWrapper:
        """Return a new wrapped cursor."""
        import mysql.connector  # noqa: F401 — lazy import

        return CursorWrapper(self._connection.cursor())
