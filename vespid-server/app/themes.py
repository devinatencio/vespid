"""Theme management — built-in themes and custom theme loading.

Provides discovery of built-in themes and loads additional user-defined
themes from a configurable directory on the filesystem.

Built-in theme files (nord.css, vespid.css) live in static/themes/ and
are loaded automatically. Users can override them by placing a file with
the same name in their CUSTOM_THEME_DIR.

Custom theme files should be named <theme_name>.css and contain a complete
CSS rule block targeting body.theme-<theme_name>, for example:

    body.theme-mytheme {
        --bg: #000000;
        --bg-card: #111111;
        --text: #ffffff;
        --accent: #ff0000;
        ...
    }
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

BUILTIN_THEMES = frozenset(
    {"dark", "light", "nord", "vespid", "catppuccin-mocha", "catppuccin-latte"}
)

# Directory containing the shipped theme CSS files (static/themes/)
_BUILTIN_THEMES_DIR = os.path.join(os.path.dirname(__file__), "static", "themes")


def _is_theme_file(entry) -> bool:
    """True for real .css files, excluding macOS AppleDouble companions
    (._name.css) that can appear when the tree is copied through non-HFS
    media."""
    return entry.is_file() and entry.name.endswith(".css") and not entry.name.startswith("._")


def discover_custom_themes(theme_dir: str | None) -> list[str]:
    """Scan a directory for custom theme .css files.

    Args:
        theme_dir: Path to the custom themes directory, or None.

    Returns:
        A list of theme names (filename stems) found in the directory.
    """
    if not theme_dir or not os.path.isdir(theme_dir):
        return []

    themes: list[str] = []
    for entry in os.scandir(theme_dir):
        if _is_theme_file(entry):
            name = entry.name[: -len(".css")]
            if name and name.isascii() and "/" not in name and "\\" not in name:
                themes.append(name)

    return sorted(themes)


def get_all_themes(theme_dir: str | None = None) -> list[str]:
    """Return all valid theme names (built-in + custom).

    Args:
        theme_dir: Path to the custom themes directory, or None.

    Returns:
        A sorted list of all valid theme names.
    """
    custom = discover_custom_themes(theme_dir)
    all_themes = set(BUILTIN_THEMES) | set(custom)
    return sorted(all_themes)


def get_custom_theme_css(theme_dir: str | None) -> str:
    """Read and concatenate all theme .css files (built-in + custom).

    Built-in theme files from static/themes/ are loaded first. If a custom
    theme directory is configured, those files are loaded after and will
    override built-in themes of the same name.

    Args:
        theme_dir: Path to the custom themes directory, or None.

    Returns:
        Concatenated CSS string, or empty string if no themes found.
    """
    parts: list[str] = []
    loaded_names: set[str] = set()

    # Determine which built-in theme files to skip (overridden by custom)
    custom_names: set[str] = set()
    if theme_dir and os.path.isdir(theme_dir):
        for entry in os.scandir(theme_dir):
            if _is_theme_file(entry):
                custom_names.add(entry.name[: -len(".css")])

    # Load built-in theme files (skip if overridden by custom)
    if os.path.isdir(_BUILTIN_THEMES_DIR):
        for entry in sorted(os.scandir(_BUILTIN_THEMES_DIR), key=lambda e: e.name):
            if _is_theme_file(entry):
                name = entry.name[: -len(".css")]
                if name in custom_names:
                    continue  # custom override takes precedence
                try:
                    with open(entry.path, encoding="utf-8") as f:
                        css = f.read()
                    if css.strip():
                        parts.append(css)
                        loaded_names.add(name)
                except (OSError, UnicodeDecodeError) as exc:
                    logger.warning("Failed to read built-in theme %s: %s", entry.name, exc)

    # Load custom theme files
    if theme_dir and os.path.isdir(theme_dir):
        for entry in sorted(os.scandir(theme_dir), key=lambda e: e.name):
            if _is_theme_file(entry):
                try:
                    with open(entry.path, encoding="utf-8") as f:
                        css = f.read()
                    if css.strip():
                        parts.append(css)
                except (OSError, UnicodeDecodeError) as exc:
                    logger.warning("Failed to read custom theme %s: %s", entry.name, exc)

    return "\n\n".join(parts)
