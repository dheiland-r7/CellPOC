"""Terminal presentation helpers for CatSocks."""

from __future__ import annotations

import os
import sys

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"


def color_enabled(stream=None) -> bool:
    """Return True when ANSI color should be emitted to the selected stream."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    stream = stream or sys.stderr
    return bool(getattr(stream, "isatty", lambda: False)())


def green(text: str, stream=None) -> str:
    """Render text in green on a color-capable terminal."""
    if not color_enabled(stream):
        return text
    return f"{ANSI_GREEN}{text}{ANSI_RESET}"


def red(text: str, stream=None) -> str:
    """Render text in red on a color-capable terminal."""
    if not color_enabled(stream):
        return text
    return f"{ANSI_RED}{text}{ANSI_RESET}"
