"""General utilities (placeholders for future helpers)."""

from pathlib import Path


def is_text_file(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(512)
            return b"\x00" not in chunk
    except Exception:
        return False
