"""Simple heuristic checks to flag suspicious files."""

from pathlib import Path


def simple_heuristic(path: Path) -> bool:
    name = path.name.lower()
    # Filename-based heuristics (expand with real checks later)
    if "malware" in name or "virus" in name:
        return True
    try:
        if path.stat().st_size == 0:
            return True
    except Exception:
        return False
    return False
