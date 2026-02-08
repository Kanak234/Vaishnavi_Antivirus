"""Quarantine helpers (copies found files to quarantine_vault)."""
import shutil
from pathlib import Path
from .config import QUARANTINE_DIR

def move_to_quarantine(path: Path, logger=None) -> Path | None:
    dest = QUARANTINE_DIR / path.name
    try:
        shutil.copy2(path, dest)
        if logger:
            logger.info("Quarantined %s -> %s", path, dest)
        return dest
    except Exception as e:
        if logger:
            logger.error("Failed to quarantine %s: %s", path, e)
        return None
