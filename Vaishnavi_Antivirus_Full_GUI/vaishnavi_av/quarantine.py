"""Quarantine helpers (copies found files to quarantine_vault)."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from .config import QUARANTINE_DIR


def move_to_quarantine(
    path: Path,
    logger: logging.Logger | None = None,
    quarantine_dir: Path | None = None,
) -> Path | None:
    """Copy a detected threat file to the secure quarantine vault.

    Args:
        path: Path to the threat file to quarantine.
        logger: Optional logger for telemetry messages.
        quarantine_dir: Optional override directory for quarantine storage.

    Returns:
        Path to the quarantined file on success, or None on error.
    """
    target_dir = quarantine_dir or QUARANTINE_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / Path(path).name
    try:
        shutil.copy2(path, dest)
        if logger:
            logger.info("Quarantined %s -> %s", path, dest)
        return dest
    except Exception as e:
        if logger:
            logger.error("Failed to quarantine %s: %s", path, e)
        return None
