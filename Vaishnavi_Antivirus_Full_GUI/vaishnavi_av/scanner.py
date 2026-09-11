"""Core scanning engine (walks files, applies signature + heuristics)."""

from __future__ import annotations

import logging
from pathlib import Path

from .heuristics import simple_heuristic
from .quarantine import move_to_quarantine
from .signatures import match


def scan_path(
    target: str | Path,
    logger: logging.Logger | None = None,
    max_files: int = 1000,
    quarantine_dir: Path | None = None,
) -> list[dict[str, str]]:
    """Scan a file or directory recursively for malware signatures and heuristics."""
    p = Path(target)
    findings: list[dict[str, str]] = []
    if not p.exists():
        if logger:
            logger.error("Target path does not exist: %s", p)
        return findings

    if p.is_file():
        targets = [p]
    else:
        targets = [t for t in p.rglob("*") if t.is_file()]

    count = 0
    for t in targets:
        count += 1
        if count > max_files:
            if logger:
                logger.info("Scan reached maximum file limit (%d)", max_files)
            break
        try:
            if match(t):
                findings.append({"path": str(t), "reason": "signature"})
                move_to_quarantine(t, logger=logger, quarantine_dir=quarantine_dir)
                if logger:
                    logger.warning("Threat detected (signature): %s", t)
            elif simple_heuristic(t):
                findings.append({"path": str(t), "reason": "heuristic"})
                move_to_quarantine(t, logger=logger, quarantine_dir=quarantine_dir)
                if logger:
                    logger.warning("Threat detected (heuristic): %s", t)
        except Exception as e:
            if logger:
                logger.error("Error scanning %s: %s", t, e)
    return findings
