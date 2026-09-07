"""Core scanning engine (walks files, applies signature + heuristics)."""

from pathlib import Path

from .heuristics import simple_heuristic
from .quarantine import move_to_quarantine
from .signatures import match


def scan_path(target, logger=None, max_files=1000):
    p = Path(target)
    findings = []
    if p.is_file():
        targets = [p]
    else:
        targets = list(p.rglob("*"))
    count = 0
    for t in targets:
        if not t.is_file():
            continue
        count += 1
        if count > max_files:
            break
        try:
            if match(t):
                findings.append({"path": str(t), "reason": "signature"})
                move_to_quarantine(t, logger=logger)
                if logger:
                    logger.warning("Threat detected (signature): %s", t)
            elif simple_heuristic(t):
                findings.append({"path": str(t), "reason": "heuristic"})
                move_to_quarantine(t, logger=logger)
                if logger:
                    logger.warning("Threat detected (heuristic): %s", t)
        except Exception as e:
            if logger:
                logger.error("Error scanning %s: %s", t, e)
    return findings
