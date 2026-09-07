"""Signature-based detection helpers (minimal example)."""

import hashlib
from pathlib import Path

# Small sample signature DB (md5 values). Expand this to real DB later.
SAMPLE_SIGNATURES = {"eicar-test-file": "44d88612fea8a8f36de82e1278abb02f"}


def file_hash(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def match(path: Path) -> bool:
    try:
        return file_hash(path) in SAMPLE_SIGNATURES.values()
    except Exception:
        return False
