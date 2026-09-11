"""Configuration settings for Vaishnavi Antivirus."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Check explicit env var first
if "VAISHNAVI_QUARANTINE_DIR" in os.environ:
    QUARANTINE_DIR = Path(os.environ["VAISHNAVI_QUARANTINE_DIR"])
else:
    # If in local repo checkout, use local quarantine_vault
    local_repo_vault = BASE_DIR.parent / "quarantine_vault"
    is_repo = (
        (BASE_DIR.parent / "Vaishnavi_Antivirus_Full_GUI").exists()
        or (BASE_DIR.parent.parent / "pyproject.toml").exists()
    )
    if is_repo:
        QUARANTINE_DIR = local_repo_vault

    else:
        # In installed environment, default to current working directory
        QUARANTINE_DIR = Path.cwd() / "quarantine_vault"

try:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass
