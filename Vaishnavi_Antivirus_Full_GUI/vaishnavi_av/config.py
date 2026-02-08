from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
QUARANTINE_DIR = BASE_DIR.parent / "quarantine_vault"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
