import json
from datetime import datetime, timezone
from pathlib import Path

from config import DATA_DIR, STORAGE_FILE


def load_registration() -> dict | None:
    if not STORAGE_FILE.exists():
        return None
    with STORAGE_FILE.open() as f:
        return json.load(f)


def save_registration(record: dict) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    record["registered_at"] = datetime.now(timezone.utc).isoformat()
    with STORAGE_FILE.open("w") as f:
        json.dump(record, f, indent=2)
    return record


def _storage_path() -> Path:
    return STORAGE_FILE
