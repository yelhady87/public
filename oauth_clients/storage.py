import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

STORAGE_FILE = Path(__file__).parent / "data" / "clients.json"


def load_clients() -> list[dict]:
    if not STORAGE_FILE.exists():
        return []
    with STORAGE_FILE.open() as f:
        return json.load(f)


def save_client(client: dict) -> dict:
    clients = load_clients()
    record = {
        "id": str(uuid.uuid4()),
        "registered_at": datetime.now(timezone.utc).isoformat(),
        **client,
    }
    clients.append(record)
    with STORAGE_FILE.open("w") as f:
        json.dump(clients, f, indent=2)
    return record


def update_client_redirect_uris(client_id: str, redirect_uris: list[str], pat: str) -> dict | None:
    clients = load_clients()
    for record in clients:
        if record.get("client_id") == client_id:
            record["redirect_uris"] = redirect_uris
            record["pat"] = pat
            with STORAGE_FILE.open("w") as f:
                json.dump(clients, f, indent=2)
            return record
    return None
