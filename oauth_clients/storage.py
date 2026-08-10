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


def update_client_redirect_uris(
    client_id: str,
    redirect_uris: list[str],
    registration_access_token: str | None = None,
) -> dict | None:
    clients = load_clients()
    for record in clients:
        if record.get("client_id") == client_id:
            record["redirect_uris"] = redirect_uris
            if registration_access_token:
                record["registration_access_token"] = registration_access_token
            with STORAGE_FILE.open("w") as f:
                json.dump(clients, f, indent=2)
            return record
    return None


def import_clients(records: list[dict]) -> dict:
    if not records:
        return {"imported": [], "skipped": []}

    clients = load_clients()
    existing_client_ids = {c.get("client_id") for c in clients}
    used_ids = {c.get("id") for c in clients}

    imported: list[dict] = []
    skipped: list[dict] = []

    for rec in records:
        client_id = rec.get("client_id")
        client_name = rec.get("client_name")
        if client_id and client_id in existing_client_ids:
            skipped.append({
                "client_id": client_id,
                "client_name": client_name,
                "reason": "duplicate client_id",
            })
            continue

        record_id = rec.get("id")
        if not record_id or record_id in used_ids:
            record_id = str(uuid.uuid4())
        used_ids.add(record_id)

        if not rec.get("registered_at"):
            rec["registered_at"] = datetime.now(timezone.utc).isoformat()

        rec["id"] = record_id
        clients.append(rec)
        if client_id:
            existing_client_ids.add(client_id)
        imported.append(rec)

    with STORAGE_FILE.open("w") as f:
        json.dump(clients, f, indent=2)

    return {"imported": imported, "skipped": skipped}
