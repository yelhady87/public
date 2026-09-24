import json
import logging

import httpx
from fastapi import HTTPException

from config import (
    CLIENT_NAME,
    CLIENT_NAME_FILE,
    CLIENT_SCOPES,
    INITIAL_ACCESS_TOKEN,
)
from discovery import get_discovery
from storage import load_registration, save_registration

logger = logging.getLogger(__name__)

GRANT_TYPES = ["authorization_code", "refresh_token"]
TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_post"

# Current client name for the registration payload. Mutable at runtime via
# set_client_name(); defaults to the env-configured CLIENT_NAME.
_client_name: str = CLIENT_NAME


def _load_persisted_name() -> str | None:
    try:
        if CLIENT_NAME_FILE.exists():
            with CLIENT_NAME_FILE.open() as f:
                data = json.load(f)
            name = data.get("client_name")
            return name if isinstance(name, str) and name.strip() else None
    except (OSError, ValueError) as exc:
        logger.warning("Could not read persisted client name: %s", exc)
    return None


def _persist_name(name: str) -> None:
    try:
        CLIENT_NAME_FILE.parent.mkdir(parents=True, exist_ok=True)
        with CLIENT_NAME_FILE.open("w") as f:
            json.dump({"client_name": name}, f, indent=2)
    except OSError as exc:
        logger.warning("Could not persist client name: %s", exc)


_persisted_name = _load_persisted_name()
if _persisted_name:
    _client_name = _persisted_name


def get_client_name() -> str:
    """Return the client name currently used in registration payloads."""
    return _client_name


def set_client_name(name: str, *, persist: bool = True) -> str:
    """Set the client name used when registering. Stored verbatim."""
    global _client_name
    name = (name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="client_name is required")
    _client_name = name
    if persist:
        _persist_name(name)
    logger.info("Client name updated to %s", name)
    return name


async def get_client_registration(
    redirect_uri: str,
    force: bool = False,
    client_name: str | None = None,
) -> dict:
    """Return the registered client, dynamically registering it if needed (RFC 7591).

    ``client_name`` overrides the runtime-configured name for this registration
    request only (it is not persisted unless set via set_client_name()).
    """
    if not force:
        existing = load_registration()
        if existing:
            return existing

    name = client_name or _client_name
    discovery = await get_discovery(force=True)
    endpoint = discovery["registration_endpoint"]

    body = {
        "client_name": name,
        "redirect_uris": [redirect_uri],
        "grant_types": GRANT_TYPES,
        "token_endpoint_auth_method": TOKEN_ENDPOINT_AUTH_METHOD,
        "scope": CLIENT_SCOPES,
    }

    headers = {"Content-Type": "application/json"}
    if INITIAL_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {INITIAL_ACCESS_TOKEN}"

    logger.info("Dynamically registering client at %s (redirect_uri=%s)", endpoint, redirect_uri)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(endpoint, headers=headers, json=body, timeout=60.0)
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not reach registration endpoint: {exc}",
            )

    trace_id = resp.headers.get("trace-id")
    if not resp.is_success:
        logger.error(
            "Dynamic registration failed: status=%s trace_id=%s body=%s",
            resp.status_code, trace_id, resp.text,
        )
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"Dynamic registration returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )

    data = resp.json()
    client_id = data.get("client_id")
    if not client_id:
        logger.error("Registration response missing 'client_id'. trace_id=%s body=%s", trace_id, resp.text)
        raise HTTPException(
            status_code=502,
            detail={"message": "Registration response missing 'client_id'", "trace_id": trace_id},
        )

    record = save_registration({
        "client_id": client_id,
        "client_secret": data.get("client_secret"),
        "registration_access_token": data.get("registration_access_token"),
        "registration_client_uri": data.get("registration_client_uri"),
        "redirect_uris": data.get("redirect_uris") or [redirect_uri],
        "grant_types": data.get("grant_types") or GRANT_TYPES,
        "token_endpoint_auth_method": data.get("token_endpoint_auth_method") or TOKEN_ENDPOINT_AUTH_METHOD,
        "scope": data.get("scope") or CLIENT_SCOPES,
        "client_name": name,
        "issuer": discovery.get("issuer"),
        "oidc_discovery_url": None,
        "trace_id": trace_id,
    })
    logger.info("Client registered successfully: client_id=%s trace_id=%s", client_id, trace_id)
    return record
