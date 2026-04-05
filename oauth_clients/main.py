# OAuth Client Registration App
#
# Run:
#   pip install -r requirements.txt
#   uvicorn main:app --reload
#   Open http://localhost:8000

import logging
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from storage import load_clients, save_client, update_client_redirect_uris

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="OAuth Client Registration")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


class RegisterClientRequest(BaseModel):
    tenant: str
    oauth_server_url: str
    pat: str
    client_name: str
    redirect_uris: list[str]
    grant_types: list[str]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/api/clients")
async def register_client(payload: RegisterClientRequest):
    base = payload.oauth_server_url.rstrip("/")
    # endpoint = f"{base}/{payload.tenant}/clients"
    endpoint = f"{base}/oauth/{payload.tenant}/register" # base -> host/incorta

    logger.info(
        "Registering client '%s' for tenant '%s' at %s",
        payload.client_name, payload.tenant, endpoint,
    )

    logger.info("Request payload: %s", payload.dict(exclude={"pat": True}))

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                endpoint,
                headers={
                    'Content-Type': 'application/json',
                    "Authorization": f"Bearer {payload.pat}"
                },
                json={
                    "client_name": payload.client_name,
                    "redirect_uris": payload.redirect_uris,
                    "grant_types": payload.grant_types,
                    "scope": "openid",
                },
                timeout=15.0,
            )
        except httpx.RequestError as exc:
            logger.exception("HTTP request to %s failed", endpoint)
            raise HTTPException(
                status_code=502,
                detail={"message": f"Could not reach OAuth server: {exc}", "trace_id": None},
            )

    trace_id = resp.headers.get("trace-id")
    logger.info(
        "OAuth server responded: status=%s trace_id=%s",
        resp.status_code, trace_id,
    )

    if not resp.is_success:
        logger.error(
            "OAuth server error: status=%s trace_id=%s body=%s",
            resp.status_code, trace_id, resp.text,
        )
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"OAuth server returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )

    logger.info(f"OAuth server response: {resp.text}")
    data = resp.json()
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")

    if not client_id:
        logger.error("OAuth server response missing 'client_id'. trace_id=%s body=%s", trace_id, resp.text)
        raise HTTPException(
            status_code=502,
            detail={"message": "OAuth server response missing 'client_id'", "trace_id": trace_id},
        )

    logger.info(
        "Client registered successfully: client_id=%s tenant=%s trace_id=%s",
        client_id, payload.tenant, trace_id,
    )

    record = save_client(
        {
            "tenant": payload.tenant,
            "oauth_server_url": payload.oauth_server_url,
            "client_name": payload.client_name,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": payload.redirect_uris,
            "grant_types": payload.grant_types,
            "oidc_discovery_url": f"{base}/oauth/{payload.tenant}/.well-known/openid-configuration",
            "trace_id": trace_id,
        }
    )
    return record


@app.get("/api/clients")
async def list_clients():
    return load_clients()


@app.get("/api/clients/{record_id}")
async def get_client(record_id: str):
    clients = load_clients()
    for c in clients:
        if c.get("id") == record_id:
            return c
    raise HTTPException(status_code=404, detail="Client not found")


class AddRedirectUriRequest(BaseModel):
    pat: str
    new_redirect_uri: str


@app.put("/api/clients/{client_id}/redirect-uris")
async def add_redirect_uri(client_id: str, payload: AddRedirectUriRequest):
    # Look up client locally to get tenant, base URL, and existing redirect_uris
    clients = load_clients()
    record = next((c for c in clients if c.get("client_id") == client_id), None)
    if record is None:
        raise HTTPException(status_code=404, detail="Client not found")

    base = record["oauth_server_url"].rstrip("/")
    tenant = record["tenant"]
    endpoint = f"{base}/oauth/{tenant}/register"

    existing = record.get("redirect_uris") or []
    merged = list(dict.fromkeys(existing + [payload.new_redirect_uri]))  # deduplicate, preserve order

    logger.info(
        "Adding redirect URI to client_id=%s tenant=%s endpoint=%s new_uri=%s",
        client_id, tenant, endpoint, payload.new_redirect_uri,
    )

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.put(
                endpoint,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {payload.pat}",
                },
                json={"client_id": client_id, "redirect_uris": merged},
                timeout=15.0,
            )
        except httpx.RequestError as exc:
            logger.exception("HTTP PUT to %s failed", endpoint)
            raise HTTPException(
                status_code=502,
                detail={"message": f"Could not reach OAuth server: {exc}", "trace_id": None},
            )

    trace_id = resp.headers.get("trace-id")
    logger.info("OAuth server PUT responded: status=%s trace_id=%s", resp.status_code, trace_id)

    if not resp.is_success:
        logger.error(
            "OAuth server PUT error: status=%s trace_id=%s body=%s",
            resp.status_code, trace_id, resp.text,
        )
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"OAuth server returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )

    updated = update_client_redirect_uris(client_id, merged)
    logger.info("Redirect URIs updated locally for client_id=%s trace_id=%s", client_id, trace_id)
    updated["trace_id"] = trace_id
    return updated
