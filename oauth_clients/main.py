# OAuth Client Registration App
#
# Run:
#   pip install -r requirements.txt
#   uvicorn main:app --reload
#   Open http://localhost:8000

import csv
import io
import logging
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.requests import Request

from delta_proxy import router as delta_router
from storage import (
    load_clients,
    save_client,
    update_client_redirect_uris,
    import_clients as bulk_import_clients,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="OAuth Client Registration")
app.include_router(delta_router)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


class RegisterClientRequest(BaseModel):
    tenant: str
    oauth_server_url: str
    pat: str | None = None
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

    headers = {"Content-Type": "application/json"}
    if payload.pat:
        headers["Authorization"] = f"Bearer {payload.pat}"

    request_body = {
        "client_name": payload.client_name,
        "redirect_uris": payload.redirect_uris,
        "grant_types": payload.grant_types,
        "scope": "openid",
    }
    logger.info("POST %s request body: %s", endpoint, request_body)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                endpoint,
                headers=headers,
                json=request_body,
                timeout=300.0,
            )
        except httpx.RequestError as exc:
            logger.exception("HTTP request to %s failed", endpoint)
            raise HTTPException(
                status_code=502,
                detail={"message": f"Could not reach OAuth server: {exc}", "trace_id": None},
            )

    trace_id = resp.headers.get("trace-id")
    logger.info(
        "POST %s response: status=%s trace_id=%s body=%s",
        endpoint, resp.status_code, trace_id, resp.text,
    )

    if not resp.is_success:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"OAuth server returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )
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

    registration_access_token = data.get("registration_access_token")
    registration_client_uri = data.get("registration_client_uri")

    record = save_client(
        {
            "tenant": payload.tenant,
            "oauth_server_url": payload.oauth_server_url,
            "pat": payload.pat,
            "client_name": payload.client_name,
            "client_id": client_id,
            "client_secret": client_secret,
            "registration_access_token": registration_access_token,
            "registration_client_uri": registration_client_uri,
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


IMPORT_REQUIRED_COLUMNS = [
    "tenant", "oauth_server_url", "pat", "client_name", "client_id",
    "client_secret", "registration_access_token", "registration_client_uri",
    "redirect_uris", "grant_types", "oidc_discovery_url", "registered_at",
]


@app.post("/api/clients/import")
async def import_clients(file: UploadFile):
    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail={"message": f"CSV file is not valid UTF-8: {exc}", "trace_id": None},
        )

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(
            status_code=400,
            detail={"message": "CSV file is empty or has no header row", "trace_id": None},
        )

    missing = [c for c in IMPORT_REQUIRED_COLUMNS if c not in reader.fieldnames]
    if missing:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"CSV missing required columns: {', '.join(missing)}",
                "missing": missing,
                "trace_id": None,
            },
        )

    def split_semi(value: str | None) -> list[str]:
        return [s.strip() for s in (value or "").split(";") if s.strip()]

    def nullable(value: str | None) -> str | None:
        v = (value or "").strip()
        return v or None

    def text(value: str | None) -> str:
        return (value or "").strip()

    parsed: list[dict] = []
    for row in reader:
        parsed.append({
            "id": nullable(row.get("id")),
            "registered_at": text(row.get("registered_at")),
            "tenant": text(row.get("tenant")),
            "oauth_server_url": text(row.get("oauth_server_url")),
            "pat": nullable(row.get("pat")),
            "client_name": text(row.get("client_name")),
            "client_id": text(row.get("client_id")),
            "client_secret": nullable(row.get("client_secret")),
            "registration_access_token": nullable(row.get("registration_access_token")),
            "registration_client_uri": nullable(row.get("registration_client_uri")),
            "redirect_uris": split_semi(row.get("redirect_uris")),
            "grant_types": split_semi(row.get("grant_types")),
            "oidc_discovery_url": nullable(row.get("oidc_discovery_url")),
        })

    logger.info("Importing %d client rows from CSV upload", len(parsed))
    result = bulk_import_clients(parsed)
    logger.info(
        "Import complete: imported=%d skipped=%d",
        len(result["imported"]), len(result["skipped"]),
    )
    return {
        "imported_count": len(result["imported"]),
        "skipped_count": len(result["skipped"]),
        "skipped": result["skipped"],
    }


@app.get("/api/clients/{record_id}")
async def get_client(record_id: str):
    clients = load_clients()
    for c in clients:
        if c.get("id") == record_id:
            return c
    raise HTTPException(status_code=404, detail="Client not found")


@app.get("/api/clients/{client_id}/definition")
async def get_client_definition(client_id: str):
    clients = load_clients()
    record = next((c for c in clients if c.get("client_id") == client_id), None)
    if record is None:
        raise HTTPException(status_code=404, detail="Client not found")

    registration_access_token = record.get("registration_access_token")
    if not registration_access_token:
        raise HTTPException(
            status_code=400,
            detail={"message": "No registration_access_token stored for this client", "trace_id": None},
        )

    endpoint = record.get("registration_client_uri") or f"{record['oauth_server_url'].rstrip('/')}/oauth/{record['tenant']}/register/{client_id}"
    logger.info("GET %s (client definition)", endpoint)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                endpoint,
                headers={"Authorization": f"Bearer {registration_access_token}"},
                timeout=30.0,
            )
        except httpx.RequestError as exc:
            logger.exception("HTTP GET to %s failed", endpoint)
            raise HTTPException(
                status_code=502,
                detail={"message": f"Could not reach OAuth server: {exc}", "trace_id": None},
            )

    trace_id = resp.headers.get("trace-id")
    logger.info("GET %s response: status=%s trace_id=%s body=%s", endpoint, resp.status_code, trace_id, resp.text)

    if not resp.is_success:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"OAuth server returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )

    return resp.json()


class AddRedirectUriRequest(BaseModel):
    new_redirect_uri: str


@app.put("/api/clients/{client_id}/redirect-uris")
async def add_redirect_uri(client_id: str, payload: AddRedirectUriRequest):
    clients = load_clients()
    record = next((c for c in clients if c.get("client_id") == client_id), None)
    if record is None:
        raise HTTPException(status_code=404, detail="Client not found")

    registration_access_token = record.get("registration_access_token")
    if not registration_access_token:
        raise HTTPException(
            status_code=400,
            detail={"message": "No registration_access_token stored for this client", "trace_id": None},
        )

    # RFC 7592: use registration_client_uri if available, fall back to reconstructed URL
    endpoint = record.get("registration_client_uri") or f"{record['oauth_server_url'].rstrip('/')}/oauth/{record['tenant']}/register/{client_id}"

    existing = record.get("redirect_uris") or []
    merged = list(dict.fromkeys(existing + [payload.new_redirect_uri]))  # deduplicate, preserve order

    logger.info(
        "Adding redirect URI to client_id=%s endpoint=%s new_uri=%s",
        client_id, endpoint, payload.new_redirect_uri,
    )

    # RFC 7592 §2.2: PUT body must be the full client metadata, not a partial update
    request_body = {
        "client_id": client_id,
        "client_name": record["client_name"],
        "redirect_uris": merged,
        "grant_types": record.get("grant_types", []),
        "scope": "openid",
    }
    logger.info("PUT %s request body: %s", endpoint, request_body)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.put(
                endpoint,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {registration_access_token}",
                },
                json=request_body,
                timeout=300.0,
            )
        except httpx.RequestError as exc:
            logger.exception("HTTP PUT to %s failed", endpoint)
            raise HTTPException(
                status_code=502,
                detail={"message": f"Could not reach OAuth server: {exc}", "trace_id": None},
            )

    trace_id = resp.headers.get("trace-id")
    logger.info(
        "PUT %s response: status=%s trace_id=%s body=%s",
        endpoint, resp.status_code, trace_id, resp.text,
    )

    if not resp.is_success:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"OAuth server returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )

    # RFC 7592: server may rotate the registration_access_token in the PUT response
    rotated_token = None
    if resp.content:
        response_data = resp.json()
        rotated_token = response_data.get("registration_access_token")
    if rotated_token:
        logger.info("registration_access_token rotated for client_id=%s", client_id)

    updated = update_client_redirect_uris(client_id, merged, rotated_token)
    logger.info("Redirect URIs updated locally for client_id=%s trace_id=%s", client_id, trace_id)
    updated["trace_id"] = trace_id
    return updated


class GenerateTokenRequest(BaseModel):
    oauth_server_url: str
    tenant: str
    token_endpoint: str | None = None
    client_id: str
    client_secret: str
    grant_type: str
    scope: str | None = None
    code: str | None = None
    redirect_uri: str | None = None
    refresh_token: str | None = None


@app.post("/api/tokens")
async def generate_token(payload: GenerateTokenRequest):
    base = payload.oauth_server_url.rstrip("/")
    endpoint = payload.token_endpoint or f"{base}/oauth/{payload.tenant}/token"

    logger.info(
        "Generating token for client_id=%s tenant=%s grant_type=%s",
        payload.client_id, payload.tenant, payload.grant_type,
    )

    form_data: dict[str, str] = {
        "grant_type": payload.grant_type,
        "client_id": payload.client_id,
        "client_secret": payload.client_secret,
    }
    if payload.scope:
        form_data["scope"] = payload.scope
    if payload.grant_type == "authorization_code":
        if not payload.code:
            raise HTTPException(
                status_code=400,
                detail={"message": "code is required for authorization_code grant", "trace_id": None},
            )
        form_data["code"] = payload.code
        if payload.redirect_uri:
            form_data["redirect_uri"] = payload.redirect_uri
    elif payload.grant_type == "refresh_token":
        if not payload.refresh_token:
            raise HTTPException(
                status_code=400,
                detail={"message": "refresh_token is required for refresh_token grant", "trace_id": None},
            )
        form_data["refresh_token"] = payload.refresh_token

    logger.info("POST %s request body: %s", endpoint, form_data)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(endpoint, data=form_data, timeout=300.0)
        except httpx.RequestError as exc:
            logger.exception("HTTP request to %s failed", endpoint)
            raise HTTPException(
                status_code=502,
                detail={"message": f"Could not reach OAuth server: {exc}", "trace_id": None},
            )

    trace_id = resp.headers.get("trace-id")
    logger.info(
        "POST %s response: status=%s trace_id=%s body=%s",
        endpoint, resp.status_code, trace_id, resp.text,
    )

    if not resp.is_success:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"OAuth server returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )

    data = resp.json()
    if trace_id:
        data["trace_id"] = trace_id
    logger.info("Token generated successfully for client_id=%s", payload.client_id)
    return data


@app.get("/browse", response_class=HTMLResponse)
async def browse(request: Request):
    return templates.TemplateResponse(request, "browse.html")


class BrowseClientsRequest(BaseModel):
    oauth_server_url: str
    tenant: str
    pat: str


@app.post("/api/browse-clients")
async def browse_clients(payload: BrowseClientsRequest):
    endpoint = f"{payload.oauth_server_url.rstrip('/')}/oauth/{payload.tenant}/clients"
    logger.info("GET %s (browse clients)", endpoint)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                endpoint,
                headers={"Authorization": f"Bearer {payload.pat}"},
                timeout=30.0,
            )
        except httpx.RequestError as exc:
            logger.exception("HTTP GET to %s failed", endpoint)
            raise HTTPException(
                status_code=502,
                detail={"message": f"Could not reach OAuth server: {exc}", "trace_id": None},
            )

    trace_id = resp.headers.get("trace-id")
    logger.info("GET %s response: status=%s trace_id=%s", endpoint, resp.status_code, trace_id)

    if not resp.is_success:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"OAuth server returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )

    return resp.json()
