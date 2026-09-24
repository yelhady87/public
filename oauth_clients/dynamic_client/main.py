# Dynamic OIDC Demo Client
#
# Registers itself on the OAuth server using RFC 7591 dynamic client
# registration (discovered via the OpenID Connect discovery document),
# then runs the authorization-code flow with PKCE.
#
# Run:
#   pip install -r requirements.txt
#   uvicorn main:app --reload --port 8100
#   Open http://localhost:8100

import logging
import secrets
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from config import (
    CLIENT_SCOPES,
    PUBLIC_BASE_URL,
    SESSION_COOKIE,
    STORAGE_FILE,
)
from discovery import get_discovery, get_discovery_url, set_discovery_url
from oidc import (
    build_authorization_url,
    code_challenge_from_verifier,
    decode_id_token,
    exchange_code,
    generate_code_verifier,
    generate_state,
    refresh_tokens,
)
from registration import get_client_registration, get_client_name, set_client_name
from storage import load_registration

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Dynamic OIDC Demo Client")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def callback_url() -> str:
    return f"{PUBLIC_BASE_URL.rstrip('/')}/callback"


# ---- Session store (in-memory; restart clears tokens but not registration) ----
_sessions: dict[str, dict] = {}


def _get_session(request: Request) -> dict | None:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    return _sessions.get(session_id)


def _create_session() -> tuple[str, dict]:
    session_id = secrets.token_urlsafe(32)
    session: dict = {}
    _sessions[session_id] = session
    return session_id, session


@app.on_event("startup")
async def on_startup():
    if not STORAGE_FILE.exists():
        try:
            record = await get_client_registration(callback_url())
            logger.info("Dynamically registered on startup: client_id=%s", record["client_id"])
        except HTTPException as exc:
            logger.warning("Startup registration skipped: %s", exc.detail)


# ---- Pages ----

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/login")
async def login(request: Request):
    record = await get_client_registration(callback_url())
    discovery = await get_discovery()

    verifier = generate_code_verifier()
    state = generate_state()
    session_id, session = _create_session()
    session["state"] = state
    session["code_verifier"] = verifier
    session["redirect_uri"] = callback_url()

    auth_url = build_authorization_url(
        discovery,
        client_id=record["client_id"],
        redirect_uri=callback_url(),
        scope=CLIENT_SCOPES,
        state=state,
        code_challenge=code_challenge_from_verifier(verifier),
    )

    response = RedirectResponse(auth_url, status_code=302)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    return response


@app.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    session = _get_session(request)
    if session is None:
        raise HTTPException(status_code=400, detail="No login session found. Start again from /login.")

    if error:
        session.clear()
        raise HTTPException(status_code=400, detail=f"Authorization failed: {error}")

    if not code:
        session.clear()
        raise HTTPException(status_code=400, detail="Authorization response missing 'code'")

    if state and state != session.get("state"):
        session.clear()
        raise HTTPException(status_code=400, detail="State mismatch — possible CSRF.")

    record = await get_client_registration(callback_url())
    discovery = await get_discovery()

    try:
        token_data = await exchange_code(
            discovery,
            client_id=record["client_id"],
            client_secret=record.get("client_secret"),
            code=code,
            redirect_uri=callback_url(),
            code_verifier=session["code_verifier"],
        )
    except HTTPException:
        session.clear()
        raise

    id_token = token_data.get("id_token")
    if id_token:
        token_data["id_token_claims"] = await decode_id_token(id_token, discovery, record["client_id"])

    session["tokens"] = token_data
    session.pop("code_verifier", None)
    session.pop("state", None)

    return RedirectResponse("/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id and session_id in _sessions:
        del _sessions[session_id]
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---- API ----

@app.get("/api/registration")
async def api_registration():
    record = load_registration()
    if record is None:
        raise HTTPException(status_code=404, detail="Client is not registered yet")
    return record


@app.post("/api/register")
async def api_register():
    return await get_client_registration(callback_url(), force=True)


@app.get("/api/discovery")
async def api_discovery():
    return await get_discovery()


@app.get("/api/discovery/config")
async def api_get_discovery_config():
    return {"discovery_url": get_discovery_url()}


@app.put("/api/discovery/config")
async def api_put_discovery_config(payload: dict):
    url = (payload or {}).get("discovery_url")
    if not url or not str(url).strip():
        raise HTTPException(status_code=400, detail="discovery_url is required")
    try:
        normalized = set_discovery_url(str(url))
    except HTTPException:
        raise
    # Refetch so the UI reflects the new provider immediately.
    await get_discovery(force=True)
    return {"discovery_url": normalized}


@app.get("/api/registration/config")
async def api_get_registration_config():
    return {"client_name": get_client_name()}


@app.put("/api/registration/config")
async def api_put_registration_config(payload: dict):
    name = (payload or {}).get("client_name")
    try:
        normalized = set_client_name(str(name) if name is not None else "")
    except HTTPException:
        raise
    return {"client_name": normalized}


@app.get("/api/session")
async def api_session(request: Request):
    session = _get_session(request)
    if session is None or not session.get("tokens"):
        return None
    tokens = session["tokens"]
    return {
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "token_type": tokens.get("token_type"),
        "expires_in": tokens.get("expires_in"),
        "scope": tokens.get("scope"),
        "id_token": tokens.get("id_token"),
        "id_token_claims": tokens.get("id_token_claims"),
        "trace_id": tokens.get("trace_id"),
    }


@app.post("/api/refresh")
async def api_refresh(request: Request):
    session = _get_session(request)
    if session is None or not session.get("tokens"):
        raise HTTPException(status_code=401, detail="No active session")

    record = load_registration()
    if record is None:
        raise HTTPException(status_code=404, detail="Client is not registered yet")

    refresh_token = session["tokens"].get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="No refresh token available in the current session")

    discovery = await get_discovery()
    token_data = await refresh_tokens(
        discovery,
        client_id=record["client_id"],
        client_secret=record.get("client_secret"),
        refresh_token=refresh_token,
    )

    id_token = token_data.get("id_token")
    if id_token:
        token_data["id_token_claims"] = await decode_id_token(id_token, discovery, record["client_id"])

    session["tokens"] = token_data
    return {"message": "Tokens refreshed"}
