import base64
import hashlib
import logging
import secrets
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import HTTPException

logger = logging.getLogger(__name__)


def generate_code_verifier() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()


def code_challenge_from_verifier(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def build_authorization_url(
    discovery: dict,
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{discovery['authorization_endpoint']}?{urlencode(params)}"


async def exchange_code(
    discovery: dict,
    *,
    client_id: str,
    client_secret: str | None,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    token_endpoint: str | None = None,
) -> dict:
    endpoint = token_endpoint or discovery["token_endpoint"]
    form: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret:
        form["client_secret"] = client_secret

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(endpoint, data=form, timeout=60.0)
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach token endpoint: {exc}")

    return _handle_token_response(resp, endpoint)


async def refresh_tokens(
    discovery: dict,
    *,
    client_id: str,
    client_secret: str | None,
    refresh_token: str,
    token_endpoint: str | None = None,
) -> dict:
    endpoint = token_endpoint or discovery["token_endpoint"]
    form: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    if client_secret:
        form["client_secret"] = client_secret

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(endpoint, data=form, timeout=60.0)
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach token endpoint: {exc}")

    return _handle_token_response(resp, endpoint)


def _handle_token_response(resp: httpx.Response, endpoint: str) -> dict:
    trace_id = resp.headers.get("trace-id")
    if not resp.is_success:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"Token endpoint {endpoint} returned {resp.status_code}: {resp.text}",
                "trace_id": trace_id,
            },
        )
    data = resp.json()
    if "error" in data:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Token endpoint error: {data.get('error')}: {data.get('error_description', '')}",
                "trace_id": trace_id,
            },
        )
    if trace_id:
        data["trace_id"] = trace_id
    return data


async def decode_id_token(token: str, discovery: dict, client_id: str) -> dict:
    """Verify the ID token against the provider JWKS; fall back to unverified decoding."""
    jwks_uri = discovery.get("jwks_uri")
    if jwks_uri:
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(jwks_uri, timeout=30.0)
            except httpx.RequestError as exc:
                logger.warning("Failed to fetch JWKS from %s: %s", jwks_uri, exc)
                resp = None
        if resp is not None and resp.is_success:
            try:
                jwk_set = jwt.PyJWKSet.from_dict(resp.json())
                kid = jwt.get_unverified_header(token).get("kid")
                key = next((jwk.key for jwk in jwk_set.keys if jwk.key_id == kid), None)
                if key is None:
                    key = jwk_set.keys[0].key
                return jwt.decode(token, key, algorithms=["RS256"], audience=client_id)
            except (jwt.PyJWTError, IndexError, StopIteration) as exc:
                logger.warning("ID token verification failed, decoding without verification: %s", exc)
        else:
            logger.warning("No valid JWKS available, decoding ID token without verification")

    return jwt.decode(token, options={"verify_signature": False})
