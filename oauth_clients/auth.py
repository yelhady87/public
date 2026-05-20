import hashlib
import logging
import time

import httpx
from fastapi import HTTPException
from starlette.requests import Request

from config import (
    INTROSPECTION_CACHE_TTL,
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    OAUTH_SERVER_URL,
)

logger = logging.getLogger(__name__)

_discovery_cache: dict[str, tuple[dict, float]] = {}
_introspection_cache: dict[str, tuple[dict, float]] = {}

DISCOVERY_TTL = 300  # 5 minutes

# Hardcoded ACL: maps subject (username) to allowed (tenant, schema, table) tuples.
# Use "*" as a wildcard for any component.
ACCESS_CONTROL: dict[str, list[tuple[str, str, str]]] = {
    "admin": [("*", "*", "*")],
    "analyst": [("demo", "SALES", "*")],
}


async def _discover_introspection_endpoint(tenant: str) -> str:
    now = time.time()
    if tenant in _discovery_cache:
        doc, expiry = _discovery_cache[tenant]
        if now < expiry:
            return doc["introspection_endpoint"]

    url = f"{OAUTH_SERVER_URL.rstrip('/')}/oauth/{tenant}/.well-known/openid-configuration"
    logger.info("Fetching OIDC discovery for tenant=%s from %s", tenant, url)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=30.0)
        except httpx.RequestError as exc:
            logger.error("OIDC discovery request failed: %s", exc)
            raise HTTPException(status_code=502, detail="Could not reach OAuth server for OIDC discovery")

    if not resp.is_success:
        logger.error("OIDC discovery returned %s: %s", resp.status_code, resp.text)
        raise HTTPException(status_code=502, detail="OIDC discovery failed")

    doc = resp.json()
    endpoint = doc.get("introspection_endpoint")
    if not endpoint:
        logger.error("OIDC discovery missing introspection_endpoint for tenant=%s", tenant)
        raise HTTPException(status_code=502, detail="OAuth server does not expose an introspection endpoint")

    _discovery_cache[tenant] = (doc, now + DISCOVERY_TTL)
    return endpoint


async def introspect_token(token: str, tenant: str) -> dict:
    now = time.time()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    cache_key = f"{token_hash}:{tenant}"

    if cache_key in _introspection_cache:
        result, expiry = _introspection_cache[cache_key]
        if now < expiry:
            logger.debug("Introspection cache hit for tenant=%s", tenant)
            return result
        del _introspection_cache[cache_key]

    introspection_endpoint = await _discover_introspection_endpoint(tenant)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                introspection_endpoint,
                data={"token": token},
                auth=(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET),
                timeout=30.0,
            )
        except httpx.RequestError as exc:
            logger.error("Token introspection request failed: %s", exc)
            raise HTTPException(status_code=502, detail="Could not reach OAuth server for token validation")

    if not resp.is_success:
        logger.error("Introspection returned %s: %s", resp.status_code, resp.text)
        raise HTTPException(status_code=502, detail="Token introspection failed")

    result = resp.json()
    if result.get("active"):
        _introspection_cache[cache_key] = (result, now + INTROSPECTION_CACHE_TTL)

    return result


def get_subject(introspection_result: dict) -> str:
    for field in ("sub", "username", "preferred_username"):
        value = introspection_result.get(field)
        if value:
            return value
    return ""


def check_access(subject: str, tenant: str, schema: str, table: str) -> bool:
    allowed = ACCESS_CONTROL.get(subject)
    if not allowed:
        return False
    for a_tenant, a_schema, a_table in allowed:
        if (a_tenant == "*" or a_tenant == tenant) and \
           (a_schema == "*" or a_schema == schema) and \
           (a_table == "*" or a_table == table):
            return True
    return False


async def get_current_user(request: Request, tenant: str) -> dict:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header[7:]
    result = await introspect_token(token, tenant)

    if not result.get("active"):
        raise HTTPException(status_code=401, detail="Token is not active or has expired")

    return result
