import json
import logging
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import HTTPException

from config import (
    DISCOVERY_TTL,
    DISCOVERY_URL_FILE,
    OIDC_DISCOVERY_URL,
)

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_cache: tuple[dict, float] | None = None  # (discovery doc, expiry timestamp)
_url_lock = threading.Lock()

# Current discovery URL. Mutable at runtime via set_discovery_url().
_discovery_url: str = OIDC_DISCOVERY_URL

# Persisted URL takes precedence over env default on startup.
def _load_persisted_url() -> str | None:
    try:
        if DISCOVERY_URL_FILE.exists():
            with DISCOVERY_URL_FILE.open() as f:
                data = json.load(f)
            url = data.get("discovery_url")
            return url if isinstance(url, str) and url.strip() else None
    except (OSError, ValueError) as exc:
        logger.warning("Could not read persisted discovery URL: %s", exc)
    return None


def _persist_url(url: str) -> None:
    try:
        DISCOVERY_URL_FILE.parent.mkdir(parents=True, exist_ok=True)
        with DISCOVERY_URL_FILE.open("w") as f:
            json.dump({"discovery_url": url}, f, indent=2)
    except OSError as exc:
        logger.warning("Could not persist discovery URL: %s", exc)


_persisted = _load_persisted_url()
if _persisted:
    _discovery_url = _persisted


REQUIRED_ENDPOINTS = ("registration_endpoint", "authorization_endpoint", "token_endpoint")

# Endpoint fields in the discovery doc that may need their host rewritten when the
# provider advertises a host unreachable from this client (e.g. localhost in Docker).
ENDPOINT_FIELDS = (
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "jwks_uri",
    "userinfo_endpoint",
    "end_session_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "device_authorization_endpoint",
)


def _validate_url(url: str) -> str:
    """Ensure ``url`` is an absolute URL. The configured URL is kept as-is."""
    parts = urlsplit(url.strip())
    if not parts.scheme or not parts.netloc:
        raise HTTPException(
            status_code=400,
            detail="Discovery URL must be an absolute URL including scheme and host.",
        )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, parts.fragment))


def get_discovery_url() -> str:
    """Return the current configured discovery URL."""
    return _discovery_url


def set_discovery_url(url: str, *, persist: bool = True) -> str:
    """Set the discovery URL at runtime. The URL is stored verbatim.

    The cache is invalidated so the next call refetches from the new URL.
    """
    global _discovery_url, _cache

    normalized = _validate_url(url)

    with _url_lock:
        changed = _discovery_url != normalized
        _discovery_url = normalized
        if persist:
            _persist_url(normalized)
    if changed:
        with _lock:
            _cache = None
        logger.info("Discovery URL updated to %s", normalized)
    return normalized


def _rewrite_host(url: str, netloc: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme:
        return url
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


async def get_discovery(force: bool = False) -> dict:
    """Fetch (and cache) the OIDC discovery document.

    Endpoint URLs advertised by the provider are rewritten to use the same
    host as the discovery URL itself, so the client can reach them from its own
    network (e.g. host.docker.internal instead of localhost).
    """
    global _cache

    now = time.time()
    with _lock:
        if not force and _cache and _cache[1] > now:
            return _cache[0]

    discovery_url = _discovery_url
    logger.info("Fetching OIDC discovery from %s", discovery_url)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(discovery_url, timeout=30.0)
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not reach OIDC discovery document: {exc}",
            )

    if not resp.is_success:
        raise HTTPException(
            status_code=502,
            detail=f"OIDC discovery returned {resp.status_code}: {resp.text}",
        )

    doc = resp.json()
    missing = [key for key in REQUIRED_ENDPOINTS if not doc.get(key)]
    if missing:
        raise HTTPException(
            status_code=502,
            detail=f"Discovery document missing required fields: {', '.join(missing)}",
        )

    netloc = urlsplit(discovery_url).netloc
    for field in ENDPOINT_FIELDS:
        if doc.get(field):
            doc[field] = _rewrite_host(doc[field], netloc)

    with _lock:
        _cache = (doc, now + DISCOVERY_TTL)
    return doc