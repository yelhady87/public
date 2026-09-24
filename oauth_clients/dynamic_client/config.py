import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
STORAGE_FILE = DATA_DIR / "registration.json"

OIDC_DISCOVERY_URL = os.environ.get(
    "OIDC_DISCOVERY_URL",
    "http://host.docker.internal/incorta/oauth/demo/.well-known/openid-configuration",
)

# Runtime-configurable discovery URL is persisted here so it survives restarts.
DISCOVERY_URL_FILE = DATA_DIR / "discovery_url.json"

# Client name used in the dynamic registration request payload (RFC 7591
# ``client_name``). Runtime-configurable and persisted.
CLIENT_NAME_FILE = DATA_DIR / "client_name.json"

# Optional initial access token for RFC 7591 registration
INITIAL_ACCESS_TOKEN = os.environ.get("INITIAL_ACCESS_TOKEN", "")

CLIENT_NAME = os.environ.get("CLIENT_NAME", "Dynamic OIDC Demo Client")
CLIENT_SCOPES = os.environ.get("CLIENT_SCOPES", "openid profile email")

# The public base URL the app is reachable at (redirect_uri = <base>/callback)
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8100")

SESSION_COOKIE = os.environ.get("SESSION_COOKIE", "dynamic_client_session")
DISCOVERY_TTL = int(os.environ.get("DISCOVERY_TTL", "300"))
