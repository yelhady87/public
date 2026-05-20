import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

DELTA_BASE_DIR = Path(os.environ.get("DELTA_BASE_DIR", "/app/tenants"))
OAUTH_SERVER_URL = os.environ.get("OAUTH_SERVER_URL", "")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
INTROSPECTION_CACHE_TTL = int(os.environ.get("INTROSPECTION_CACHE_TTL", "60"))

if not OAUTH_SERVER_URL:
    logger.warning("OAUTH_SERVER_URL is not set — Delta Lake proxy token validation will fail")
if not OAUTH_CLIENT_ID or not OAUTH_CLIENT_SECRET:
    logger.warning("OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET not set — token introspection will fail")
