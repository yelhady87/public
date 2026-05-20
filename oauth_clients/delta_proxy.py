import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from starlette.requests import Request

from auth import check_access, get_current_user, get_subject
from config import DELTA_BASE_DIR

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/delta", tags=["Delta Lake Proxy"])

CONTENT_TYPES = {
    ".parquet": "application/octet-stream",
    ".json": "application/json",
    ".crc": "application/octet-stream",
}


def _validate_path(base: Path, *components: str) -> Path:
    target = base.joinpath(*components).resolve()
    base_resolved = base.resolve()
    if target != base_resolved and not str(target).startswith(str(base_resolved) + "/"):
        raise HTTPException(status_code=400, detail="Invalid path")
    return target


def _require_base_dir() -> Path:
    resolved = DELTA_BASE_DIR.resolve()
    if not resolved.is_dir():
        raise HTTPException(status_code=500, detail="Delta Lake base directory is not configured or does not exist")
    return resolved


@router.get("/{tenant}/{schema}/{table}")
async def list_table_files(tenant: str, schema: str, table: str, request: Request):
    user_info = await get_current_user(request, tenant)
    subject = get_subject(user_info)

    if not check_access(subject, tenant, schema, table):
        logger.warning("Access denied: subject=%s path=%s/%s/%s", subject, tenant, schema, table)
        raise HTTPException(status_code=403, detail=f"Access denied to {tenant}/{schema}/{table}")

    base = _require_base_dir()
    table_dir = _validate_path(base, tenant, "source", schema, table)

    if not table_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"Table not found: {tenant}/{schema}/{table}")

    files = []
    for entry in sorted(table_dir.rglob("*")):
        if entry.is_file():
            files.append({
                "name": str(entry.relative_to(table_dir)),
                "size": entry.stat().st_size,
            })

    logger.info("Listed %d files for %s/%s/%s (user=%s)", len(files), tenant, schema, table, subject)
    return {"tenant": tenant, "schema": schema, "table": table, "files": files}


@router.get("/{tenant}/{schema}/{table}/{file_path:path}")
async def download_file(tenant: str, schema: str, table: str, file_path: str, request: Request):
    user_info = await get_current_user(request, tenant)
    subject = get_subject(user_info)

    if not check_access(subject, tenant, schema, table):
        logger.warning("Access denied: subject=%s path=%s/%s/%s", subject, tenant, schema, table)
        raise HTTPException(status_code=403, detail=f"Access denied to {tenant}/{schema}/{table}")

    base = _require_base_dir()
    full_path = _validate_path(base, tenant, "source", schema, table, file_path)

    if not full_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    suffix = full_path.suffix
    media_type = CONTENT_TYPES.get(suffix, "application/octet-stream")
    if not suffix and full_path.name == "_last_checkpoint":
        media_type = "application/json"

    logger.info("Serving %s (user=%s)", full_path.relative_to(base), subject)
    return FileResponse(full_path, media_type=media_type, filename=full_path.name)
