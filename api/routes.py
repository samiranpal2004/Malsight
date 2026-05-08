# Phase 4: FastAPI route handlers — all 5 endpoints from PRD Section 9.1.
import asyncio
import hashlib
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import Optional

import redis as redis_lib
from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
from rq import Queue, Worker

from api import db
from malsight.config import MALSIGHT_API_KEYS, REDIS_URL

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Constants ────────────────────────────────────────────────────────────────

MAX_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB (PRD Section 9.3)

ALLOWED_EXTENSIONS = {".exe", ".dll", ".py", ".sh", ".bash", ".pdf", ".zip"}

VALID_MODES = {"standard", "deep_scan"}

STAGING_DIR = "/tmp/malsight_jobs"

ESTIMATED_SECONDS = {"standard": 60, "deep_scan": 300}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _require_api_key(x_api_key: str | None) -> None:
    """Raise 401 if the X-API-Key header is missing or not in MALSIGHT_API_KEYS."""
    valid = {k.strip() for k in MALSIGHT_API_KEYS() if k.strip()}
    if not x_api_key or x_api_key not in valid:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


def _redis() -> redis_lib.Redis:
    return redis_lib.from_url(REDIS_URL())


def _queue() -> Queue:
    return Queue("malsight", connection=_redis())


def _elapsed(ts: datetime | None) -> int:
    if ts is None:
        return 0
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - ts).total_seconds()))


# ── POST /analyze ─────────────────────────────────────────────────────────────

@router.post("/analyze", status_code=200)
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    mode: str = Form("standard"),
    x_api_key: str | None = Header(None),
) -> dict:
    """Accept a file upload, validate it, enqueue analysis, return job_id immediately."""
    _require_api_key(x_api_key)

    # Validate mode
    if mode not in VALID_MODES:
        raise HTTPException(status_code=400, detail=f"mode must be one of {sorted(VALID_MODES)}")

    # Quick size check via Content-Length before reading body
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="File exceeds 50 MB limit")

    # Validate extension
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {sorted(ALLOWED_EXTENSIONS)}",
        )

    # Read file content, compute SHA-256, and enforce size limit precisely
    data = await file.read()
    if len(data) > MAX_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="File exceeds 50 MB limit")
    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    sha256 = hashlib.sha256(data).hexdigest()
    job_id = str(uuid.uuid4())

    # Save to staging directory
    job_dir = os.path.join(STAGING_DIR, job_id)
    file_path = os.path.join(job_dir, f"original_{filename}")
    await asyncio.to_thread(_write_file, job_dir, file_path, data)

    # Persist job row
    await asyncio.to_thread(
        db.insert_job, job_id, "queued", mode, filename, sha256,
        len(data), file.content_type or "", file_path,
    )

    # Enqueue RQ job (import here so worker module is only loaded when needed)
    from api.worker import analyze_file_job  # noqa: PLC0415 — deferred to avoid circular imports

    try:
        q = _queue()
        q.enqueue(analyze_file_job, job_id, file_path, mode, filename, job_timeout=600)
    except Exception as exc:
        logger.error("Failed to enqueue job %s: %s", job_id, exc)
        raise HTTPException(status_code=500, detail="Queue unavailable — try again shortly")

    return {
        "job_id": job_id,
        "status": "queued",
        "mode": mode,
        "estimated_seconds": ESTIMATED_SECONDS[mode],
    }


def _write_file(job_dir: str, file_path: str, data: bytes) -> None:
    os.makedirs(job_dir, exist_ok=True)
    with open(file_path, "wb") as fh:
        fh.write(data)


# ── GET /report/{job_id} ──────────────────────────────────────────────────────

@router.get("/report/{job_id}")
async def get_report(
    job_id: str,
    x_api_key: str | None = Header(None),
) -> dict:
    """Return live status while running; full report when complete."""
    _require_api_key(x_api_key)

    job = await asyncio.to_thread(db.get_job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    status = job["status"]
    created_at: datetime | None = job.get("created_at")

    if status == "queued":
        return {
            "job_id": job_id,
            "status": "queued",
            "elapsed_seconds": _elapsed(created_at),
        }

    if status == "running":
        # agent.JOB_STATUS is module-level in agent.py and written by the RQ worker.
        # This dict is only visible when the API server and RQ worker share the same
        # Python process (e.g. SimpleWorker in dev mode). In multi-process production
        # deployments the dict will be empty here and the route falls back to generic
        # "processing" text — move step tracking to Redis/DB for multi-process setups.
        try:
            import agent as _agent  # noqa: PLC0415

            live = _agent.JOB_STATUS.get(job_id, {})
        except Exception:
            live = {}

        started_at: datetime | None = job.get("started_at")
        return {
            "job_id": job_id,
            "status": "running",
            "current_step": live.get("step", 0),
            "current_action": live.get("action", "Processing…"),
            "elapsed_seconds": _elapsed(started_at or created_at),
        }

    if status == "complete":
        report_row = await asyncio.to_thread(db.get_report, job_id)
        report_data = report_row["report_json"] if report_row else {}
        return {
            "job_id": job_id,
            "status": "complete",
            "report": report_data,
        }

    if status == "failed":
        return {
            "job_id": job_id,
            "status": "failed",
            "error": job.get("error_message") or job.get("error") or "Unknown error",
        }

    # Catch-all for unexpected status values
    return {"job_id": job_id, "status": status}


# ── GET /reports ──────────────────────────────────────────────────────────────

@router.get("/reports")
async def list_reports(
    page: int = 1,
    page_size: int = 20,
    verdict: Optional[str] = None,
    mode: Optional[str] = None,
    x_api_key: str | None = Header(None),
) -> dict:
    """Paginated list of all completed reports with optional filters."""
    _require_api_key(x_api_key)

    if page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1")
    if not (1 <= page_size <= 100):
        raise HTTPException(status_code=400, detail="page_size must be 1–100")
    if verdict and verdict not in {"benign", "suspicious", "malicious"}:
        raise HTTPException(status_code=400, detail="Invalid verdict filter")
    if mode and mode not in VALID_MODES:
        raise HTTPException(status_code=400, detail="Invalid mode filter")

    items, total = await asyncio.to_thread(
        db.list_reports, page, page_size, verdict, mode
    )
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


# ── GET /health ───────────────────────────────────────────────────────────────

def _health_db() -> bool:
    conn = db.get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return True
    except Exception as e:
        print("DB health check failed:", e)
        return False
    finally:
        conn.close()


@router.get("/health")
async def health() -> dict:
    """Service health check — no auth required."""
    db_connected = False
    queue_depth = -1
    workers_active = 0

    # DB check — fresh connection so we bypass any stale pool state
    try:
        db_connected = await asyncio.to_thread(_health_db)
    except Exception as e:
        print("DB health check failed:", e)
        db_connected = False

    # Redis + RQ check — read URL directly from env with a safe fallback so
    # get_secret() failures don't silently zero out the worker count
    redis_url = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379")
    try:
        from redis import Redis as RedisClient
        conn = RedisClient.from_url(redis_url, socket_connect_timeout=5)
        conn.ping()
        q = Queue("malsight", connection=conn)
        queue_depth = len(q)
        workers_active = len(Worker.all(connection=conn))
    except Exception as e:
        print("Redis health check failed:", e)
        queue_depth = -1
        workers_active = 0

    status = "ok" if db_connected else "degraded"

    return {
        "status": status,
        "queue_depth": queue_depth,
        "workers_active": workers_active,
        "db_connected": db_connected,
    }


# ── DELETE /report/{job_id} ───────────────────────────────────────────────────

@router.delete("/report/{job_id}")
async def delete_report(
    job_id: str,
    x_api_key: str | None = Header(None),
) -> dict:
    """Delete a job and its report; also remove staged files."""
    _require_api_key(x_api_key)

    deleted = await asyncio.to_thread(db.delete_report, job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Job not found")

    # Best-effort cleanup of staged files
    job_dir = os.path.join(STAGING_DIR, job_id)
    if os.path.exists(job_dir):
        await asyncio.to_thread(shutil.rmtree, job_dir, True)

    return {"deleted": True, "job_id": job_id}
