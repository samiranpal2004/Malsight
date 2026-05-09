# Phase 4: RQ worker job function — called by the RQ worker process.
#
# Process model note
# ──────────────────
# The RQ worker is a *separate* process from the FastAPI server.  Both processes
# import agent.py, so each has its own copy of agent.JOB_STATUS (an in-memory dict).
# The worker fills JOB_STATUS[job_id] during agent.run_agent().
# The FastAPI GET /report route reads agent.JOB_STATUS in *its* process — which is
# always empty unless the worker and API run in the same process (e.g. RQ SimpleWorker
# in dev / single-process mode).
# For multi-process production deployments, migrate live-step tracking to Redis or
# add a current_step column to the jobs table so both processes can share state.
from dotenv import load_dotenv
load_dotenv(override=True)
import hashlib
import logging
import os
import shutil
import traceback
from datetime import datetime, timezone
from pathlib import Path

# agent.run_agent() is the Phase 3 Gemini loop.  It calls agent.update_job_status()
# internally, writing progress to agent.JOB_STATUS (same process only — see note above).
import agent as _malsight_agent
from tool_executor import set_current_job_id

from api import db
from tools.static_analysis import get_entropy

logger = logging.getLogger(__name__)


def analyze_file_job(
    job_id: str,
    file_path: str,
    mode: str,
    filename: str,
) -> None:
    """
    Top-level RQ job function — must be importable at module level (no closures).

    Steps
    -----
    1. Update jobs table: status="running", started_at=now()
    2. Build file_meta dict (sha256, size, entropy)
    3. Call agent.run_agent() → full Gemini agent loop
    4. Persist the returned report to PostgreSQL
    5. Update jobs table: status="complete"
    6. On any exception: status="failed", log full traceback
    7. Always clean up /tmp/malsight_jobs/{job_id}/
    """
    staging_dir = Path("/tmp/malsight_jobs") / job_id

    try:
        # ── Step 1 ──────────────────────────────────────────────────────────
        job_started_at = datetime.now(timezone.utc)
        db.update_job_status(
            job_id, "running",
            started_at=job_started_at,
            current_step=0,
            current_action="Starting analysis...",
        )
        logger.info("Job %s starting (mode=%s, file=%s)", job_id, mode, filename)

        # ── Step 2 ──────────────────────────────────────────────────────────
        with open(file_path, "rb") as fh:
            data = fh.read()

        sha256 = hashlib.sha256(data).hexdigest()
        size_bytes = len(data)
        ext = os.path.splitext(filename)[1].lower()

        try:
            entropy_result = get_entropy(file_path)
            entropy = (
                entropy_result.get("overall_entropy", 0.0)
                if isinstance(entropy_result, dict)
                else 0.0
            )
        except Exception:
            entropy = 0.0  # non-fatal — agent still gets a valid meta dict

        file_meta = {
            "job_id": job_id,       # agent writes to JOB_STATUS[job_id] using this
            "filename": filename,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "extension": ext,
            "entropy": entropy,
        }

        # Zip files must never be extracted on the host — pass the zip as-is to
        # the agent, which will extract it inside the gVisor sandbox container.
        if ext == ".zip":
            file_meta["is_zip"] = True
            file_meta["zip_password"] = "infected"  # MalwareBazaar standard password
        else:
            file_meta["is_zip"] = False
            file_meta["zip_password"] = None

        # ── Step 3 ──────────────────────────────────────────────────────────
        logger.info("Job %s: starting agent loop (mode=%s)", job_id, mode)
        set_current_job_id(job_id)
        report = _malsight_agent.run_agent(file_path, file_meta, mode)

        # ── Step 4 ──────────────────────────────────────────────────────────
        db.insert_report(job_id, report)

        # ── Step 5 ──────────────────────────────────────────────────────────
        completed_at = datetime.now(timezone.utc)
        elapsed = int((completed_at - job_started_at).total_seconds())
        db.update_job_status(
            job_id, "complete",
            completed_at=completed_at,
        )
        logger.info(
            "Job %s complete: verdict=%s confidence=%s",
            job_id,
            report.get("verdict"),
            report.get("confidence"),
        )

    except Exception as exc:  # ── Step 6 ────────────────────────────────────
        logger.error("Job %s FAILED:\n%s", job_id, traceback.format_exc())
        try:
            db.update_job_status(job_id, "failed", error=str(exc))
        except Exception:
            logger.exception("Could not update job %s status to failed", job_id)

    finally:  # ── Step 7 ────────────────────────────────────────────────────
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
            logger.debug("Job %s: cleaned up staging dir %s", job_id, staging_dir)
