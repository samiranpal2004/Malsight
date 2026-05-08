# Phase 4: FastAPI application entrypoint.
import asyncio
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router

logger = logging.getLogger(__name__)

app = FastAPI(
    title="MalSight API",
    description="AI-powered malware analyzer — Gemini 1.5 Pro agent brain",
    version="0.1.0",
)

# Hackathon context: allow all origins.
# X-API-Key is exposed so the browser can read it in responses.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-API-Key"],
)

app.include_router(router)


@app.on_event("startup")
async def _startup_checks() -> None:
    """Verify external dependencies and initialize DB schema on boot.

    Degraded startup (unavailable DB / Redis) is logged as a warning but does
    NOT crash the process — routes will return 503-style errors at call time.
    """
    # ── PostgreSQL ──────────────────────────────────────────────────────────
    try:
        from api.db import init_tables

        await asyncio.to_thread(init_tables)
        logger.info("PostgreSQL: connected and tables initialized.")
    except Exception as exc:
        logger.warning("PostgreSQL unavailable on startup (will degrade): %s", exc)

    # ── Redis ───────────────────────────────────────────────────────────────
    try:
        import redis as redis_lib

        r = redis_lib.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379")
        )
        r.ping()
        logger.info("Redis: connected.")
    except Exception as exc:
        logger.warning("Redis unavailable on startup (will degrade): %s", exc)
