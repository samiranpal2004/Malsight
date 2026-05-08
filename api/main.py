# Phase 4: FastAPI application entrypoint.
from dotenv import load_dotenv
load_dotenv(override=True)  # Load .env variables, allowing override (e.g. from environment or secrets manager)
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
    # ── PostgreSQL ──────────────────────────────────────────────────────────
    try:
        from api.db import init_tables
        await asyncio.to_thread(init_tables)
        logger.info("PostgreSQL: connected and tables initialized.")
    except Exception as exc:
        logger.warning("PostgreSQL unavailable on startup (will degrade): %s", exc)


# ── Redis ───────────────────────────────────────────────────────────────  
    try:
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        logger.info("Redis URL configured: %s", redis_url)
    except Exception as exc:
        logger.warning("Redis config error: %s", exc)