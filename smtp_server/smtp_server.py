"""MalSight SMTP server — intercepts all inbound email, stores it, enqueues analysis."""
import asyncio
import logging
import os

from dotenv import load_dotenv
load_dotenv()

from aiosmtpd.controller import Controller
import redis as redis_lib
from rq import Queue

from db import save_email_to_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
_redis_conn: redis_lib.Redis | None = None


def _get_redis() -> redis_lib.Redis:
    global _redis_conn
    if _redis_conn is None:
        _redis_conn = redis_lib.from_url(REDIS_URL)
    return _redis_conn


class MalSightHandler:
    """aiosmtpd handler — always accepts email, enqueues async analysis."""

    async def handle_DATA(self, server, session, envelope):  # noqa: N802
        try:
            email_id = await asyncio.to_thread(
                save_email_to_db,
                envelope.mail_from,
                envelope.rcpt_tos,
                envelope.content,
            )
            q = Queue("malsight", connection=_get_redis())
            q.enqueue("mail_processor.process_email", email_id, job_timeout=600)
            logger.info(
                "Accepted email %s from=%s to=%s",
                email_id, envelope.mail_from, envelope.rcpt_tos,
            )
        except Exception as exc:
            logger.error("Failed to handle inbound email: %s", exc)
        # Always accept — never bounce at SMTP layer
        return "250 Message accepted for delivery"


if __name__ == "__main__":
    host = os.environ.get("SMTP_HOST", "0.0.0.0")
    port = int(os.environ.get("SMTP_PORT", "25"))

    controller = Controller(MalSightHandler(), hostname=host, port=port)
    controller.start()
    logger.info("MalSight SMTP server listening on %s:%d", host, port)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        logger.info("SMTP server stopped")
