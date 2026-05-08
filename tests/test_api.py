# Phase 4 tests for the FastAPI backend.
# All external I/O (PostgreSQL, Redis, RQ, agent) is mocked — no real connections.
import io
import json
import os
import sys
from contextlib import ExitStack
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ── Environment setup (must happen before app is imported) ──────────────────
os.environ.setdefault("MALSIGHT_API_KEYS", "test-key-abc")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/testdb")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("GEMINI_API_KEY", "fake-gemini-key")

# Stub out psycopg2 so tests run without the binary installed.
# api.db imports psycopg2 at module level; faking it here prevents ImportError.
_psycopg2_mock = MagicMock()
_psycopg2_mock.extras = MagicMock()
_psycopg2_mock.pool = MagicMock()
_psycopg2_mock.pool.ThreadedConnectionPool = MagicMock()
sys.modules.setdefault("psycopg2", _psycopg2_mock)
sys.modules.setdefault("psycopg2.pool", _psycopg2_mock.pool)
sys.modules.setdefault("psycopg2.extras", _psycopg2_mock.extras)

API_KEY = "test-key-abc"
AUTH = {"X-API-Key": API_KEY}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app_with_mocks():
    """Import and return the FastAPI app (psycopg2 already stubbed via sys.modules)."""
    from api.main import app  # safe: psycopg2 is already faked in sys.modules

    return app


@pytest.fixture()
def client(app_with_mocks):
    """TestClient with startup events mocked (no real DB/Redis on startup)."""
    with ExitStack() as stack:
        stack.enter_context(patch("api.db.init_tables", return_value=None))
        stack.enter_context(
            patch("redis.from_url", return_value=_make_redis())
        )
        with TestClient(app_with_mocks, raise_server_exceptions=True) as c:
            yield c


def _make_redis(queue_count: int = 0, workers: list | None = None) -> MagicMock:
    r = MagicMock()
    r.ping.return_value = True
    # Queue.count reads from Redis; mock it to return queue_count
    return r


def _fake_job(status: str = "queued", **extra) -> dict:
    base = {
        "job_id": "abc-123",
        "status": status,
        "mode": "standard",
        "filename": "sample.exe",
        "sha256": "a" * 64,
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "started_at": None,
        "completed_at": None,
        "error": None,
    }
    base.update(extra)
    return base


def _fake_report_row(report_dict: dict | None = None) -> dict:
    rd = report_dict or {
        "job_id": "abc-123",
        "mode": "standard",
        "verdict": "malicious",
        "confidence": 95,
        "threat_category": "trojan",
        "severity": "high",
        "summary": "Trojan found.",
        "key_indicators": ["packed"],
        "mitre_techniques": [],
        "recommended_action": "Quarantine",
        "iocs": {},
        "tools_called": 5,
        "analysis_time_seconds": 42,
        "reasoning_chain": {"steps": []},
    }
    return {"job_id": "abc-123", "report_json": rd, "verdict": "malicious", "confidence": 95}


# ---------------------------------------------------------------------------
# POST /analyze
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_valid_file_accepted(self, client):
        file_data = b"MZ" + b"\x00" * 100  # minimal PE stub
        with ExitStack() as stack:
            stack.enter_context(patch("api.db.insert_job", return_value=None))
            stack.enter_context(patch("api.db.update_job_status", return_value=None))
            mock_q = MagicMock()
            stack.enter_context(patch("api.routes._queue", return_value=mock_q))
            # Patch file writing so we don't touch /tmp in tests
            stack.enter_context(patch("api.routes._write_file", return_value=None))

            resp = client.post(
                "/analyze",
                headers=AUTH,
                data={"mode": "standard"},
                files={"file": ("sample.exe", io.BytesIO(file_data), "application/octet-stream")},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "queued"
        assert body["mode"] == "standard"
        assert "job_id" in body
        assert body["estimated_seconds"] == 60
        mock_q.enqueue.assert_called_once()

    def test_invalid_extension_rejected(self, client):
        resp = client.post(
            "/analyze",
            headers=AUTH,
            data={"mode": "standard"},
            files={"file": ("malware.mp3", io.BytesIO(b"data"), "audio/mpeg")},
        )
        assert resp.status_code == 400
        assert "Unsupported file type" in resp.json()["detail"]

    def test_missing_api_key_returns_401(self, client):
        resp = client.post(
            "/analyze",
            data={"mode": "standard"},
            files={"file": ("a.exe", io.BytesIO(b"MZ"), "application/octet-stream")},
        )
        assert resp.status_code == 401

    def test_invalid_api_key_returns_401(self, client):
        resp = client.post(
            "/analyze",
            headers={"X-API-Key": "wrong-key"},
            data={"mode": "standard"},
            files={"file": ("a.exe", io.BytesIO(b"MZ"), "application/octet-stream")},
        )
        assert resp.status_code == 401

    def test_oversized_file_rejected(self, client):
        # Build a body just over 50 MB
        large_data = b"A" * (50 * 1024 * 1024 + 1)
        resp = client.post(
            "/analyze",
            headers=AUTH,
            data={"mode": "standard"},
            files={"file": ("big.exe", io.BytesIO(large_data), "application/octet-stream")},
        )
        assert resp.status_code == 400
        assert "50 MB" in resp.json()["detail"]

    def test_invalid_mode_rejected(self, client):
        resp = client.post(
            "/analyze",
            headers=AUTH,
            data={"mode": "turbo"},
            files={"file": ("a.exe", io.BytesIO(b"MZ"), "application/octet-stream")},
        )
        assert resp.status_code == 400

    def test_deep_scan_returns_300_seconds(self, client):
        with ExitStack() as stack:
            stack.enter_context(patch("api.db.insert_job", return_value=None))
            stack.enter_context(patch("api.routes._queue", return_value=MagicMock()))
            stack.enter_context(patch("api.routes._write_file", return_value=None))

            resp = client.post(
                "/analyze",
                headers=AUTH,
                data={"mode": "deep_scan"},
                files={"file": ("sample.exe", io.BytesIO(b"MZ" * 10), "application/octet-stream")},
            )

        assert resp.status_code == 200
        assert resp.json()["estimated_seconds"] == 300


# ---------------------------------------------------------------------------
# GET /report/{job_id}
# ---------------------------------------------------------------------------

class TestGetReport:
    def test_queued_status(self, client):
        with patch("api.db.get_job", return_value=_fake_job("queued")):
            resp = client.get("/report/abc-123", headers=AUTH)

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "queued"
        assert body["job_id"] == "abc-123"
        assert "elapsed_seconds" in body

    def test_running_status_includes_current_step(self, client):
        job = _fake_job("running", started_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        fake_status = {
            "abc-123": {"step": 3, "action": "Scanning memory dump...", "elapsed_seconds": 15}
        }
        with patch("api.db.get_job", return_value=job), \
             patch.dict("agent.JOB_STATUS", fake_status):
            resp = client.get("/report/abc-123", headers=AUTH)

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "running"
        assert body["current_step"] == 3
        assert body["current_action"] == "Scanning memory dump..."
        assert "elapsed_seconds" in body

    def test_complete_status_includes_report(self, client):
        job = _fake_job("complete", completed_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        with patch("api.db.get_job", return_value=job), \
             patch("api.db.get_report", return_value=_fake_report_row()):
            resp = client.get("/report/abc-123", headers=AUTH)

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "complete"
        assert "report" in body
        assert body["report"]["verdict"] == "malicious"

    def test_failed_status_includes_error(self, client):
        job = _fake_job("failed", error="Gemini API quota exceeded")
        with patch("api.db.get_job", return_value=job):
            resp = client.get("/report/abc-123", headers=AUTH)

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "failed"
        assert "Gemini" in body["error"]

    def test_404_for_unknown_job(self, client):
        with patch("api.db.get_job", return_value=None):
            resp = client.get("/report/does-not-exist", headers=AUTH)
        assert resp.status_code == 404

    def test_missing_api_key_returns_401(self, client):
        resp = client.get("/report/abc-123")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /reports
# ---------------------------------------------------------------------------

class TestListReports:
    def _sample_items(self, n: int = 3) -> list[dict]:
        return [
            {
                "job_id": f"job-{i}",
                "filename": f"file{i}.exe",
                "mode": "standard",
                "verdict": "malicious",
                "confidence": 90,
                "threat_category": "trojan",
                "severity": "high",
                "tools_called": 5,
                "analysis_time_seconds": 40,
                "created_at": "2024-01-01T00:00:00",
            }
            for i in range(n)
        ]

    def test_returns_paginated_list(self, client):
        items = self._sample_items(3)
        with patch("api.db.list_reports", return_value=(items, 3)):
            resp = client.get("/reports", headers=AUTH)

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 3
        assert body["total"] == 3
        assert body["page"] == 1
        assert body["page_size"] == 20

    def test_verdict_filter_passed_to_db(self, client):
        with patch("api.db.list_reports", return_value=([], 0)) as mock_list:
            resp = client.get("/reports?verdict=malicious", headers=AUTH)

        assert resp.status_code == 200
        call_args = mock_list.call_args
        assert call_args.args[2] == "malicious"  # verdict_filter positional arg

    def test_mode_filter_passed_to_db(self, client):
        with patch("api.db.list_reports", return_value=([], 0)) as mock_list:
            resp = client.get("/reports?mode=deep_scan", headers=AUTH)

        assert resp.status_code == 200
        call_args = mock_list.call_args
        assert call_args.args[3] == "deep_scan"  # mode_filter positional arg

    def test_pagination_params_forwarded(self, client):
        with patch("api.db.list_reports", return_value=([], 0)) as mock_list:
            resp = client.get("/reports?page=2&page_size=10", headers=AUTH)

        assert resp.status_code == 200
        assert resp.json()["page"] == 2
        assert resp.json()["page_size"] == 10
        args = mock_list.call_args.args
        assert args[0] == 2   # page
        assert args[1] == 10  # page_size

    def test_invalid_verdict_filter_rejected(self, client):
        resp = client.get("/reports?verdict=unknown_verdict", headers=AUTH)
        assert resp.status_code == 400

    def test_missing_auth_returns_401(self, client):
        resp = client.get("/reports")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_returns_queue_depth_and_db_connected(self, client):
        mock_q = MagicMock()
        mock_q.count = 4
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        # Queue and Worker are imported *into* api.routes, so patch them there.
        mock_worker_cls = MagicMock()
        mock_worker_cls.all.return_value = [MagicMock(), MagicMock()]

        with patch("api.db.get_job", return_value=None), \
             patch("api.routes._redis", return_value=mock_redis), \
             patch("api.routes.Queue", return_value=mock_q), \
             patch("api.routes.Worker", mock_worker_cls):
            resp = client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["db_connected"] is True
        assert body["queue_depth"] == 4
        assert body["workers_active"] == 2
        assert body["status"] == "ok"

    def test_degraded_when_redis_down(self, client):
        bad_redis = MagicMock()
        bad_redis.ping.side_effect = Exception("Connection refused")

        with patch("api.db.get_job", return_value=None), \
             patch("api.routes._redis", return_value=bad_redis):
            resp = client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "degraded"

    def test_degraded_when_db_down(self, client):
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_q = MagicMock()
        mock_q.count = 0
        mock_worker_cls = MagicMock()
        mock_worker_cls.all.return_value = []

        with patch("api.db.get_job", side_effect=Exception("DB down")), \
             patch("api.routes._redis", return_value=mock_redis), \
             patch("api.routes.Queue", return_value=mock_q), \
             patch("api.routes.Worker", mock_worker_cls):
            resp = client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["db_connected"] is False
        assert body["status"] == "degraded"

    def test_no_auth_required(self, client):
        mock_q = MagicMock()
        mock_q.count = 0
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        mock_worker_cls = MagicMock()
        mock_worker_cls.all.return_value = []

        with patch("api.db.get_job", return_value=None), \
             patch("api.routes._redis", return_value=mock_redis), \
             patch("api.routes.Queue", return_value=mock_q), \
             patch("api.routes.Worker", mock_worker_cls):
            resp = client.get("/health")  # no X-API-Key header

        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# DELETE /report/{job_id}
# ---------------------------------------------------------------------------

class TestDeleteReport:
    def test_delete_returns_true(self, client):
        with patch("api.db.delete_report", return_value=True), \
             patch("os.path.exists", return_value=False):
            resp = client.delete("/report/abc-123", headers=AUTH)

        assert resp.status_code == 200
        body = resp.json()
        assert body["deleted"] is True
        assert body["job_id"] == "abc-123"

    def test_404_for_unknown_job(self, client):
        with patch("api.db.delete_report", return_value=False):
            resp = client.delete("/report/no-such-job", headers=AUTH)
        assert resp.status_code == 404

    def test_missing_api_key_returns_401(self, client):
        resp = client.delete("/report/abc-123")
        assert resp.status_code == 401

    def test_staged_files_cleaned_up(self, client):
        with patch("api.db.delete_report", return_value=True), \
             patch("os.path.exists", return_value=True) as mock_exists, \
             patch("shutil.rmtree") as mock_rmtree:
            resp = client.delete("/report/abc-123", headers=AUTH)

        assert resp.status_code == 200
        mock_rmtree.assert_called_once()
