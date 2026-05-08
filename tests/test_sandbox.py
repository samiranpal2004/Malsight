# Phase 2 unit tests for tools/sandbox.py
# All Docker SDK calls are mocked — no real containers are started.
import os
import tempfile
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from tools import sandbox as _sandbox_module
from tools.sandbox import (
    run_sandbox,
    capture_memory_dump,
    monitor_filesystem,
    get_dropped_files,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_sandbox_state():
    """Reset shared module state before every test."""
    _sandbox_module._state.update({
        "container": None,
        "client": None,
        "results_dir": None,
        "file_path": None,
        "start_time": None,
        "dump_path": None,
        "created_files": [],
    })
    yield


@pytest.fixture
def sample_file(tmp_path):
    p = tmp_path / "sample.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    return str(p)


def _make_mock_docker(image_found: bool = True, container_exit_code: int = 0):
    """Build a mock Docker client."""
    client = MagicMock()
    if not image_found:
        import docker.errors
        client.images.get.side_effect = docker.errors.ImageNotFound("not found")
    else:
        client.images.get.return_value = MagicMock()

    container = MagicMock()
    container.wait.return_value = {"StatusCode": container_exit_code}
    container.logs.return_value = b""
    container.exec_run.return_value = MagicMock(output=b"123")  # PID
    client.containers.run.return_value = container
    return client, container


# ---------------------------------------------------------------------------
# run_sandbox
# ---------------------------------------------------------------------------

class TestRunSandbox:
    def test_docker_not_installed_returns_error(self, sample_file):
        with patch.dict("sys.modules", {"docker": None}):
            result = run_sandbox(sample_file)
        assert "error" in result
        assert "sandbox not available" in result["error"]

    def test_image_not_found_returns_error(self, sample_file):
        import docker.errors
        mock_client = MagicMock()
        mock_client.images.get.side_effect = docker.errors.ImageNotFound("nope")
        with patch("tools.sandbox._get_docker_client", return_value=mock_client):
            result = run_sandbox(sample_file)
        assert "error" in result
        assert "malsight-sandbox" in result["error"]

    def test_successful_run_returns_summary(self, sample_file, tmp_path):
        mock_client, mock_container = _make_mock_docker()
        results_dir = str(tmp_path / "results")
        os.makedirs(results_dir, exist_ok=True)

        with patch("tools.sandbox._get_docker_client", return_value=mock_client), \
             patch("tools.sandbox.tempfile.mkdtemp", return_value=results_dir):
            result = run_sandbox(sample_file, duration=5)

        assert "error" not in result
        assert "duration_actual" in result
        assert "file_ops" in result
        assert "network_attempts" in result
        assert "processes_spawned" in result
        assert "falco_events" in result

    def test_strace_log_parsed_correctly(self, sample_file, tmp_path):
        mock_client, mock_container = _make_mock_docker()
        results_dir = str(tmp_path / "res")
        os.makedirs(results_dir, exist_ok=True)

        trace_log = tmp_path / "res" / "trace.log"
        trace_log.write_text(
            'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n'
            'write(1, "hello", 5) = 5\n'
            'connect(3, ...) = -1 ECONNREFUSED\n'
            'execve("/bin/sh", ...) = 0\n'
        )

        with patch("tools.sandbox._get_docker_client", return_value=mock_client), \
             patch("tools.sandbox.tempfile.mkdtemp", return_value=results_dir):
            result = run_sandbox(sample_file, duration=5)

        assert result["file_ops"]["reads"] >= 1
        assert result["file_ops"]["writes"] >= 1
        assert result["network_attempts"]["count"] >= 1
        assert "sh" in result["processes_spawned"]

    def test_docker_error_returns_error(self, sample_file):
        mock_client = MagicMock()
        mock_client.images.get.return_value = MagicMock()
        mock_client.containers.run.side_effect = Exception("docker daemon error")
        with patch("tools.sandbox._get_docker_client", return_value=mock_client):
            result = run_sandbox(sample_file)
        assert "error" in result


# ---------------------------------------------------------------------------
# capture_memory_dump
# ---------------------------------------------------------------------------

class TestCaptureMemoryDump:
    def test_no_active_sandbox_returns_not_captured(self):
        result = capture_memory_dump()
        assert result["captured"] is False

    def test_existing_dump_returned_from_state(self, tmp_path):
        dump = tmp_path / "memdump.bin"
        dump.write_bytes(b"\x00" * 1024)
        _sandbox_module._state["dump_path"] = str(dump)
        result = capture_memory_dump(timing=5)
        assert result["captured"] is True
        assert result["dump_size_bytes"] == 1024
        assert result["timing_seconds"] == 5

    def test_active_container_triggers_gcore(self, tmp_path):
        import time
        dump = tmp_path / "memdump.bin"
        dump.write_bytes(b"\x4D\x5A" + b"\x00" * 2046)

        mock_container = MagicMock()
        mock_container.exec_run.side_effect = [
            MagicMock(output=b"42\n"),           # pgrep call
            MagicMock(output=b""),               # gcore call
        ]
        _sandbox_module._state.update({
            "container": mock_container,
            "results_dir": str(tmp_path),
            "start_time": time.time(),
        })

        with patch("tools.sandbox.os.path.exists", return_value=True), \
             patch("tools.sandbox.os.path.getsize", return_value=2048):
            result = capture_memory_dump(timing=0)

        assert result["captured"] is True


# ---------------------------------------------------------------------------
# monitor_filesystem
# ---------------------------------------------------------------------------

class TestMonitorFilesystem:
    def test_no_sandbox_returns_empty_lists(self):
        result = monitor_filesystem()
        assert "created" in result
        assert "modified" in result
        assert "deleted" in result
        assert result["created"] == []

    def test_active_container_exec_parsed(self):
        inotify_output = (
            b"CREATE /tmp/dropped.exe\n"
            b"MODIFY /etc/crontab\n"
            b"DELETE /tmp/original.sh\n"
        )
        mock_container = MagicMock()
        mock_container.exec_run.return_value = MagicMock(output=inotify_output)
        _sandbox_module._state["container"] = mock_container

        result = monitor_filesystem()
        assert "/tmp/dropped.exe" in result["created"]
        assert "/etc/crontab" in result["modified"]
        assert "/tmp/original.sh" in result["deleted"]

    def test_container_exec_error_returns_error(self):
        mock_container = MagicMock()
        mock_container.exec_run.side_effect = Exception("container dead")
        _sandbox_module._state["container"] = mock_container

        result = monitor_filesystem()
        assert "error" in result


# ---------------------------------------------------------------------------
# get_dropped_files
# ---------------------------------------------------------------------------

class TestGetDroppedFiles:
    def test_no_created_files_returns_empty_list(self):
        result = get_dropped_files()
        assert result == []

    def test_existing_file_returned_with_hash(self, tmp_path):
        dropped = tmp_path / "evil.exe"
        dropped.write_bytes(b"MZ" + b"\x90" * 100)
        _sandbox_module._state["created_files"] = [str(dropped)]
        _sandbox_module._state["results_dir"] = str(tmp_path)

        result = get_dropped_files()
        assert len(result) == 1
        assert result[0]["path"] == str(dropped)
        assert len(result[0]["sha256"]) == 64
        assert result[0]["size_bytes"] == 102

    def test_nonexistent_file_skipped(self, tmp_path):
        _sandbox_module._state["created_files"] = ["/nonexistent/ghost.exe"]
        _sandbox_module._state["results_dir"] = str(tmp_path)
        _sandbox_module._state["container"] = None  # no container to copy from
        result = get_dropped_files()
        assert result == []
