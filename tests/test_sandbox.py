# Unit tests for tools/sandbox.py (Kubernetes SDK backend)
# All k8s API calls are mocked — no real cluster is contacted.
import os
import tempfile
import time
from unittest.mock import MagicMock, patch, call

import pytest

from tools import sandbox as _sandbox_module
from tools.sandbox import (
    run_sandbox,
    capture_memory_dump,
    monitor_filesystem,
    get_dropped_files,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENV = {
    "SANDBOX_IMAGE": "gcr.io/test-project/malsight-sandbox:latest",
    "GCP_PROJECT": "test-project",
    "GKE_CLUSTER": "malsight-cluster",
    "GKE_ZONE": "us-central1-a",
}


def _make_k8s_mocks(log_text: str = "", job_complete: bool = True):
    """Return (mock_batch_api, mock_core_api) pre-configured for a normal run."""
    batch_api = MagicMock()
    core_api = MagicMock()

    # Job status: Complete
    cond = MagicMock()
    cond.type = "Complete"
    cond.status = "True"
    job_status = MagicMock()
    job_status.status.conditions = [cond] if job_complete else []
    batch_api.read_namespaced_job_status.return_value = job_status

    # Pod listing
    pod = MagicMock()
    pod.metadata.name = "malsight-sandbox-test-pod-abc"
    pod_list = MagicMock()
    pod_list.items = [pod]
    core_api.list_namespaced_pod.return_value = pod_list

    # Pod logs (strace output)
    core_api.read_namespaced_pod_log.return_value = log_text

    return batch_api, core_api


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_sandbox_state():
    """Reset shared module state before every test."""
    _sandbox_module._state.update({
        "job_id": None,
        "pod_name": None,
        "namespace": "default",
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


# ---------------------------------------------------------------------------
# run_sandbox
# ---------------------------------------------------------------------------

class TestRunSandbox:
    def test_env_vars_missing_returns_error(self, sample_file):
        """Missing SANDBOX_IMAGE / GKE vars → error without touching k8s."""
        with patch.dict(os.environ, {}, clear=True):
            # Ensure none of the required vars are set
            for k in _ENV:
                os.environ.pop(k, None)
            result = run_sandbox(sample_file)
        assert "error" in result
        assert "sandbox not available" in result["error"]

    def test_k8s_unreachable_returns_error(self, sample_file):
        """_load_kube_config raising → sandbox not available error."""
        with patch.dict(os.environ, _ENV), \
             patch("tools.sandbox._load_kube_config",
                   side_effect=Exception("no kubeconfig")):
            result = run_sandbox(sample_file)
        assert "error" in result
        assert "sandbox not available" in result["error"]

    def test_successful_run_returns_summary(self, sample_file):
        batch_api, core_api = _make_k8s_mocks(log_text="")

        with patch.dict(os.environ, _ENV), \
             patch("tools.sandbox._load_kube_config"), \
             patch("kubernetes.client.BatchV1Api", return_value=batch_api), \
             patch("kubernetes.client.CoreV1Api", return_value=core_api):
            result = run_sandbox(sample_file, duration=5)

        assert "error" not in result
        assert "duration_actual" in result
        assert "file_ops" in result
        assert "network_attempts" in result
        assert "processes_spawned" in result
        assert "falco_events" in result

    def test_strace_log_parsed_correctly(self, sample_file):
        strace_log = (
            'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n'
            'write(1, "hello", 5) = 5\n'
            'connect(3, ...) = -1 ECONNREFUSED\n'
            'execve("/bin/sh", ...) = 0\n'
        )
        batch_api, core_api = _make_k8s_mocks(log_text=strace_log)

        with patch.dict(os.environ, _ENV), \
             patch("tools.sandbox._load_kube_config"), \
             patch("kubernetes.client.BatchV1Api", return_value=batch_api), \
             patch("kubernetes.client.CoreV1Api", return_value=core_api):
            result = run_sandbox(sample_file, duration=5)

        assert result["file_ops"]["reads"] >= 1
        assert result["file_ops"]["writes"] >= 1
        assert result["network_attempts"]["count"] >= 1
        assert "sh" in result["processes_spawned"]

    def test_job_creation_error_returns_error(self, sample_file):
        batch_api, core_api = _make_k8s_mocks()
        batch_api.create_namespaced_job.side_effect = Exception("quota exceeded")

        with patch.dict(os.environ, _ENV), \
             patch("tools.sandbox._load_kube_config"), \
             patch("kubernetes.client.BatchV1Api", return_value=batch_api), \
             patch("kubernetes.client.CoreV1Api", return_value=core_api):
            result = run_sandbox(sample_file)

        assert "error" in result
        assert "sandbox not available" in result["error"]

    def test_job_cleanup_deletes_configmap_and_job(self, sample_file):
        """After a successful run, both the Job and ConfigMap must be deleted."""
        batch_api, core_api = _make_k8s_mocks(log_text="")

        with patch.dict(os.environ, _ENV), \
             patch("tools.sandbox._load_kube_config"), \
             patch("kubernetes.client.BatchV1Api", return_value=batch_api), \
             patch("kubernetes.client.CoreV1Api", return_value=core_api):
            result = run_sandbox(sample_file, duration=5)

        assert "error" not in result
        batch_api.delete_namespaced_job.assert_called_once()
        core_api.delete_namespaced_config_map.assert_called()
        # ConfigMap delete called at least once (cleanup path; not the error path)
        delete_calls = core_api.delete_namespaced_config_map.call_count
        assert delete_calls >= 1


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

    def test_active_pod_triggers_gcore(self, tmp_path):
        _sandbox_module._state.update({
            "pod_name": "malsight-sandbox-abc-pod",
            "namespace": "default",
            "start_time": time.time(),
        })

        dump_bytes = b"\x4D\x5A" + b"\x00" * 2046
        # stream() is called three times: pgrep, gcore, cat
        stream_responses = ["42\n", "", dump_bytes.decode("latin-1")]

        mock_core_api = MagicMock()
        mock_stream = MagicMock(side_effect=stream_responses)

        with patch("tools.sandbox._load_kube_config"), \
             patch("kubernetes.client.CoreV1Api", return_value=mock_core_api), \
             patch("kubernetes.stream.stream", mock_stream), \
             patch("tools.sandbox.os.makedirs"), \
             patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.write = MagicMock()
            _sandbox_module._state["dump_path"] = None  # ensure no early return

            result = capture_memory_dump(timing=0)

        assert result["captured"] is True
        assert result["dump_size_bytes"] == len(dump_bytes)


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

    def test_active_pod_exec_parsed(self):
        _sandbox_module._state["pod_name"] = "malsight-sandbox-abc-pod"
        _sandbox_module._state["namespace"] = "default"

        inotify_output = (
            "CREATE /tmp/dropped.exe\n"
            "MODIFY /etc/crontab\n"
            "DELETE /tmp/original.sh\n"
        )
        mock_core_api = MagicMock()
        mock_stream = MagicMock(return_value=inotify_output)

        with patch("tools.sandbox._load_kube_config"), \
             patch("kubernetes.client.CoreV1Api", return_value=mock_core_api), \
             patch("kubernetes.stream.stream", mock_stream):
            result = monitor_filesystem()

        assert "/tmp/dropped.exe" in result["created"]
        assert "/etc/crontab" in result["modified"]
        assert "/tmp/original.sh" in result["deleted"]

    def test_pod_exec_error_returns_error(self):
        _sandbox_module._state["pod_name"] = "malsight-sandbox-abc-pod"
        _sandbox_module._state["namespace"] = "default"

        mock_core_api = MagicMock()
        mock_stream = MagicMock(side_effect=Exception("pod dead"))

        with patch("tools.sandbox._load_kube_config"), \
             patch("kubernetes.client.CoreV1Api", return_value=mock_core_api), \
             patch("kubernetes.stream.stream", mock_stream):
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
        _sandbox_module._state["pod_name"] = None  # no pod to copy from
        result = get_dropped_files()
        assert result == []
