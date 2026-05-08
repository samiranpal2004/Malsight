# Phase 2: run_sandbox, capture_memory_dump, monitor_filesystem, get_dropped_files
# Interfaces with the malsight-sandbox Docker container via the Docker Python SDK.
import hashlib
import os
import tempfile
import threading
import time

# Module-level state shared across sandbox tool calls within a single analysis job
_state: dict = {
    "container": None,
    "client": None,
    "results_dir": None,
    "file_path": None,
    "start_time": None,
    "dump_path": None,
    "created_files": [],
}


def _get_docker_client():
    """Return a Docker client or raise if unavailable."""
    try:
        import docker
        return docker.from_env()
    except ImportError:
        raise RuntimeError("docker Python SDK not installed (pip install docker)")
    except Exception as e:
        raise RuntimeError(f"Docker daemon unreachable: {e}")


def _schedule_gcore(container, results_dir: str, timing: int) -> None:
    """Background thread: exec gcore inside container at `timing` seconds after start."""
    time.sleep(timing)
    try:
        pid_result = container.exec_run(
            "sh -c 'pgrep -n -f /tmp/target || pgrep -n -f wine'",
            demux=False,
        )
        pid_str = (pid_result.output or b"").decode().strip().split("\n")[0].strip()
        if pid_str.isdigit():
            dump_path = "/results/memdump.bin"
            container.exec_run(f"gcore -o {dump_path} {pid_str}", demux=False)
            host_dump = os.path.join(results_dir, "memdump.bin")
            _state["dump_path"] = host_dump
    except Exception:
        pass


def run_sandbox(file_path: str, duration: int = 30, capture_focus: str = "all") -> dict:
    """Execute file in malsight-sandbox container; capture strace/Falco output."""
    try:
        client = _get_docker_client()
    except RuntimeError as e:
        return {"error": f"sandbox not available: {e}"}

    try:
        client.images.get("malsight-sandbox")
    except Exception:
        return {"error": "sandbox not available: malsight-sandbox image not found"}

    # Clamp duration
    duration = max(5, min(120, duration))

    results_dir = tempfile.mkdtemp(prefix="malsight_")
    file_name = os.path.basename(file_path)
    file_dir = os.path.dirname(os.path.abspath(file_path))

    strace_filter = {
        "network":    "-e trace=network",
        "filesystem": "-e trace=file",
        "process":    "-e trace=process",
    }.get(capture_focus, "-f")

    command = (
        f"/bin/sh -c '"
        f"cp /sample/{file_name} /tmp/target && "
        f"chmod +x /tmp/target && "
        f"strace {strace_filter} -o /results/trace.log /tmp/target "
        f"> /results/output.log 2>&1 &"
        f"'"
    )

    _state.update({
        "client": client,
        "results_dir": results_dir,
        "file_path": file_path,
        "start_time": time.time(),
        "dump_path": None,
        "created_files": [],
    })

    try:
        container = client.containers.run(
            "malsight-sandbox",
            command=command,
            volumes={
                file_dir: {"bind": "/sample", "mode": "ro"},
                results_dir: {"bind": "/results", "mode": "rw"},
            },
            network_mode="none",
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            remove=False,
            detach=True,
        )
        _state["container"] = container

        # Schedule automatic gcore dump at T+min(5, duration//2)
        auto_timing = min(5, max(2, duration // 2))
        gcore_thread = threading.Thread(
            target=_schedule_gcore,
            args=(container, results_dir, auto_timing),
            daemon=True,
        )
        gcore_thread.start()

        # Wait for container to finish (or duration + buffer)
        try:
            container.wait(timeout=duration + 10)
        except Exception:
            try:
                container.kill()
            except Exception:
                pass

        gcore_thread.join(timeout=2)

        # Parse strace output
        file_ops = {"reads": 0, "writes": 0, "deletes": 0, "paths": []}
        network_attempts = {"count": 0, "all_blocked": True}
        processes_spawned: list = []
        falco_events: list = []

        trace_path = os.path.join(results_dir, "trace.log")
        if os.path.exists(trace_path):
            with open(trace_path, "r", errors="ignore") as fh:
                import re
                for line in fh:
                    if "openat(" in line or "open(" in line:
                        file_ops["reads"] += 1
                        m = re.search(r'"([^"]+)"', line)
                        if m and m.group(1) not in file_ops["paths"]:
                            file_ops["paths"].append(m.group(1))
                    elif "write(" in line:
                        file_ops["writes"] += 1
                    elif "unlink" in line:
                        file_ops["deletes"] += 1
                    elif "connect(" in line:
                        network_attempts["count"] += 1
                    elif "execve(" in line:
                        m = re.search(r'execve\("([^"]+)"', line)
                        if m:
                            proc = os.path.basename(m.group(1))
                            if proc not in processes_spawned:
                                processes_spawned.append(proc)

        # Parse Falco events if present
        falco_path = os.path.join(results_dir, "falco.log")
        if os.path.exists(falco_path):
            with open(falco_path, "r", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        falco_events.append(line)

        try:
            container.remove()
        except Exception:
            pass
        _state["container"] = None

        return {
            "duration_actual": duration,
            "file_ops": file_ops,
            "network_attempts": network_attempts,
            "processes_spawned": processes_spawned,
            "falco_events": falco_events[:50],
        }

    except Exception as e:
        # Cleanup on error
        try:
            if _state.get("container"):
                _state["container"].remove(force=True)
                _state["container"] = None
        except Exception:
            pass
        return {"error": f"sandbox not available: {e}"}


def capture_memory_dump(timing: int = 5) -> dict:
    """Capture gcore memory dump of the running sandbox process at `timing` seconds."""
    results_dir = _state.get("results_dir")
    start_time = _state.get("start_time")
    container = _state.get("container")

    # If a dump was already captured by the background thread, return it
    existing_dump = _state.get("dump_path")
    if existing_dump and os.path.exists(existing_dump):
        return {
            "captured": True,
            "timing_seconds": timing,
            "dump_size_bytes": os.path.getsize(existing_dump),
            "dump_path": existing_dump,
        }

    if container is None:
        return {"captured": False, "error": "no active sandbox container"}

    # Wait until timing seconds have elapsed since sandbox start
    if start_time:
        elapsed = time.time() - start_time
        wait_time = timing - elapsed
        if wait_time > 0:
            time.sleep(wait_time)

    try:
        pid_result = container.exec_run(
            "sh -c 'pgrep -n -f /tmp/target || pgrep -n -f wine'",
            demux=False,
        )
        pid_str = (pid_result.output or b"").decode().strip().split("\n")[0].strip()
        if not pid_str.isdigit():
            return {"captured": False, "error": "could not determine target PID"}

        dump_path_container = "/results/memdump.bin"
        container.exec_run(f"gcore -o {dump_path_container} {pid_str}", demux=False)

        host_dump = os.path.join(results_dir or "/tmp/results", "memdump.bin")
        _state["dump_path"] = host_dump

        if os.path.exists(host_dump):
            return {
                "captured": True,
                "timing_seconds": timing,
                "dump_size_bytes": os.path.getsize(host_dump),
                "dump_path": host_dump,
            }
        return {"captured": False, "error": "gcore ran but dump file not found on host"}
    except Exception as e:
        return {"captured": False, "error": str(e)}


def monitor_filesystem(file_path: str = None) -> dict:
    """Return filesystem create/modify/delete events recorded during sandbox run."""
    results_dir = _state.get("results_dir")
    container = _state.get("container")

    # If sandbox is active, exec inotifywait for a short window
    if container is not None:
        try:
            result = container.exec_run(
                "inotifywait -r -e create,modify,delete --format '%e %w%f' "
                "-t 5 /tmp /etc /home 2>/dev/null",
                demux=False,
            )
            output = (result.output or b"").decode("utf-8", errors="ignore")
            created, modified, deleted = [], [], []
            for line in output.splitlines():
                parts = line.strip().split(" ", 1)
                if len(parts) == 2:
                    event_type, path = parts
                    if "CREATE" in event_type:
                        created.append(path)
                    elif "MODIFY" in event_type:
                        modified.append(path)
                    elif "DELETE" in event_type:
                        deleted.append(path)
            _state["created_files"] = created
            return {"created": created, "modified": modified, "deleted": deleted}
        except Exception as e:
            return {"error": str(e)}

    # Fallback: read inotify log if container already finished
    inotify_log = os.path.join(results_dir or "/tmp", "inotify.log")
    if os.path.exists(inotify_log):
        created, modified, deleted = [], [], []
        with open(inotify_log, "r", errors="ignore") as fh:
            for line in fh:
                parts = line.strip().split(" ", 1)
                if len(parts) == 2:
                    event_type, path = parts
                    if "CREATE" in event_type:
                        created.append(path)
                    elif "MODIFY" in event_type:
                        modified.append(path)
                    elif "DELETE" in event_type:
                        deleted.append(path)
        _state["created_files"] = created
        return {"created": created, "modified": modified, "deleted": deleted}

    return {"created": [], "modified": [], "deleted": []}


def get_dropped_files() -> list:
    """Extract content + SHA-256 of files created during sandbox execution."""
    results_dir = _state.get("results_dir", "")
    created_files = _state.get("created_files", [])
    dropped: list = []

    for path in created_files:
        # Files written inside the container are accessible via the shared results_dir
        # or the container filesystem — try to copy them out
        host_path = os.path.join(results_dir, os.path.basename(path)) if results_dir else ""
        actual_path = host_path if os.path.exists(host_path) else path

        if not os.path.exists(actual_path):
            # Attempt to copy from container
            container = _state.get("container")
            if container:
                try:
                    bits, _ = container.get_archive(path)
                    tmp = tempfile.NamedTemporaryFile(delete=False)
                    for chunk in bits:
                        tmp.write(chunk)
                    tmp.close()
                    actual_path = tmp.name
                except Exception:
                    continue
            else:
                continue

        try:
            with open(actual_path, "rb") as fh:
                content = fh.read()
            sha256 = hashlib.sha256(content).hexdigest()
            size = len(content)

            mime = "application/octet-stream"
            try:
                import magic
                mime = magic.from_buffer(content, mime=True)
            except Exception:
                pass

            dropped.append({
                "path": path,
                "sha256": sha256,
                "size_bytes": size,
                "mime": mime,
                "child_job_id": None,  # Set by the worker when it enqueues a child job
            })
        except Exception:
            continue

    return dropped
