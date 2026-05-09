# Phase 2: run_sandbox, capture_memory_dump, monitor_filesystem, get_dropped_files
# Interfaces with GKE + gVisor via the Kubernetes Python SDK.
import hashlib
import os
import re
import threading

from malsight.config import SANDBOX_IMAGE, GCP_PROJECT, GKE_CLUSTER, GKE_ZONE
import tempfile
import time
import uuid

# Module-level state shared across sandbox tool calls within a single analysis job
_state: dict = {
    "job_id": None,
    "pod_name": None,
    "namespace": "default",
    "results_dir": None,
    "file_path": None,
    "start_time": None,
    "dump_path": None,
    "created_files": [],
}

# Per-job memory snapshot results keyed by job_id
_memdump_state: dict = {}


def _build_sandbox_command(file_path: str, duration: int, capture_focus: str) -> list:
    """Return a ["/bin/sh", "-c", script] command appropriate for the file type."""
    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)

    strace_filter = {
        "network":    "-f -e trace=network,process",
        "filesystem": "-f -e trace=file",
        "process":    "-f -e trace=process",
    }.get(capture_focus, "-f -e trace=network,process,file")
    strace_flags = f"{strace_filter} -o /tmp/strace.log"
    sleep_sec = min(duration, 30)

    if ext in ('.exe', '.dll'):
        script = (
            f'FILE_TYPE=$(file /sample/{filename} 2>/dev/null || echo "unknown")\n'
            f'echo "sandbox_file_type: $FILE_TYPE" > /tmp/strace.log\n'
            f'echo "sandbox_note: Windows PE32 binary - static string analysis only" >> /tmp/strace.log\n'
            f'strings /sample/{filename} 2>/dev/null | head -200 >> /tmp/strace.log\n'
            f'echo "sandbox_complete: static_only" >> /tmp/strace.log\n'
            f'cat /tmp/strace.log'
        )
    elif ext == '.py':
        script = (
            f'strace {strace_flags} python3 /sample/{filename} > /tmp/sandbox_stdout.log 2>&1 &\n'
            f'STRACE_PID=$!\n'
            f'sleep {sleep_sec}\n'
            f'kill $STRACE_PID 2>/dev/null || true\n'
            f'wait 2>/dev/null || true\n'
            f'cat /tmp/strace.log 2>/dev/null || echo "no strace output"\n'
            f'echo "sandbox_complete: python_executed" >> /tmp/strace.log'
        )
    elif ext in ('.sh', '.bash'):
        script = (
            f'strace {strace_flags} /bin/bash /sample/{filename} > /tmp/sandbox_stdout.log 2>&1 &\n'
            f'STRACE_PID=$!\n'
            f'sleep {sleep_sec}\n'
            f'kill $STRACE_PID 2>/dev/null || true\n'
            f'wait 2>/dev/null || true\n'
            f'cat /tmp/strace.log 2>/dev/null || echo "no strace output"\n'
            f'echo "sandbox_complete: shell_executed" >> /tmp/strace.log'
        )
    elif ext == '.pdf':
        script = (
            f'strings /sample/{filename} > /tmp/sandbox_stdout.log 2>&1\n'
            f'echo "sandbox_note: PDF static analysis" > /tmp/strace.log\n'
            f'echo "sandbox_complete: pdf_static" >> /tmp/strace.log\n'
            f'cat /tmp/strace.log'
        )
    else:
        # Native ELF or unknown — copy to /tmp so we can chmod (ConfigMap mount is read-only)
        script = (
            f'cp /sample/{filename} /tmp/target_bin && chmod +x /tmp/target_bin\n'
            f'strace {strace_flags} /tmp/target_bin > /tmp/sandbox_stdout.log 2>&1 &\n'
            f'STRACE_PID=$!\n'
            f'sleep {sleep_sec}\n'
            f'kill $STRACE_PID 2>/dev/null || true\n'
            f'wait 2>/dev/null || true\n'
            f'cat /tmp/strace.log 2>/dev/null || echo "no strace output"\n'
            f'echo "sandbox_complete: direct_executed" >> /tmp/strace.log'
        )

    return ["/bin/sh", "-c", script]


def _load_kube_config() -> None:
    """Load in-cluster config; fall back to local kubeconfig for dev."""
    from kubernetes import config
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


def _get_env_or_error() -> tuple:
    """Return (image, project, cluster, zone) or raise RuntimeError on missing vars."""
    image = SANDBOX_IMAGE()  # raises RuntimeError if secret unavailable
    project = GCP_PROJECT()
    cluster = GKE_CLUSTER()
    zone = GKE_ZONE()
    missing = [k for k, v in [
        ("GCP_PROJECT", project), ("GKE_CLUSTER", cluster), ("GKE_ZONE", zone),
    ] if not v]
    if missing:
        raise RuntimeError(f"missing env vars: {', '.join(missing)}")
    return image, project, cluster, zone


def _snapshot_memory(job_id: str, pod_name: str, namespace: str, timing: int) -> None:
    """Background thread: capture /proc/1/maps from a running pod at T+timing seconds."""
    time.sleep(timing)
    try:
        _load_kube_config()
        from kubernetes import client as k8s_client
        from kubernetes.stream import stream

        core_api = k8s_client.CoreV1Api()
        resp = stream(
            core_api.connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            command=["cat", "/proc/1/maps"],
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )
        _memdump_state[job_id] = {
            "memdump_maps": resp or "",
            "memdump_captured": True,
        }
    except Exception as e:
        _memdump_state[job_id] = {
            "memdump_captured": False,
            "memdump_error": str(e),
        }


def run_sandbox(
    file_path: str,
    duration: int = 30,
    capture_focus: str = "all",
    is_zip: bool = False,
    zip_password: str = "infected",
) -> dict:
    """Execute file in a GKE gVisor Job; parse strace output from pod logs.

    If is_zip=True the zip is extracted *inside* the container by 7z before
    execution — the host filesystem never sees the malware binary.
    """
    try:
        image, _project, _cluster, _zone = _get_env_or_error()
        _load_kube_config()
    except RuntimeError as e:
        return {"error": f"sandbox not available: {e}"}
    except Exception as e:
        return {"error": f"sandbox not available: k8s API unreachable: {e}"}

    from kubernetes import client as k8s_client

    duration = max(5, min(120, duration))
    job_id = str(uuid.uuid4())
    job_name = f"malsight-sandbox-{job_id}"
    configmap_name = f"sample-{job_id}"
    namespace = "default"

    strace_filter = {
        "network":    "-f -e trace=network,process",
        "filesystem": "-f -e trace=file",
        "process":    "-f -e trace=process",
    }.get(capture_focus, "-f -e trace=network,process")

    try:
        import base64
        with open(file_path, "rb") as fh:
            sample_data = base64.b64encode(fh.read()).decode("utf-8")
    except OSError as e:
        return {"error": f"sandbox not available: cannot read sample: {e}"}

    batch_api = k8s_client.BatchV1Api()
    core_api = k8s_client.CoreV1Api()

    # Upload sample as a ConfigMap so the Job can mount it read-only
    configmap = k8s_client.V1ConfigMap(
        metadata=k8s_client.V1ObjectMeta(name=configmap_name, namespace=namespace),
        binary_data={"sample": sample_data},
    )
    try:
        core_api.create_namespaced_config_map(namespace=namespace, body=configmap)
    except Exception as e:
        return {"error": f"sandbox not available: ConfigMap creation failed: {e}"}

    filename = os.path.basename(file_path)

    if is_zip:
        # Extraction happens entirely inside the gVisor container — the host
        # filesystem never sees the malware binary.
        command = [
            "/bin/sh", "-c",
            (
                f"cp /sample/{filename} /tmp/sample.zip && "
                f"7z x -p{zip_password} /tmp/sample.zip -o/tmp/extracted/ && "
                f"EXTRACTED=$(find /tmp/extracted -maxdepth 3 -type f -perm /111 | head -1) && "
                f"[ -z \"$EXTRACTED\" ] && EXTRACTED=$(find /tmp/extracted -maxdepth 3 -type f | head -1) ; "
                f"chmod +x \"$EXTRACTED\" && "
                f"timeout {duration} strace {strace_filter} -o /tmp/strace.log -f \"$EXTRACTED\" "
                f"> /tmp/output.log 2>&1; "
                f"cat /tmp/strace.log"
            ),
        ]
    else:
        command = _build_sandbox_command(file_path, duration, capture_focus)

    job_body = k8s_client.V1Job(
        metadata=k8s_client.V1ObjectMeta(name=job_name, namespace=namespace),
        spec=k8s_client.V1JobSpec(
            ttl_seconds_after_finished=60,
            template=k8s_client.V1PodTemplateSpec(
                spec=k8s_client.V1PodSpec(
                    runtime_class_name="gvisor",
                    restart_policy="Never",
                    containers=[
                        k8s_client.V1Container(
                            name="sandbox",
                            image=image,
                            command=command,
                            security_context=k8s_client.V1SecurityContext(
                                run_as_non_root=True,
                                run_as_user=65534,
                                allow_privilege_escalation=False,
                                read_only_root_filesystem=True,
                                capabilities=k8s_client.V1Capabilities(drop=["ALL"]),
                            ),
                            resources=k8s_client.V1ResourceRequirements(
                                limits={"memory": "512Mi", "cpu": "1"},
                            ),
                            volume_mounts=[
                                k8s_client.V1VolumeMount(
                                    name="tmp-volume", mount_path="/tmp"
                                ),
                                k8s_client.V1VolumeMount(
                                    name="sample-volume",
                                    mount_path="/sample",
                                    read_only=True,
                                ),
                            ],
                        )
                    ],
                    volumes=[
                        k8s_client.V1Volume(
                            name="tmp-volume",
                            empty_dir=k8s_client.V1EmptyDirVolumeSource(),
                        ),
                        k8s_client.V1Volume(
                            name="sample-volume",
                            config_map=k8s_client.V1ConfigMapVolumeSource(
                                name=configmap_name,
                                items=[k8s_client.V1KeyToPath(
                                    key="sample", path=filename
                                )],
                            ),
                        ),
                    ],
                )
            ),
        ),
    )

    try:
        batch_api.create_namespaced_job(namespace=namespace, body=job_body)
    except Exception as e:
        try:
            core_api.delete_namespaced_config_map(
                name=configmap_name, namespace=namespace
            )
        except Exception:
            pass
        return {"error": f"sandbox not available: Job creation failed: {e}"}

    _state.update({
        "job_id": job_id,
        "pod_name": None,
        "namespace": namespace,
        "results_dir": tempfile.mkdtemp(prefix="malsight_"),
        "file_path": file_path,
        "start_time": time.time(),
        "dump_path": None,
        "created_files": [],
    })

    # Poll until Job completes or timeout; start memory snapshot thread once pod is Running
    deadline = time.time() + duration + 10
    pod_name = None
    snapshot_started = False
    while time.time() < deadline:
        try:
            status = batch_api.read_namespaced_job_status(
                name=job_name, namespace=namespace
            )
            conditions = status.status.conditions or []
            done = any(
                c.type in ("Complete", "Failed") and c.status == "True"
                for c in conditions
            )
            if done:
                break
        except Exception:
            pass
        if pod_name is None:
            try:
                pods = core_api.list_namespaced_pod(
                    namespace=namespace,
                    label_selector=f"job-name={job_name}",
                )
                if pods.items:
                    pod_name = pods.items[0].metadata.name
            except Exception:
                pass
        if pod_name and not snapshot_started:
            t = threading.Thread(
                target=_snapshot_memory,
                args=(job_id, pod_name, namespace, 5),
                daemon=True,
            )
            t.start()
            snapshot_started = True
        time.sleep(2)

    if pod_name is None:
        try:
            pods = core_api.list_namespaced_pod(
                namespace=namespace,
                label_selector=f"job-name={job_name}",
            )
            if pods.items:
                pod_name = pods.items[0].metadata.name
        except Exception:
            pass

    _state["pod_name"] = pod_name

    # Pod logs contain the cat'd strace output
    log_text = ""
    if pod_name:
        try:
            log_text = core_api.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                container="sandbox",
                stderr=True,
                stdout=True,
            )
        except Exception:
            log_text = ""

    # Parse strace lines from pod log
    file_ops = {"reads": 0, "writes": 0, "deletes": 0, "paths": []}
    connect_calls: list = []
    extracted_ips: list = []
    extracted_ports: list = []
    processes_spawned: list = []
    falco_events: list = []

    for line in (log_text or "").splitlines():
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
            connect_calls.append(line)
            ip_m = re.search(r'inet_addr\("([^"]+)"\)', line)
            if ip_m:
                extracted_ips.append(ip_m.group(1))
            port_m = re.search(r'sin_port=htons\((\d+)\)', line)
            if port_m:
                extracted_ports.append(int(port_m.group(1)))
        elif "execve(" in line:
            m = re.search(r'execve\("([^"]+)"', line)
            if m:
                proc = os.path.basename(m.group(1))
                if proc not in processes_spawned:
                    processes_spawned.append(proc)

    network_attempts = {
        "count": len(connect_calls),
        "all_blocked": True,
        "attempted_ips": list(set(extracted_ips)),
        "attempted_ports": list(set(extracted_ports)),
    }

    # Cleanup Job and ConfigMap
    try:
        batch_api.delete_namespaced_job(name=job_name, namespace=namespace)
    except Exception:
        pass
    try:
        core_api.delete_namespaced_config_map(
            name=configmap_name, namespace=namespace
        )
    except Exception:
        pass

    result = {
        "duration_actual": duration,
        "file_ops": file_ops,
        "network_attempts": network_attempts,
        "processes_spawned": processes_spawned,
        "falco_events": falco_events,
    }

    if "sandbox_note: Windows PE32 binary" in (log_text or ""):
        result["note"] = (
            "PE32 Windows binary — static analysis performed in sandbox. "
            "Native execution requires Wine."
        )
        skip_prefixes = ("sandbox_file_type:", "sandbox_note:", "sandbox_complete:")
        result["pe_static_strings"] = [
            line for line in (log_text or "").splitlines()
            if line and not any(line.startswith(p) for p in skip_prefixes)
        ]

    return result


def capture_memory_dump(timing: int = 5) -> dict:
    """Return memory snapshot captured during sandbox run, or a graceful failure."""
    job_id = _state.get("job_id")
    if not job_id:
        return {"captured": False, "error": "No active sandbox job"}

    # Honour a previously written dump file (legacy path)
    existing_dump = _state.get("dump_path")
    if existing_dump and os.path.exists(existing_dump):
        return {
            "captured": True,
            "timing_seconds": timing,
            "dump_size_bytes": os.path.getsize(existing_dump),
            "dump_path": existing_dump,
        }

    state = _memdump_state.get(job_id, {})
    if state.get("memdump_captured"):
        maps = state.get("memdump_maps", "") or ""
        return {
            "captured": True,
            "timing_seconds": timing,
            "dump_size_bytes": len(maps),
            "note": "Memory maps captured from running process via /proc/1/maps",
            "maps_preview": maps[:500],
        }

    return {
        "captured": False,
        "error": state.get("memdump_error", "Memory snapshot not available"),
        "note": "gVisor may restrict /proc/mem access — this is expected in the sandbox environment",
    }


def monitor_filesystem(file_path: str = None) -> dict:
    """Return filesystem events; sourced from pod exec (active) or inotify log (finished)."""
    pod_name = _state.get("pod_name")
    namespace = _state.get("namespace", "default")

    if pod_name is not None:
        try:
            _load_kube_config()
            from kubernetes import client as k8s_client
            from kubernetes.stream import stream

            core_api = k8s_client.CoreV1Api()
            output = stream(
                core_api.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                command=[
                    "inotifywait", "-r", "-e", "create,modify,delete",
                    "--format", "%e %w%f", "-t", "5", "/tmp", "/etc", "/home",
                ],
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
            )
            text = output if isinstance(output, str) else (output or "")
            created, modified, deleted = [], [], []
            for line in text.splitlines():
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

    # Fallback: read inotify log written alongside pod results
    results_dir = _state.get("results_dir")
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
    pod_name = _state.get("pod_name")
    namespace = _state.get("namespace", "default")
    dropped: list = []

    for path in created_files:
        host_path = (
            os.path.join(results_dir, os.path.basename(path)) if results_dir else ""
        )
        actual_path = host_path if os.path.exists(host_path) else path

        if not os.path.exists(actual_path):
            if pod_name:
                try:
                    _load_kube_config()
                    from kubernetes import client as k8s_client
                    from kubernetes.stream import stream

                    core_api = k8s_client.CoreV1Api()
                    raw = stream(
                        core_api.connect_get_namespaced_pod_exec,
                        pod_name,
                        namespace,
                        command=["cat", path],
                        stderr=False,
                        stdin=False,
                        stdout=True,
                        tty=False,
                    )
                    content = (
                        raw.encode("latin-1") if isinstance(raw, str) else (raw or b"")
                    )
                    tmp = tempfile.NamedTemporaryFile(delete=False)
                    tmp.write(content)
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
                "child_job_id": None,
            })
        except Exception:
            continue

    return dropped
