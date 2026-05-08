# Phase 2: run_sandbox, capture_memory_dump, monitor_filesystem, get_dropped_files
# Interfaces with GKE + gVisor via the Kubernetes Python SDK.
import hashlib
import os
import re
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


def _load_kube_config() -> None:
    """Load in-cluster config; fall back to local kubeconfig for dev."""
    from kubernetes import config
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


def _get_env_or_error() -> tuple:
    """Return (image, project, cluster, zone) or raise RuntimeError on missing vars."""
    image = os.environ.get("SANDBOX_IMAGE")
    project = os.environ.get("GCP_PROJECT")
    cluster = os.environ.get("GKE_CLUSTER")
    zone = os.environ.get("GKE_ZONE")
    missing = [k for k, v in [
        ("SANDBOX_IMAGE", image), ("GCP_PROJECT", project),
        ("GKE_CLUSTER", cluster), ("GKE_ZONE", zone),
    ] if not v]
    if missing:
        raise RuntimeError(f"missing env vars: {', '.join(missing)}")
    return image, project, cluster, zone


def run_sandbox(file_path: str, duration: int = 30, capture_focus: str = "all") -> dict:
    """Execute file in a GKE gVisor Job; parse strace output from pod logs."""
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
        "network":    "-e trace=network",
        "filesystem": "-e trace=file",
        "process":    "-e trace=process",
    }.get(capture_focus, "-f")

    try:
        with open(file_path, "rb") as fh:
            sample_data = fh.read()
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

    command = [
        "/bin/sh", "-c",
        (
            f"cp /sample/sample /tmp/target && "
            f"chmod +x /tmp/target && "
            f"timeout {duration} strace {strace_filter} -o /tmp/strace.log /tmp/target "
            f"> /tmp/output.log 2>&1; "
            f"cat /tmp/strace.log"
        ),
    ]

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
                                name=configmap_name
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

    # Poll until Job completes or timeout
    deadline = time.time() + duration + 10
    pod_name = None
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
                name=pod_name, namespace=namespace
            )
        except Exception:
            log_text = ""

    # Parse strace lines from pod log
    file_ops = {"reads": 0, "writes": 0, "deletes": 0, "paths": []}
    network_attempts = {"count": 0, "all_blocked": True}
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
            network_attempts["count"] += 1
        elif "execve(" in line:
            m = re.search(r'execve\("([^"]+)"', line)
            if m:
                proc = os.path.basename(m.group(1))
                if proc not in processes_spawned:
                    processes_spawned.append(proc)

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

    return {
        "duration_actual": duration,
        "file_ops": file_ops,
        "network_attempts": network_attempts,
        "processes_spawned": processes_spawned,
        "falco_events": falco_events,
    }


def capture_memory_dump(timing: int = 5) -> dict:
    """Exec gcore inside the running pod at T+timing seconds; copy dump locally."""
    pod_name = _state.get("pod_name")
    start_time = _state.get("start_time")
    namespace = _state.get("namespace", "default")

    existing_dump = _state.get("dump_path")
    if existing_dump and os.path.exists(existing_dump):
        return {
            "captured": True,
            "timing_seconds": timing,
            "dump_size_bytes": os.path.getsize(existing_dump),
            "dump_path": existing_dump,
        }

    if pod_name is None:
        return {"captured": False, "error": "no active sandbox pod"}

    if start_time:
        elapsed = time.time() - start_time
        wait_time = timing - elapsed
        if wait_time > 0:
            time.sleep(wait_time)

    try:
        _load_kube_config()
        from kubernetes import client as k8s_client
        from kubernetes.stream import stream

        core_api = k8s_client.CoreV1Api()

        pid_output = stream(
            core_api.connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            command=["sh", "-c", "pgrep -n -f /tmp/target || pgrep -n -f wine"],
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )
        pid_str = (pid_output or "").strip().split("\n")[0].strip()
        if not pid_str.isdigit():
            return {"captured": False, "error": "could not determine target PID"}

        stream(
            core_api.connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            command=["gcore", "-o", "/tmp/memdump.bin", pid_str],
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )

        raw = stream(
            core_api.connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            command=["cat", "/tmp/memdump.bin"],
            stderr=False,
            stdin=False,
            stdout=True,
            tty=False,
        )
        dump_bytes = raw.encode("latin-1") if isinstance(raw, str) else (raw or b"")

        dump_dir = "/tmp/results"
        os.makedirs(dump_dir, exist_ok=True)
        dump_path = os.path.join(dump_dir, "memdump.bin")
        with open(dump_path, "wb") as fh:
            fh.write(dump_bytes)

        _state["dump_path"] = dump_path
        return {
            "captured": True,
            "timing_seconds": timing,
            "dump_size_bytes": len(dump_bytes),
            "dump_path": dump_path,
        }

    except Exception as e:
        return {"captured": False, "error": str(e)}


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
