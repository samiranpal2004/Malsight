"""Start MalSight RQ workers for local dev.

Run from the project root:
    python scripts/start_worker.py

Two worker processes are started so that process_email and analyze_file_job
can run concurrently.  Without a second worker, process_email blocks polling
for analyze_file_job while the only worker is busy — causing a deadlock where
analyze_file_job stays queued forever.
"""
import multiprocessing
import os
import sys

# Put mail_processor/ on the path so RQ can import process_email
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_root, "mail_processor"))
sys.path.insert(0, _root)

from dotenv import load_dotenv
load_dotenv(os.path.join(_root, ".env"))

_redis_url = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")


def _run_worker(worker_id: int) -> None:
    import redis
    from rq import Worker, Queue

    conn = redis.from_url(_redis_url)
    queues = [Queue("malsight", connection=conn)]
    worker = Worker(queues, connection=conn, name=f"malsight-worker-{worker_id}")
    print(f"[worker-{worker_id}] starting — queue: malsight  redis: {_redis_url}")
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    print(f"MALSIGHT_API_URL : {os.environ.get('MALSIGHT_API_URL', 'http://localhost:8000')}")
    print(f"UPLOAD_DIR       : {os.environ.get('UPLOAD_DIR', '(default temp dir)')}")
    print("Starting 2 workers to handle concurrent process_email + analyze_file_job jobs...")

    procs = []
    for i in range(1, 3):
        p = multiprocessing.Process(target=_run_worker, args=(i,), daemon=True)
        p.start()
        procs.append(p)

    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        print("\nShutting down workers...")
        for p in procs:
            p.terminate()
