# MalSight — Developer Setup Guide

> AI-powered malware analyzer with Gemini 2.5 Flash agent brain, GKE sandbox, and real-time threat reports.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [GCP Access Setup](#3-gcp-access-setup)
4. [Environment Variables](#4-environment-variables)
5. [Starting All Services](#5-starting-all-services)
6. [Verifying the Stack](#6-verifying-the-stack)
7. [Running the Frontend](#7-running-the-frontend)
8. [Testing the Pipeline](#8-testing-the-pipeline)
9. [Project Structure](#9-project-structure)
10. [Common Errors and Fixes](#10-common-errors-and-fixes)
11. [Daily Dev Workflow](#11-daily-dev-workflow)

---

## 1. Architecture Overview

```
Browser (localhost:5173)
    ↓
React Frontend
    ↓
FastAPI (localhost:8000)
    ↓ enqueue job
Redis (via SSH tunnel → GCP Memorystore 10.143.223.187:6379)
    ↓ RQ worker picks up
Gemini Agent Loop (agent.py)
    ↓ calls tools
Tool Executor (tool_executor.py)
    ↓ sandbox tools
GKE gVisor Sandbox (us-central1-a)
    ↓ results
PostgreSQL (via Cloud SQL Proxy → 127.0.0.1:5432)
    ↓
FastAPI serves report
    ↓
React Frontend displays report
```

**Infrastructure (GCP, managed by Dev 1):**
- GKE cluster: `malsight-cluster` (us-central1-a) — runs sandbox jobs with gVisor isolation
- Cloud SQL: `malsight-db` (PostgreSQL 15) — stores jobs and reports
- Memorystore: Redis 7 (VPC-internal, reachable via SSH tunnel)
- Artifact Registry: sandbox Docker image at `us-central1-docker.pkg.dev/malsight/malsight/sandbox:latest`
- Secret Manager: stores all API keys (fallback: `.env` file for local dev)

---

## 2. Prerequisites

Install these before starting:

```bash
# Python 3.11+ (use pyenv)
pyenv install 3.11.9
pyenv local 3.11.9

# Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Google Cloud CLI
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init

# GKE auth plugin (required for kubectl to talk to GKE)
sudo apt-get install google-cloud-cli-gke-gcloud-auth-plugin
# OR:
gcloud components install gke-gcloud-auth-plugin

# kubectl
sudo snap install kubectl --classic

# 7zip (for extracting malware samples safely)
sudo apt-get install -y 7zip p7zip-full

# Cloud SQL Proxy
curl -o cloud-sql-proxy \
  https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.6.0/cloud-sql-proxy.linux.amd64
chmod +x cloud-sql-proxy
# Move it to the project root
```

---

## 3. GCP Access Setup

Ask Dev 1 to grant your GCP account these roles on the `malsight` project:

- `roles/container.developer` — spawn GKE sandbox jobs
- `roles/secretmanager.secretAccessor` — read API keys from Secret Manager
- `roles/cloudsql.client` — connect to PostgreSQL via proxy
- `roles/artifactregistry.reader` — pull the sandbox Docker image

Then authenticate:

```bash
# Login
gcloud auth login
gcloud auth application-default login
gcloud config set project malsight

# Connect kubectl to the GKE cluster
gcloud container clusters get-credentials malsight-cluster \
  --zone=us-central1-a \
  --project=malsight

# Verify kubectl works
kubectl get nodes
# Should show 3 nodes: default-pool + sandbox-pool
```

Authenticate Docker to pull the sandbox image:

```bash
gcloud auth configure-docker us-central1-docker.pkg.dev
docker pull us-central1-docker.pkg.dev/malsight/malsight/sandbox:latest
# Should download successfully
```

---

## 4. Environment Variables

Create a `.env` file in the project root. **Never commit this file.**

```dotenv
# Gemini (get from Google AI Studio: https://aistudio.google.com)
GEMINI_API_KEY=your_gemini_api_key_here

# Database (Cloud SQL Proxy listens on 127.0.0.1:5432)
DATABASE_URL=postgresql://malsight:YOUR_DB_PASSWORD@127.0.0.1:5432/malsight

# Redis (SSH tunnel forwards 127.0.0.1:6379 → Memorystore)
# IMPORTANT: use 127.0.0.1, NOT the Memorystore IP directly
REDIS_URL=redis://127.0.0.1:6379

# GCP
GCP_PROJECT=malsight
GKE_CLUSTER=malsight-cluster
GKE_ZONE=us-central1-a

# Sandbox image (no http:// prefix)
SANDBOX_IMAGE=us-central1-docker.pkg.dev/malsight/malsight/sandbox:latest

# Threat Intel APIs
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
MALWAREBAZAAR_API_KEY=your_malwarebazaar_key_here

# MalSight API (choose any string — used as Bearer token for the API)
MALSIGHT_API_KEYS=your_chosen_api_key_here
```

> Get API keys from:
> - MalwareBazaar + AbuseIPDB: https://auth.abuse.ch
> - VirusTotal: https://www.virustotal.com/gui/my-apikey
> - Gemini: https://aistudio.google.com/apikey

> DB password and other GCP values: ask Dev 1.

### Critical gotcha — shell environment variables override .env

If you ever set `REDIS_URL` or `DATABASE_URL` as shell variables in a previous session, they will override `.env`. Always unset before starting:

```bash
unset REDIS_URL DATABASE_URL GEMINI_API_KEY
```

---

## 5. Starting All Services

You need **4 terminals open simultaneously** every time you develop.

### Terminal 1 — SSH Tunnel (Redis)

Memorystore Redis is VPC-internal. You must tunnel through a GKE node to reach it:

```bash
gcloud compute ssh gke-malsight-cluster-default-pool-16aad609-r1n6 \
  --zone=us-central1-a \
  --project=malsight \
  -- -L 6379:10.143.223.187:6379 -N
```

This terminal will hang — that means the tunnel is active. **Keep it open.**

> If the node name has changed (Dev 1 rotated the cluster), run `gcloud compute instances list --project=malsight` to get the current node name.

### Terminal 2 — Cloud SQL Proxy (PostgreSQL)

```bash
cd ~/path/to/Malsight
./cloud-sql-proxy malsight:us-central1:malsight-db
```

Should print: `The proxy has started successfully and is ready for new connections!`

**Keep it open.**

### Terminal 3 — FastAPI Server

```bash
cd ~/path/to/Malsight

# First time only — install dependencies
poetry install

# Unset any stale env vars
unset REDIS_URL DATABASE_URL

# Start the server
python -m uvicorn api.main:app --port 8000
```

Should print: `Uvicorn running on http://127.0.0.1:8000`

### Terminal 4 — RQ Worker

```bash
cd ~/path/to/Malsight

# Unset stale env vars
unset REDIS_URL DATABASE_URL

rq worker malsight --url redis://127.0.0.1:6379
```

Should print: `*** Listening on malsight...`

> **Important:** Every time you change any Python file that the worker imports (agent.py, worker.py, db.py, tool_executor.py, any file in tools/), you must **Ctrl+C and restart the RQ worker**. It loads code once at startup and does not hot-reload.

---

## 6. Verifying the Stack

Run these checks after all 4 terminals are running:

```bash
# 1. DB
python -c "import psycopg2; conn = psycopg2.connect('postgresql://malsight:PASSWORD@127.0.0.1:5432/malsight'); print('DB OK')"

# 2. Redis
python -c "import redis; r = redis.from_url('redis://127.0.0.1:6379', socket_connect_timeout=3); print(r.ping())"
# Should print: True

# 3. Health endpoint
curl http://localhost:8000/health
# Should return: {"status":"ok","db_connected":true,...}

# 4. Submit a test file
echo "print('hello')" > /tmp/test.py
curl -X POST http://localhost:8000/analyze \
  -H "X-API-Key: YOUR_MALSIGHT_API_KEY" \
  -F "file=@/tmp/test.py" \
  -F "mode=standard"
# Should return: {"job_id":"...","status":"queued",...}
```

---

## 7. Running the Frontend

```bash
cd ~/path/to/Malsight/frontend

# First time only
npm install

# Create frontend env file
cat > .env.local << EOF
VITE_API_BASE_URL=http://localhost:8000
VITE_API_KEY=YOUR_MALSIGHT_API_KEY
EOF

# Start dev server
npm run dev
```

Open http://localhost:5173 in your browser.

---

## 8. Testing the Pipeline

### Test 1 — Benign file (fast-track, no sandbox)

```bash
echo "x = 1 + 1" > /tmp/benign.py

curl -X POST http://localhost:8000/analyze \
  -H "X-API-Key: YOUR_MALSIGHT_API_KEY" \
  -F "file=@/tmp/benign.py" \
  -F "mode=standard"
```

Expected: `verdict: benign`, ~5 seconds, 3-5 tool calls.

### Test 2 — EICAR test file (known hash hit)

```bash
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.exe

curl -X POST http://localhost:8000/analyze \
  -H "X-API-Key: YOUR_MALSIGHT_API_KEY" \
  -F "file=@/tmp/eicar.exe" \
  -F "mode=standard"
```

Expected: `verdict: benign`, `threat_category: test_file`, ~5 seconds, 2-3 tool calls.

### Test 3 — Real malware (MalwareBazaar sample)

```bash
# Download sample (password: infected)
python3 -c "
import requests, os
from dotenv import load_dotenv
load_dotenv(override=True)
api_key = os.getenv('MALWAREBAZAAR_API_KEY', '')
sha256 = '097a8878d5d1e4571dd09082069b71c7781b27ee6467e74b6adf5c4c8a580a24'
resp = requests.post(
    'https://mb-api.abuse.ch/api/v1/',
    headers={'Auth-Key': api_key},
    data={'query': 'get_file', 'sha256_hash': sha256},
    timeout=30
)
if resp.content[:2] == b'PK':
    with open('/tmp/malware.zip', 'wb') as f:
        f.write(resp.content)
    print('Saved to /tmp/malware.zip')
else:
    print('Error:', resp.text[:200])
"

# Extract with 7zip (NOT regular unzip — MalwareBazaar uses newer compression)
7z x /tmp/malware.zip -p"infected" -o/tmp/malware_sample/

# Submit (do NOT submit .zip directly — submit the extracted binary)
curl -X POST http://localhost:8000/analyze \
  -H "X-API-Key: YOUR_MALSIGHT_API_KEY" \
  -F "file=@/tmp/malware_sample/<extracted_filename>.exe" \
  -F "mode=deep_scan"

# Clean up after — never leave malware binaries on disk
rm -rf /tmp/malware_sample/ /tmp/malware.zip
```

> ⚠️ Always delete extracted malware samples immediately after submission. The binary is only needed for the upload — once MalSight has it, delete it from your local machine.

### Polling a report

```bash
# Poll until complete (Ctrl+C to stop)
watch -n 3 "curl -s http://localhost:8000/report/YOUR_JOB_ID \
  -H 'X-API-Key: YOUR_MALSIGHT_API_KEY' | python3 -m json.tool"
```

---

## 9. Project Structure

```
Malsight/
├── agent.py                  # Gemini agent loop — drives the entire analysis
├── tool_executor.py          # Dispatches agent tool calls to implementations
├── api/
│   ├── main.py               # FastAPI app entrypoint
│   ├── routes.py             # /analyze, /report, /reports, /health endpoints
│   ├── worker.py             # RQ job function — called by the worker process
│   └── db.py                 # PostgreSQL connection pool and query helpers
├── tools/
│   ├── threat_intel.py       # MalwareBazaar, VirusTotal, AbuseIPDB, domain checks
│   ├── static_analysis.py    # File magic, entropy, strings, PE imports/sections
│   ├── sandbox.py            # GKE Job creation, strace capture, memory dump
│   ├── memory.py             # PE header scan, shellcode detection, YARA
│   ├── anti_analysis.py      # Anti-debug, anti-VM, anti-sandbox detection
│   └── ioc.py                # IOC extraction, get_report() signal tool
├── malsight/
│   └── config.py             # get_secret() — reads from env or GCP Secret Manager
├── frontend/
│   ├── src/
│   │   ├── api.js            # Axios client — sets base URL and X-API-Key header
│   │   ├── App.jsx           # Router: / → Upload, /job/:id → Monitor, /reports → History
│   │   └── pages/
│   │       ├── Upload.jsx        # Drag-and-drop + mode selector
│   │       ├── AgentMonitor.jsx  # Live polling — shows agent steps in real time
│   │       ├── Report.jsx        # Full threat report with reasoning chain
│   │       └── History.jsx       # Paginated report history with filters
│   └── .env.local            # VITE_API_BASE_URL + VITE_API_KEY (create manually)
├── tests/                    # pytest unit tests — all tools + API + agent mocked
├── docs/
│   └── MalSight_PRD_v2_1.md  # Full product requirements document
├── cloud-sql-proxy            # Binary — run this to connect to Cloud SQL locally
├── pyproject.toml             # Poetry dependencies
└── .env                       # Local secrets — NEVER commit
```

---

## 10. Common Errors and Fixes

### `ModuleNotFoundError: No module named 'malsight.api'`
The project root is not in the Python path. Run uvicorn from the project root:
```bash
cd ~/path/to/Malsight
python -m uvicorn api.main:app --port 8000
```

### `Redis timeout / connection refused`
The SSH tunnel is not running. Start Terminal 1 first, wait for it to hang (that means it's active), then start everything else.

### `REDIS_URL` pointing to `10.143.223.187` instead of `127.0.0.1`
A stale shell variable is overriding `.env`. Fix:
```bash
unset REDIS_URL
# Also make sure .env has: REDIS_URL=redis://127.0.0.1:6379
```

### `psycopg2.errors.GeneratedAlways: column "elapsed_seconds" can only be updated to DEFAULT`
The `elapsed_seconds` column in the jobs table is auto-generated by PostgreSQL. Never pass it manually in `UPDATE` statements in `api/db.py`.

### `ConfigMap creation failed: Object of type bytes is not JSON serializable`
The sandbox file upload to Kubernetes needs base64 encoding. In `tools/sandbox.py`:
```python
import base64
with open(file_path, "rb") as fh:
    sample_data = base64.b64encode(fh.read()).decode("utf-8")
```

### `SANDBOX_IMAGE` has `http://` prefix
Remove the `http://` from the `.env` value:
```
# Wrong
SANDBOX_IMAGE=http://us-central1-docker.pkg.dev/malsight/malsight/sandbox:latest
# Correct
SANDBOX_IMAGE=us-central1-docker.pkg.dev/malsight/malsight/sandbox:latest
```

### `gke-gcloud-auth-plugin not found`
```bash
sudo apt-get install google-cloud-cli-gke-gcloud-auth-plugin
```

### `check_malwarebazaar()` returns `found: True` for every file
The MalwareBazaar API uses `Auth-Key` header (not `API-KEY`). The key must be sent as:
```python
headers={"Auth-Key": api_key}
```

### `unzip` fails on MalwareBazaar samples
MalwareBazaar zips use compression level 5.1. Use 7zip instead:
```bash
7z x malware.zip -p"infected" -o./output/
```

### RQ worker not picking up new code changes
The worker caches code at startup. After any Python file change, always restart:
```bash
# Ctrl+C the worker terminal, then:
rq worker malsight --url redis://127.0.0.1:6379
```

### `FutureWarning: google.generativeai is deprecated`
The old SDK reached end-of-life November 2025. Migrate `agent.py` to `google-genai`:
```bash
pip install google-genai
# Then update agent.py imports from google.generativeai to google.genai
```

---

## 11. Daily Dev Workflow

Every day when you sit down to work:

```bash
# 1. Open Terminal 1 — SSH tunnel
gcloud compute ssh gke-malsight-cluster-default-pool-16aad609-r1n6 \
  --zone=us-central1-a --project=malsight \
  -- -L 6379:10.143.223.187:6379 -N

# 2. Open Terminal 2 — Cloud SQL proxy
./cloud-sql-proxy malsight:us-central1:malsight-db

# 3. Open Terminal 3 — FastAPI (unset stale vars first)
unset REDIS_URL DATABASE_URL
python -m uvicorn api.main:app --port 8000

# 4. Open Terminal 4 — RQ worker (unset stale vars first)
unset REDIS_URL DATABASE_URL
rq worker malsight --url redis://127.0.0.1:6379

# 5. Open Terminal 5 — Frontend
cd frontend && npm run dev

# 6. Verify everything
curl http://localhost:8000/health
# Open http://localhost:5173
```

When you shut down — just Ctrl+C all 4 terminals. No cleanup needed.

---

*MalSight SETUP.md — last updated May 2026*
*For PRD, architecture details, and API spec see docs/MalSight_PRD_v2_1.md*
