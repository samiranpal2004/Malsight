# MalSight 🔍

**AI-powered malware analyzer with an adaptive Gemini agent brain.**

Upload a suspicious file. Watch a Gemini 1.5 Pro agent reason through the investigation in real time — calling the right tools in the right order — and receive a structured threat report with full MITRE ATT&CK mapping and a step-by-step explanation of every decision it made.

---

## The Problem

### Signature-based AV is dead against modern threats

Traditional antivirus relies on known signatures. Novel malware, polymorphic packers, and AI-generated samples have no signatures — they sail straight through.

### Fixed-pipeline sandboxes are nearly as bad

Even behavioral sandboxes fail when they treat every file identically:

| Scenario | Fixed Pipeline | A Real Analyst |
|---|---|---|
| Clearly benign Python script | Runs full sandbox + memory dump anyway | Checks strings and entropy, done in 5s |
| Known-malicious hash | Spins up sandbox before checking the hash DB | Hash lookup, verdict in 2s |
| UPX-packed binary | Dumps memory at T+5s regardless of packer | Identifies packer first, times dump to decompression window |
| PDF with embedded JS | Generic strace misses JavaScript execution | Calls PDF structure analysis first |
| Anti-sandbox malware | Gets a clean run — malware detected the VM | Detects evasion techniques, adjusts environment |

**A fixed pipeline's quality is bounded by whoever designed it. An adaptive agent is not.**

---

## The Solution

MalSight replaces the fixed pipeline with a **Gemini 1.5 Pro agent** that acts as a senior malware analyst:

1. It receives the file and initial metadata
2. It forms a hypothesis and calls tools strategically — not exhaustively
3. It follows unexpected findings (injected PE? re-analyze it. Anti-sandbox code? adjust the environment)
4. When it has enough evidence, it calls `get_report()` and the investigation closes

Every reasoning step and tool call is captured as an **Analysis Reasoning Chain** — analysts see exactly why each decision was made, not just the verdict.

### Three analysis layers

- **Static analysis** — file type, entropy, PE structure, packer detection, hash lookups, digital signatures
- **Dynamic behavioral analysis** — isolated sandbox execution under strace + Falco
- **RAM forensics** — live memory dump at agent-chosen timing, revealing unpacked payloads, decrypted C2 strings, and injected DLLs invisible on disk

---

## Demo Scenarios

| File Type | Agent Pattern | Time |
|---|---|---|
| Benign Python script | Hash check → strings → entropy → `get_report(benign)` | ~8s |
| Known-malicious hash | `check_malwarebazaar()` → hit → `get_report(malicious)` | ~3s |
| UPX-packed trojan | PE sections → detect packer → sandbox + memory dump → injected PE extraction → C2 reputation → report | ~45s |
| PDF with embedded JS | PDF structure → JS found → sandbox → dropped files → IOC enrichment → report | ~50s |
| Anti-sandbox malware | Sandbox (clean run) → detect anti-VM → detect sleep evasion → re-run with bypass → memory dump → report | ~3 min |

---

## Architecture

```
User uploads file
       ↓
FastAPI (file validation → UUID job_id)
       ↓
Redis + RQ (async job queue)
       ↓
┌─────────────────────────────────┐
│       GEMINI AGENT LOOP         │
│                                 │
│  Think → Call tool(s)           │
│  Tool executes → JSON result    │
│  Reason → next tool or report   │
│                                 │
│  Ends when: get_report() called │
│  or max iterations reached      │
└─────────────────────────────────┘
       ↓
Threat report + reasoning chain → PostgreSQL
       ↓
React frontend displays live agent status + final report
       ↓
GKE sandbox pod destroyed
```

**GCP Infrastructure:**

```
GKE Cluster (malsight-cluster)
├── default-pool          ← GKE system workloads
└── sandbox-pool (gVisor) ← malware execution pods
                            cap_drop: ALL, network: none, readOnly FS

Cloud SQL (PostgreSQL 15)  ← report + reasoning chain storage
Cloud Memorystore (Redis 7) ← job queue
Artifact Registry          ← sandbox container image
Secret Manager             ← API keys (Gemini, VT, AbuseIPDB)
Cloud Run                  ← API + worker services
```

---

## Tool Catalog (30 tools across 6 categories)

**Threat Intelligence** — `check_malwarebazaar`, `check_virustotal`, `check_ip_reputation`, `check_domain_reputation`

**Static Analysis** — `get_file_magic`, `get_entropy`, `extract_strings`, `get_pe_imports`, `get_pe_sections`, `detect_packer`, `check_digital_signature`, `get_compile_timestamp`, `analyze_pdf_structure`, `deobfuscate_script`

**Sandbox Execution** — `run_sandbox`, `capture_memory_dump`, `monitor_filesystem`, `get_dropped_files`

**Memory Forensics** — `scan_pe_headers`, `extract_strings_from_memory`, `detect_shellcode`, `get_memory_entropy`, `analyze_injected_pe`, `run_yara`

**Anti-Analysis Detection** — `detect_anti_debug`, `detect_anti_vm`, `detect_anti_sandbox`

**IOC + Control** — `extract_iocs`, `get_report`

---

## Analysis Modes

| | Standard ⚡ | Deep Scan 🔬 |
|---|---|---|
| Target time | < 60 seconds | < 5 minutes |
| Max agent iterations | 8 | 20 |
| Max sandbox duration | 30s | 120s |
| All IOC enrichment | Top 1 only | All IOCs |
| YARA full ruleset | ❌ | ✅ |
| Dropped file child analysis | Queued | Inline |
| Anti-sandbox bypass | ❌ | ✅ |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 + Tailwind CSS |
| API Backend | FastAPI (Python) |
| Job Queue | Redis 7 + RQ |
| Agent Brain | Google Gemini 1.5 Pro (function calling) |
| Sandbox | Docker + GKE gVisor |
| Syscall Capture | strace |
| Behavioral Monitor | Falco 0.38+ |
| Memory Capture | gdb / gcore |
| Static Analysis | pefile, libmagic, yara-python |
| PDF Analysis | pdfminer.six + pikepdf |
| Threat Intel APIs | MalwareBazaar, VirusTotal, AbuseIPDB |
| Database | PostgreSQL 15 (Cloud SQL) |
| Infrastructure | GKE, Cloud Memorystore, Artifact Registry, Secret Manager |

---

## Setup

### Prerequisites

- GCP project with billing enabled
- `gcloud` CLI authenticated (`gcloud auth login`)
- `kubectl`, `docker`, `psql` installed
- API keys: Gemini, VirusTotal, AbuseIPDB

### 1. Clone and configure

```bash
git clone https://github.com/your-team/malsight.git
cd malsight
cp .env.example .env
# Fill in your API keys in .env
```

### 2. GCP infrastructure

```bash
# Enable required APIs
gcloud services enable \
  container.googleapis.com sqladmin.googleapis.com \
  redis.googleapis.com artifactregistry.googleapis.com \
  secretmanager.googleapis.com run.googleapis.com

# Artifact Registry
gcloud artifacts repositories create malsight \
  --repository-format=docker --location=us-central1
gcloud auth configure-docker us-central1-docker.pkg.dev

# GKE cluster + gVisor sandbox pool
gcloud container clusters create malsight-cluster \
  --zone=us-central1-a --num-nodes=1 \
  --machine-type=e2-standard-4 --enable-ip-alias

gcloud container node-pools create sandbox-pool \
  --cluster=malsight-cluster --zone=us-central1-a \
  --num-nodes=1 --machine-type=e2-standard-4 \
  --image-type=COS_CONTAINERD --sandbox type=gvisor

# Cloud SQL
gcloud sql instances create malsight-db \
  --database-version=POSTGRES_15 --tier=db-f1-micro --region=us-central1
gcloud sql databases create malsight --instance=malsight-db
gcloud sql users create malsight --instance=malsight-db --password=YOUR_PASSWORD

# Cloud Memorystore (Redis)
gcloud redis instances create malsight-redis \
  --size=1 --region=us-central1 --redis-version=redis_7_0
```

### 3. Store secrets

```bash
echo -n "YOUR_GEMINI_KEY"    | gcloud secrets create GEMINI_API_KEY --data-file=-
echo -n "YOUR_VT_KEY"        | gcloud secrets create VIRUSTOTAL_API_KEY --data-file=-
echo -n "YOUR_ABUSEIPDB_KEY" | gcloud secrets create ABUSEIPDB_API_KEY --data-file=-
echo -n "YOUR_DB_PASSWORD"   | gcloud secrets create DB_PASSWORD --data-file=-
```

### 4. Apply database schema

```bash
# Connect via Cloud Shell (easiest) or Cloud SQL Proxy
gcloud sql connect malsight-db --user=malsight --database=malsight
# Paste contents of db/migrations/001_init.sql
```

### 5. Build and push the sandbox image

```bash
docker build -t us-central1-docker.pkg.dev/YOUR_PROJECT/malsight/sandbox:latest sandbox/
docker push us-central1-docker.pkg.dev/YOUR_PROJECT/malsight/sandbox:latest
```

### 6. Get kubectl credentials and verify gVisor

```bash
gcloud container clusters get-credentials malsight-cluster --zone=us-central1-a
kubectl get runtimeclass gvisor
# Expected: NAME=gvisor  HANDLER=gvisor
```

### 7. Deploy API + worker

```bash
# Deploy to Cloud Run (or run locally for dev)
docker-compose up        # local dev
# or
gcloud run deploy ...    # production
```

---

## API

```
POST /analyze          Upload file + select mode → returns job_id immediately
GET  /report/{id}      Poll status (live agent step while running) or fetch completed report
GET  /reports          List all past reports (filterable by verdict, mode)
GET  /health           Service status + queue depth
```

**Submit a file:**
```bash
curl -X POST https://YOUR_API/analyze \
  -H "X-API-Key: your_key" \
  -F "file=@suspicious.exe" \
  -F "mode=deep_scan"
```

**Response:**
```json
{ "job_id": "a3f9c12e-...", "status": "queued", "mode": "deep_scan", "estimated_seconds": 180 }
```

**Supported file types:** `.exe` `.dll` `.py` `.sh` `.bash` `.pdf` `.zip` — max 50MB

---

## Example Report Output

```json
{
  "verdict": "malicious",
  "confidence": 97,
  "threat_category": "trojan",
  "severity": "critical",
  "summary": "UPX-packed trojan dropper. Real payload recovered from memory dump — invisible on disk. Injects a DLL into a remote process, reads browser credentials, establishes registry persistence, contacts a known C2 IP (97/100 AbuseIPDB score).",
  "key_indicators": [
    "UPX packing confirmed — payload only visible in memory",
    "Injected PE at offset 0x3f2000 (reflective DLL injection)",
    "Decrypted C2 URL from memory: http://185.220.101.45/gate.php",
    "C2 IP reputation: 97/100 abuse score",
    "Registry persistence: HKCU\\...\\Run"
  ],
  "mitre_techniques": [
    { "id": "T1027.002", "name": "Software Packing",            "tactic": "Defense Evasion" },
    { "id": "T1055.001", "name": "DLL Injection",               "tactic": "Defense Evasion" },
    { "id": "T1555.003", "name": "Credentials from Web Browsers","tactic": "Credential Access" },
    { "id": "T1547.001", "name": "Registry Run Keys",           "tactic": "Persistence" },
    { "id": "T1041",     "name": "Exfiltration Over C2 Channel","tactic": "Exfiltration" }
  ],
  "recommended_action": "Quarantine",
  "tools_called": 5,
  "analysis_time_seconds": 48
}
```

---

## Sandbox Isolation

Every malware sample executes inside a GKE Pod with gVisor (kernel-level syscall interception):

- `runtimeClassName: gvisor` — gVisor intercepts all syscalls, host kernel never touched
- `capabilities: drop: ALL` — no Linux capabilities
- `network: none` — zero outbound connectivity
- `readOnlyRootFilesystem: true` — no persistent writes outside tmpfs
- `runAsUser: 65534` (nobody) — unprivileged execution
- Pod auto-deleted 60 seconds after job completion

---

## Project Structure

```
malsight/
├── api/                  FastAPI backend
│   └── main.py
├── worker/               RQ worker + agent runner
│   ├── agent.py          Gemini agent loop
│   └── tool_executor.py  Tool dispatch
├── tools/                30 analysis tool implementations
│   ├── threat_intel/
│   ├── static/
│   ├── sandbox/
│   ├── memory/
│   ├── anti_analysis/
│   └── ioc/
├── sandbox/              Docker image for malware execution
│   ├── Dockerfile
│   └── entrypoint.sh
├── frontend/             React + Tailwind dashboard
├── k8s/
│   └── sandbox-job.yaml  Kubernetes Job template (gVisor)
├── db/
│   └── migrations/
│       └── 001_init.sql
├── scripts/
│   └── verify_sandbox.sh
└── docker-compose.yml    Local dev only
```

---

## Safety Note

> All malware samples are handled exclusively inside the isolated gVisor sandbox with zero network access and no host filesystem visibility. Use the EICAR test string for live demonstrations. Never execute real samples outside the sandbox.

---

*MalSight v2.1 — Hackathon Project — May 2026*
