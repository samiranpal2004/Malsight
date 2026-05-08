# MalSight — Product Requirements Document

**Version:** 2.1 — Core Pipeline + RAM Analysis + Gemini Agent Brain
**LLM Engine:** Google Gemini 1.5 Pro
**Status:** Draft — For Review
**Date:** May 2026
**Authors:** Hackathon Team
**Classification:** Internal

---

## Changelog

| Version | Date | Changes |
|---|---|---|
| v1.x | May 2026 | GCP migration, Email Gateway, Admin Dashboard (deprecated) |
| v2.0 | May 2026 | Refocused to core pipeline. Local Docker sandbox. Added RAM Static Binary Analysis. |
| **v2.1** | **May 2026** | **Gemini Agent Brain — replaced fixed sequential pipeline with an agent-driven loop. Gemini now decides which analysis tools to call, in what order, and when enough evidence has been gathered. Added 30-tool catalog across 6 categories. Added Standard and Deep Scan modes. Agent reasoning chain included in the threat report.** |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals & Success Metrics](#3-goals--success-metrics)
4. [System Architecture](#4-system-architecture)
5. [Gemini Agent Brain](#5-gemini-agent-brain)
6. [Agent Tool Catalog](#6-agent-tool-catalog)
7. [Analysis Modes](#7-analysis-modes)
8. [Threat Report](#8-threat-report)
9. [API Specification](#9-api-specification)
10. [Web Dashboard](#10-web-dashboard)
11. [Non-Functional Requirements](#11-non-functional-requirements)
12. [Technology Stack](#12-technology-stack)
13. [Build Plan](#13-build-plan)
14. [Risks & Mitigations](#14-risks--mitigations)
15. [Future Roadmap](#15-future-roadmap)
- [Appendix A: Gemini API — Tool Calling Reference](#appendix-a-gemini-api--tool-calling-reference)
- [Appendix B: Agent Loop Implementation](#appendix-b-agent-loop-implementation)
- [Appendix C: Full Tool Implementations](#appendix-c-full-tool-implementations)
- [Appendix D: MalwareBazaar Integration](#appendix-d-malwarebazaar-integration)

---

## 1. Executive Summary

> **Product Vision:** MalSight is an AI-powered malware analyzer where a Gemini agent acts as the analytical brain — deciding how to investigate each file, calling the right tools in the right order, and reasoning about results until it has enough evidence to deliver a verdict. Users upload a file and receive a structured threat report in plain English, including a full trace of the agent's reasoning and every step it took.

A user visits the MalSight website, uploads a suspicious file, and chooses either **Standard** or **Deep Scan** mode. A Gemini 1.5 Pro agent then takes over as the lead analyst. It inspects initial file metadata, forms a hypothesis, and begins calling tools — hash lookups, PE analysis, sandbox execution, memory dumping, shellcode detection, IOC enrichment, anti-analysis checks — in an order it determines based on what each result reveals. When it has enough evidence, the agent calls `get_report()` and the final verdict is generated.

This is fundamentally different from a fixed pipeline. A fixed pipeline runs the same steps on every file regardless of what that file is. The agent adapts: a clearly benign Python script gets fast-tracked with two tool calls; a UPX-packed binary with no known hash gets a full investigation including memory dump, injected PE extraction, IOC reputation checks, and anti-sandbox detection. The depth of analysis is proportional to the complexity of the threat.

Every tool call the agent makes — and its reasoning at each step — is captured and included in the final report as an **Analysis Reasoning Chain**, giving analysts full visibility into how the verdict was reached.

**Three complementary analysis layers are available to the agent:**

1. **Static analysis** — Pre-execution inspection: file type, entropy, strings, PE structure, packer detection, known-hash lookups, digital signature validity.
2. **Dynamic behavioral analysis** — Runtime execution in an isolated Docker sandbox under strace (syscall capture) and Falco (behavioral event detection).
3. **RAM static binary analysis** — Live memory dump via gcore at agent-specified timing, revealing unpacked payloads, decrypted strings, injected DLLs, and shellcode patterns invisible on disk.

The agent chooses which layers to invoke, in what sequence, and with what parameters — based on what each result tells it about the file.

---

## 2. Problem Statement

### 2.1 The Signature Problem

Signature-based antivirus engines fail against novel, polymorphic, and AI-generated malware for three fundamental reasons:

- **Zero-day blindness:** Novel malware with no prior signature evades detection entirely on first contact.
- **Polymorphic evasion:** Malware that repackages or re-encrypts itself on each deployment generates unique hashes, making signature databases useless.
- **Expertise barrier:** Understanding what a suspicious file actually does requires deep reverse engineering skills most teams don't have.

### 2.2 The Fixed Pipeline Problem

Even behavioral sandboxes — which are a genuine improvement over signature matching — have a critical limitation when designed as fixed sequential pipelines: **they treat every file identically regardless of what it is.**

A fixed pipeline like `static → sandbox → memory dump → Gemini` has these failure modes:

| Scenario | What a Fixed Pipeline Does | What an Analyst Would Do |
|---|---|---|
| Clearly benign Python script | Runs full sandbox + memory dump anyway | Checks strings and entropy, stops immediately |
| Known-malicious hash | Spins up sandbox before checking the hash DB | Checks hash first, returns verdict in 2 seconds |
| UPX-packed binary | Dumps memory at T+5s regardless of packer type | Identifies packer first, times dump to packer's decompression speed |
| PDF with embedded JavaScript | Runs generic strace, misses JS execution | Calls `analyze_pdf_structure()` first, then sandboxes with JS engine |
| Anti-sandbox malware | Gets a clean execution because malware detected the sandbox | Detects anti-sandbox techniques first and adjusts execution environment |
| Injected PE found in dump | Pipeline ends after first dump | Extracts the injected PE and re-analyzes it as a new sample |

The core problem: **a fixed pipeline's analysis quality is bounded by the imagination of whoever designed it.** An adaptive agent can reason about unexpected findings and take actions the designer never anticipated.

### 2.3 The Packer/Obfuscation Blind Spot

Modern malware rarely executes as-is from disk. The on-disk binary is a loader — a wrapper that decrypts the real payload into memory at runtime without ever writing it back to the filesystem. This makes disk-level analysis useless against packed samples:

| Evasion Technique | Disk-Level Detection | Memory Detection |
|---|---|---|
| UPX / custom packing | Encrypted blob, high entropy | Unpacked PE headers and real imports visible |
| Runtime-decrypted strings | All strings encrypted | C2 URLs, registry keys, API names in heap |
| Reflective DLL injection | DLL never written to disk | Injected PE at unexpected memory offset |
| Process hollowing | Legitimate process image on disk | Malicious code in process memory space |
| Position-independent shellcode | No EXE or DLL to analyze | PEB-walk and NOP sled byte patterns |

The agent addresses this by reasoning about entropy and packer signatures before deciding *when* and *whether* to dump memory — rather than blindly dumping every process at a fixed T+5s.

---

## 3. Goals & Success Metrics

### 3.1 Primary Goals

1. Accept a file upload and return a completed threat report within mode-specific time targets.
2. Use a Gemini agent as the analytical brain — it decides which tools to call, in what order, based on evidence gathered at each step.
3. Execute files in fully isolated Docker sandboxes with no possible host impact.
4. Expose a 30-tool catalog covering static analysis, dynamic execution, memory forensics, IOC enrichment, and anti-analysis detection.
5. Include the agent's full reasoning chain in every report — analysts can see exactly why each step was taken.
6. Map all findings to MITRE ATT&CK techniques.

### 3.2 Success Metrics

| Metric | Target | Measurement |
|---|---|---|
| Standard mode analysis time | < 60 seconds | Upload → report displayed |
| Deep Scan mode analysis time | < 5 minutes | Upload → report displayed |
| Verdict accuracy | > 85% on labeled test set | MalwareBazaar labeled samples |
| MITRE technique recall | ≥ 3 techniques per malicious sample | Manual review |
| Benign fast-track rate | > 70% of benign files resolved without sandbox | Measure short-circuit rate |
| Agent tool call efficiency | < 8 avg calls per Standard analysis | Logged per job |
| Packed sample uplift vs. fixed pipeline | ≥ 2 additional ATT&CK techniques on packed samples | Manual comparison |
| Report readability | Understandable to non-experts | Live judge feedback |
| Reasoning chain completeness | Every tool call accompanied by agent rationale | Manual review of 10 reports |

---

## 4. System Architecture

### 4.1 Component Overview

| Component | Technology | Responsibility |
|---|---|---|
| Web Frontend | React + Tailwind CSS | File upload, mode selection, live agent status, report display |
| API Backend | FastAPI (Python) | File intake, job queuing, report serving |
| Job Queue | Redis + RQ | Async job queue — API returns instantly, agent runs in worker |
| **Agent Brain** | **Google Gemini 1.5 Pro (function calling)** | **Decides which tools to call, reasons about results, drives the entire analysis** |
| **Tool Executor** | **Python (tool_executor.py)** | **Receives tool call requests from agent, executes them, returns structured JSON results** |
| Static Analyzer | Python | SHA-256, entropy, strings, PE parsing, packer detection |
| Docker Sandbox | Docker | Isolated execution environment — no network, no host access |
| Syscall Capture | strace | Full syscall trace of target process |
| Behavioral Monitor | Falco | High-level behavioral event detection |
| Memory Capture | gcore (gdb) | Live process memory dump at agent-specified timing |
| RAM Analyzer | Python (memory_analyzer.py) | PE scan, string extraction, shellcode detection on memory dump |
| Database | PostgreSQL | Store completed reports + agent reasoning chains |
| Report Server | FastAPI | Serve reports to frontend |

### 4.2 High-Level Flow

```
User uploads file + selects mode (Standard / Deep Scan)
                    ↓
         FastAPI validates file
      (type, size, MIME check → UUID job_id)
                    ↓
         Job enqueued in Redis
         API returns job_id instantly
                    ↓
         RQ Worker picks up job
                    ↓
┌──────────────────────────────────────────────────────┐
│                  GEMINI AGENT LOOP                   │
│                                                      │
│  Agent receives:                                     │
│    - filename, size, type, sha256, entropy           │
│    - analysis mode (standard / deep_scan)            │
│    - full tool catalog as callable functions         │
│                                                      │
│  ┌────────────────────────────────────────────┐      │
│  │  Agent thinks → calls tool(s)              │      │
│  │  Tool executes → returns JSON result       │      │
│  │  Agent reasons about result                │      │
│  │  Agent decides: more tools or get_report() │      │
│  └────────────────────────────────────────────┘      │
│           ↑_______________ loop ___________________↓ │
│                                                      │
│  Loop ends when:                                     │
│    - Agent calls get_report()                        │
│    - Max iterations reached (8 standard / 20 deep)   │
│                                                      │
└──────────────────────────────────────────────────────┘
                    ↓
     Threat report + reasoning chain generated
                    ↓
         Stored in PostgreSQL
                    ↓
     Frontend displays report + reasoning chain
                    ↓
     Docker sandbox destroyed (if spawned)
```

---

## 5. Gemini Agent Brain

### 5.1 What the Agent Is

The agent is a Gemini 1.5 Pro instance running in **function calling mode** — a native Gemini capability where the model can call pre-defined functions (tools), receive their results as new context, and decide what to do next. The agent loop runs entirely in the RQ worker process.

At each iteration, the agent:
1. Reads all evidence gathered so far (initial file metadata + all previous tool results)
2. Reasons about what the evidence means and what gaps remain
3. Calls one or more tools to fill those gaps, OR calls `get_report()` if it has enough evidence

This is not a pre-scripted sequence. The agent constructs its own investigation plan based on what each result reveals.

### 5.2 Agent System Prompt

```
SYSTEM:
You are MalSight, an expert malware analyst AI. You have access to a catalog of
analysis tools. Your job is to investigate a suspicious file by calling tools
strategically — not exhaustively. Think like a senior analyst: form a hypothesis
from initial signals, call the tools most likely to confirm or refute it, and
follow interesting findings.

Rules:
1. At each step, briefly explain your reasoning BEFORE calling a tool.
   This reasoning will be shown to the analyst in the final report.
2. Do not call a tool whose result you can already infer from prior results.
3. If the file is clearly benign (low entropy, benign strings, clean hash,
   no suspicious imports), call get_report() early — do not waste time.
4. If you find something unexpected (injected PE, anti-sandbox code, unknown
   packer), follow it — call additional tools to understand it fully.
5. Always check the hash before sandboxing — avoid unnecessary execution.
6. In Standard mode, target ≤ 8 tool calls. In Deep Scan, you may use up to 20.
7. When you call get_report(), provide your final verdict, confidence,
   threat category, severity, summary, key indicators, and MITRE ATT&CK
   technique mappings as a structured JSON object.

You have the following tools available:
{tool_catalog}
```

### 5.3 Agent Reasoning Chain

Every message the agent produces before calling a tool is captured verbatim and stored as the **Analysis Reasoning Chain** — a step-by-step log of the agent's thought process throughout the investigation. This chain is included in the final report and displayed in the dashboard.

**Example reasoning chain for a packed trojan:**

```
[Step 1 — Reasoning]
"SHA-256 is unknown, file is a PE32+, on-disk entropy is 7.8.
 Very high entropy strongly suggests packing or encryption.
 I'll check the PE sections to identify the packer before
 doing anything else."

[Step 1 — Tool Call] get_pe_sections()
[Step 1 — Result] Sections: .upx0 (entropy 0.1), .upx1 (entropy 7.9)
                  → UPX packer confirmed.

[Step 2 — Reasoning]
"UPX confirmed. The real payload will decompress into memory
 within the first 2 seconds. I'll run a short 15-second sandbox
 execution and request a memory dump at T+3s to catch the payload
 right after decompression."

[Step 2 — Tool Call] run_sandbox(duration=15), capture_memory_dump(timing=3)
[Step 2 — Result] trace.log: 4 file reads, 7 blocked network attempts,
                  schtasks.exe spawned.
                  memdump.bin: 14MB captured at T+3s.

[Step 3 — Reasoning]
"Blocked network attempts and schtasks spawning are significant.
 I need to see what's in memory — specifically any injected PE
 images and what strings the real payload contains."

[Step 3 — Tool Call] scan_pe_headers(target="memdump"), 
                     extract_strings_from_memory(filter="ioc")
[Step 3 — Result] Second PE at offset 0x3f2000 (PE32).
                  Strings: http://185.220.101.45/gate.php,
                  HKEY_CURRENT_USER\...\Run,
                  CreateRemoteThread, VirtualAllocEx.

[Step 4 — Reasoning]
"There is an injected PE — reflective DLL injection is likely.
 The C2 URL and registry persistence key are now visible.
 I'll check the C2 IP reputation and extract the injected PE
 for its own import table."

[Step 4 — Tool Call] check_ip_reputation(ip="185.220.101.45"),
                     analyze_injected_pe(offset="0x3f2000")
[Step 4 — Result] IP flagged as known C2 by AbuseIPDB (score: 97/100).
                  Injected PE imports: CreateRemoteThread,
                  VirtualAllocEx, WinHttpOpen, CryptEncrypt.

[Step 5 — Reasoning]
"I have strong, multi-layered evidence: confirmed C2, process
 injection API imports, persistence via registry Run key, and
 a known-malicious IP. Confidence is very high. Calling get_report()."

[Step 5 — Tool Call] get_report()
```

This chain is the most valuable thing MalSight shows an analyst — it makes the verdict fully explainable and auditable.

### 5.4 Agent Decision Logic Patterns

The agent learns to follow these investigation patterns based on its training and system prompt:

**Pattern 1 — Early exit for benign files**
```
entropy < 5.0 + clean strings + clean hash + no suspicious imports
→ get_report("benign", confidence: 92)
   Total tool calls: 3   Time: ~8 seconds
```

**Pattern 2 — Known malicious hash**
```
check_malwarebazaar() → hit
→ get_report("malicious", confidence: 99)
   Total tool calls: 1   Time: ~3 seconds
```

**Pattern 3 — Packed binary investigation**
```
high entropy → detect_packer() → confirm packer
→ run_sandbox() + capture_memory_dump(timing=packer_decompression_time)
→ scan_pe_headers() + extract_strings_from_memory()
→ [if injected PE] analyze_injected_pe()
→ [if C2 string found] check_ip_reputation() / check_domain_reputation()
→ get_report()
   Total tool calls: 6–9   Time: ~45–90 seconds
```

**Pattern 4 — PDF with suspicious structure**
```
get_file_magic() → PDF
→ analyze_pdf_structure() → JavaScript objects found
→ run_sandbox() → monitor_filesystem() + get_dropped_files()
→ extract_iocs() → check_domain_reputation()
→ get_report()
   Total tool calls: 5–7   Time: ~40–60 seconds
```

**Pattern 5 — Anti-sandbox malware (Deep Scan)**
```
run_sandbox() → near-empty strace (malware detected sandbox)
→ detect_anti_vm() → CPUID VMX check found
→ detect_anti_sandbox() → sleep(300) call detected
→ detect_anti_debug() → IsDebuggerPresent import found
→ [agent decides to re-run sandbox with modified environment]
→ run_sandbox(duration=60, bypass_anti_sandbox=true)
→ capture_memory_dump() → full memory analysis
→ get_report()
   Total tool calls: 9–14   Time: ~3–5 minutes
```

---

## 6. Agent Tool Catalog

The agent has access to 30 tools across 6 categories. Every tool accepts parameters, executes in Python, and returns structured JSON. The agent receives the full tool catalog in its system context at the start of each job.

### Category 1 — Threat Intelligence Lookups

These tools are fast (< 2 seconds) and should be called early in any investigation.

---

**`check_malwarebazaar(hash: str)`**

Queries the abuse.ch MalwareBazaar API for the file's SHA-256 hash. A hit returns the known malware family, threat category, tags, and first-seen date. This is the single most efficient tool — a confirmed hit means no sandbox execution is needed at all.

```json
// Returns
{
  "found": true,
  "malware_family": "Emotet",
  "tags": ["trojan", "banker", "loader"],
  "first_seen": "2024-11-02",
  "reporter": "abuse.ch"
}
```

---

**`check_virustotal(hash: str)`**

Queries the VirusTotal API for multi-engine detection results. Returns the number of engines that flagged the file, the majority verdict, and a list of engine-specific detections. Provides a broader consensus than MalwareBazaar alone.

```json
// Returns
{
  "found": true,
  "detections": 47,
  "total_engines": 72,
  "majority_verdict": "Trojan.GenericKD",
  "notable_engines": {
    "Kaspersky": "Trojan-Spy.Win32.Agent",
    "CrowdStrike": "win/malicious_confidence_100"
  }
}
```

---

**`check_ip_reputation(ip: str)`**

Queries AbuseIPDB for threat intelligence on an IP address extracted from the file or memory dump. Returns abuse confidence score, known categories (C2, scanning, phishing), and country of origin. Most valuable after C2 strings are extracted from a memory dump.

```json
// Returns
{
  "ip": "185.220.101.45",
  "abuse_confidence_score": 97,
  "categories": ["C2", "malware_distribution"],
  "country": "RO",
  "total_reports": 412
}
```

---

**`check_domain_reputation(domain: str)`**

Queries threat intelligence feeds for a domain name extracted from the file or memory dump. Returns verdict, categories, and registrar information. Catches C2 domains and phishing infrastructure.

```json
// Returns
{
  "domain": "update-svc-cdn.net",
  "verdict": "malicious",
  "categories": ["phishing", "c2"],
  "age_days": 12,
  "registrar": "Namecheap"
}
```

---

### Category 2 — Static File Analysis

Pre-execution tools that inspect the file on disk without running it.

---

**`get_file_magic()`**

Detects the true file type using magic bytes (libmagic), independent of file extension. Catches mismatched extensions (e.g., an EXE renamed to `.pdf`) and identifies subtypes like PE32, PE32+, ELF, Mach-O, ZIP, OLE2, PDF.

```json
// Returns
{ "magic_type": "PE32+ executable (GUI) x86-64", "mime": "application/x-dosexec" }
```

---

**`get_entropy(target: str, region: str?)`**

Calculates Shannon entropy of the whole file, or a specific named PE section if `region` is specified. High entropy (> 7.0) on the whole file indicates packing. Per-section entropy reveals which sections are encrypted vs. plaintext.

```json
// Returns
{
  "overall_entropy": 7.84,
  "sections": {
    ".text": 6.12,
    ".upx1": 7.91,
    ".data": 3.44
  }
}
```

---

**`extract_strings(target: str, min_length: int?, encoding: str?)`**

Extracts printable strings from the file (ASCII and UTF-16LE by default, min length 6). Returns all strings plus a filtered subset matching security-relevant patterns: URLs, IPs, registry keys, API names, shell commands, file paths.

```json
// Returns
{
  "total_strings": 142,
  "suspicious": [
    "http://malicious-domain.com/payload",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "cmd.exe /c whoami"
  ]
}
```

---

**`get_pe_imports()`**

Parses the PE import table and returns all imported DLLs and function names. The import table is one of the most revealing static analysis artifacts — it shows exactly which Windows APIs the binary intends to call. Certain function combinations are near-definitive malware indicators.

```json
// Returns
{
  "dlls": ["kernel32.dll", "ntdll.dll", "winhttp.dll"],
  "suspicious_imports": [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WinHttpOpen"
  ],
  "injection_apis_present": true,
  "network_apis_present": true
}
```

---

**`get_pe_sections()`**

Returns PE section headers: name, virtual size, raw size, entropy, and flags. Abnormal sections (unusual names like `.upx0`, sections with executable + writable flags, high-entropy executable sections) are strong indicators of packing or self-modifying code.

```json
// Returns
[
  { "name": ".text",  "entropy": 6.12, "flags": ["executable", "readable"] },
  { "name": ".upx0",  "entropy": 0.04, "flags": ["executable", "readable", "writable"] },
  { "name": ".upx1",  "entropy": 7.91, "flags": ["executable", "readable", "writable"] }
]
```

---

**`detect_packer()`**

Identifies the specific packer or protector used by matching against a signature database (UPX, MPRESS, Themida, ASPack, VMProtect, Enigma). Knowing the packer tells the agent exactly how to time the memory dump for optimal payload capture.

```json
// Returns
{
  "packer_detected": true,
  "packer_name": "UPX",
  "version": "3.96",
  "decompression_time_estimate_ms": 800
}
```

---

**`check_digital_signature()`**

Verifies the PE's Authenticode digital signature. Returns the signer, certificate chain, and validity status. Many malware samples use stolen, self-signed, or expired certificates to appear legitimate. An invalid or mismatched signature is a significant red flag.

```json
// Returns
{
  "signed": true,
  "valid": false,
  "signer": "Microsoft Corporation",
  "reason": "Certificate not in trusted store — likely forged",
  "cert_expired": true
}
```

---

**`get_compile_timestamp()`**

Extracts the PE compilation timestamp from the file header. Returns the timestamp and a flag if it appears to be zeroed out or set to a suspiciously round number (common malware behavior to defeat timestamp-based detection).

```json
// Returns
{
  "timestamp": "2018-03-14T00:00:00Z",
  "suspicious": true,
  "reason": "Timestamp is exactly midnight — likely zeroed or faked"
}
```

---

**`analyze_pdf_structure()`**

Performs deep structural analysis on PDF files. Extracts JavaScript objects, embedded file streams, suspicious action types (`/Launch`, `/JavaScript`, `/OpenAction`), and stream filter chains. PDF-based malware relies almost entirely on structure — this tool catches what generic string extraction misses.

```json
// Returns
{
  "has_javascript": true,
  "embedded_files": 1,
  "suspicious_actions": ["/JavaScript", "/OpenAction"],
  "stream_filters": ["FlateDecode", "ASCIIHexDecode"],
  "obfuscated_js": true
}
```

---

**`deobfuscate_script()`**

For Python, JavaScript, PowerShell, and shell scripts: attempts static deobfuscation by resolving string concatenation, base64 decoding, hex decoding, and simple eval chains. Returns the deobfuscated source where possible and flags obfuscation techniques used.

```json
// Returns
{
  "obfuscation_detected": true,
  "techniques": ["base64_encoding", "string_concatenation", "eval_exec"],
  "deobfuscated_snippet": "import socket; s=socket.socket(); s.connect(('185.220.101.45', 4444))"
}
```

---

### Category 3 — Sandbox Execution

Tools that run the file in the isolated Docker environment and collect behavioral evidence.

---

**`run_sandbox(duration: int?, capture_focus: str?)`**

Executes the target file inside an isolated Docker container. `duration` specifies the execution timeout in seconds (default: 30, max Deep Scan: 120). `capture_focus` can be `"all"`, `"network"`, `"filesystem"`, or `"process"` to control strace verbosity. Returns a structured behavioral summary: file operations, blocked network attempts, child processes spawned, and Falco event list.

```json
// Returns
{
  "duration_actual": 28,
  "file_ops": { "reads": 12, "writes": 3, "deletes": 1, "paths": ["~/.ssh/id_rsa"] },
  "network_attempts": { "count": 7, "all_blocked": true },
  "processes_spawned": ["schtasks.exe", "cmd.exe"],
  "falco_events": [
    "Sensitive file read: /etc/shadow",
    "Outbound connection attempt to 185.220.101.45:443"
  ]
}
```

---

**`capture_memory_dump(timing: int?)`**

Captures a full gcore memory dump of the running process at `timing` seconds after execution start (default: 5). The agent can choose a custom timing based on packer decompression estimates from `detect_packer()`. Returns dump size and path for downstream analysis.

```json
// Returns
{
  "captured": true,
  "timing_seconds": 3,
  "dump_size_bytes": 14680064,
  "dump_path": "/tmp/results/memdump.bin"
}
```

---

**`monitor_filesystem()`**

Uses `inotifywait` inside the sandbox to capture real-time filesystem change events during execution. Returns every file created, modified, or deleted by the process — useful for catching droppers that write secondary payloads to disk.

```json
// Returns
{
  "created": ["/tmp/svchost32.exe", "/tmp/.hidden_config"],
  "modified": ["/etc/crontab"],
  "deleted": ["/tmp/original_dropper.sh"]
}
```

---

**`get_dropped_files()`**

Extracts the content of files created by the malware during sandbox execution (identified by `monitor_filesystem()`). Returns file data, SHA-256 hashes, and MIME types of each dropped file. Dropped files are submitted as child analysis jobs automatically.

```json
// Returns
[
  {
    "path": "/tmp/svchost32.exe",
    "sha256": "a3f9c1...",
    "size_bytes": 45056,
    "mime": "application/x-dosexec",
    "child_job_id": "b7c2d4e1-..."
  }
]
```

---

### Category 4 — Memory Forensics

Tools that analyze the memory dump captured by `capture_memory_dump()`.

---

**`scan_pe_headers(target: str)`**

Scans the memory dump for all embedded PE images (`MZ` + `PE` signatures at any offset). The primary process image is expected at offset 0x0 — any PE found at a higher offset is flagged as a possible injected DLL or hollowed payload.

```json
// Returns
{
  "pe_images_found": 2,
  "images": [
    { "offset": "0x0",      "pe_type": "PE32+", "note": "primary process image" },
    { "offset": "0x3f2000", "pe_type": "PE32",  "note": "possible injected PE" }
  ]
}
```

---

**`extract_strings_from_memory(filter: str?)`**

Extracts ASCII and UTF-16LE strings from the memory dump. `filter` can be `"ioc"` (IPs, URLs, domains), `"registry"` (HKEY paths), `"api"` (Windows API names), or `"all"`. Returns strings that were not present in the on-disk binary — these are strings that only existed after decryption/decompression at runtime.

```json
// Returns
{
  "new_strings_vs_disk": [
    "http://185.220.101.45/gate.php",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "CreateRemoteThread",
    "WinHttpSendRequest"
  ]
}
```

---

**`detect_shellcode()`**

Scans the memory dump for byte patterns characteristic of position-independent shellcode: PEB-walk sequences (locating kernel32 without imports), ROR-13 API hash resolution loops, indirect call-register patterns, and NOP sleds.

```json
// Returns
{
  "shellcode_detected": true,
  "indicators": [
    { "pattern": "peb_walk",              "offset": "0x401800" },
    { "pattern": "ror13_api_hash_loop",   "offset": "0x401850" },
    { "pattern": "indirect_call_register","offset": "0x401900" }
  ]
}
```

---

**`get_memory_entropy(region: str?)`**

Calculates per-region entropy across the memory dump. Can target specific address ranges or named regions. Persistently high entropy in an executable region after decompression suggests a second-stage payload that has not yet been decoded.

```json
// Returns
{
  "overall": 6.87,
  "regions": [
    { "range": "0x0–0x1000",       "entropy": 6.12, "type": "code"   },
    { "range": "0x3f2000–0x3f3000","entropy": 7.81, "type": "unknown — high entropy in executable region" }
  ]
}
```

---

**`analyze_injected_pe(offset: str)`**

Extracts the PE image at the given memory offset from the dump and runs the full static analysis suite against it — imports, sections, strings, packer detection. This is how MalSight investigates the actual payload independently of the loader that delivered it.

```json
// Returns
{
  "pe_type": "PE32",
  "imports": ["CreateRemoteThread", "VirtualAllocEx", "WinHttpOpen", "CryptEncrypt"],
  "sections": [
    { "name": ".text", "entropy": 6.3 },
    { "name": ".data", "entropy": 3.1 }
  ],
  "strings": ["http://185.220.101.45/gate.php", "Mozilla/5.0 (compatible)"],
  "packer": "none — plaintext payload"
}
```

---

**`run_yara(rules: list[str], target: str)`**

Runs YARA rules against the file on disk or the memory dump. `rules` specifies named rule sets from the MalSight rule library (`"ransomware"`, `"banker"`, `"rat"`, `"coinminer"`, `"webshell"`). Returns matching rules and the specific byte patterns that triggered each match.

```json
// Returns
{
  "matches": [
    {
      "rule": "Emotet_Dropper_v4",
      "ruleset": "banker",
      "matched_strings": ["$c2_pattern", "$persistence_key"]
    }
  ]
}
```

---

### Category 5 — Anti-Analysis Detection

Tools that check whether the malware is actively trying to detect and evade the analysis environment. Findings here are both threat indicators AND signals for the agent to adjust its approach.

---

**`detect_anti_debug()`**

Checks for anti-debugging techniques in the binary and imports: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, NtQueryInformationProcess debug port checks, timing-based checks (RDTSC), and SEH-based debugger detection. Malware using these techniques is always attempting to hide its behavior.

```json
// Returns
{
  "anti_debug_detected": true,
  "techniques": [
    "IsDebuggerPresent import",
    "RDTSC timing check pattern",
    "NtQueryInformationProcess(ProcessDebugPort)"
  ]
}
```

---

**`detect_anti_vm()`**

Checks for virtual machine detection techniques: CPUID hypervisor bit checks, VMware/VirtualBox registry key lookups, known VM process names (`vmtoolsd.exe`, `vboxservice.exe`), and MAC address prefix matching for VM vendors. Anti-VM malware will behave benignly or exit cleanly when it detects a sandbox.

```json
// Returns
{
  "anti_vm_detected": true,
  "techniques": [
    "CPUID VMX hypervisor bit check",
    "Registry: HKLM\\SOFTWARE\\VMware, Inc.",
    "Process name check: vboxservice.exe"
  ]
}
```

---

**`detect_anti_sandbox()`**

Checks for sandbox-specific evasion: long sleep calls before execution (`sleep(300)`), checks for mouse movement or user interaction, low-count process environment checks (sandboxes often have very few running processes), and checks for the presence of recently-accessed files.

```json
// Returns
{
  "anti_sandbox_detected": true,
  "techniques": [
    "Sleep call with 300000ms delay before payload",
    "GetCursorPos() — checks for mouse movement",
    "GetSystemInfo() — checks processor count (< 2 = sandbox)"
  ]
}
```

---

### Category 6 — IOC Extraction & Control

---

**`extract_iocs(target: str)`**

Performs focused extraction of all Indicators of Compromise from the file on disk or the memory dump: IPv4/IPv6 addresses, URLs, domains, email addresses, cryptocurrency wallet addresses (Bitcoin, Monero), and mutex names. Returns a deduplicated, categorized IOC list ready for threat intelligence enrichment.

```json
// Returns
{
  "ips": ["185.220.101.45", "10.0.0.1"],
  "urls": ["http://185.220.101.45/gate.php", "https://update-svc-cdn.net/dl"],
  "domains": ["update-svc-cdn.net"],
  "emails": [],
  "crypto_wallets": ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"],
  "mutexes": ["Global\\MicrosoftUpdateMutex_v2"]
}
```

---

**`get_report(verdict, confidence, threat_category, severity, summary, key_indicators, mitre_techniques, recommended_action)`**

Signal tool — calling this tells the agent loop that analysis is complete. The agent passes its final verdict and all supporting fields as parameters. The tool executor generates the structured final report, persists it to PostgreSQL, and closes the agent loop.

This is the only way the agent loop terminates normally. If max iterations are reached without the agent calling `get_report()`, the loop forces a `get_report()` call with whatever evidence has been gathered and a note indicating the analysis was incomplete.

---

## 7. Analysis Modes

### 7.1 Standard Mode

Targets < 60 seconds end-to-end. Designed for rapid triage of uploaded files.

| Parameter | Value |
|---|---|
| Max tool calls | 8 |
| Max sandbox duration | 30 seconds |
| Memory dump | Available |
| Anti-analysis detection | Available |
| IOC reputation checks | 1 (most critical IOC only) |
| Dropped file child jobs | Queued but not awaited |

The agent is instructed to prioritize speed: use hash lookups first, exit early for benign files, and focus sandbox time on the most suspicious signals.

### 7.2 Deep Scan Mode

Targets < 5 minutes. Designed for thorough investigation of high-priority or suspicious files.

| Parameter | Value |
|---|---|
| Max tool calls | 20 |
| Max sandbox duration | 120 seconds |
| Memory dump | Available (agent can dump multiple times at different timings) |
| Anti-analysis detection | Always run |
| IOC reputation checks | All IOCs enriched |
| Dropped file child jobs | Fully analyzed inline |
| YARA scanning | Full ruleset |
| Anti-sandbox bypass | Agent can request modified execution environment |

The agent is instructed to be thorough: investigate every anomaly, follow every lead, and produce the most complete picture possible.

### 7.3 Mode Comparison

| | Standard | Deep Scan |
|---|---|---|
| Target time | < 60s | < 5 min |
| Benign fast-track | ✅ | ✅ |
| PE import analysis | ✅ | ✅ |
| Sandbox execution | ✅ | ✅ (longer) |
| Memory forensics | ✅ | ✅ (multi-dump) |
| Anti-analysis detection | ✅ | ✅ (always) |
| All IOC enrichment | ❌ (top 1 only) | ✅ |
| YARA full ruleset | ❌ | ✅ |
| Dropped file child analysis | ❌ (queued) | ✅ (inline) |
| Max agent iterations | 8 | 20 |

---

## 8. Threat Report

Every completed analysis produces a structured threat report stored in PostgreSQL and rendered in the frontend. The report has two parts: the **Verdict Block** (the agent's final output) and the **Analysis Reasoning Chain** (the agent's step-by-step investigation log).

### 8.1 Verdict Block Schema

| Field | Type | Description |
|---|---|---|
| `job_id` | UUID | Unique job identifier |
| `mode` | enum | `standard` \| `deep_scan` |
| `verdict` | enum | `benign` \| `suspicious` \| `malicious` |
| `confidence` | integer 0–100 | Agent confidence in the verdict |
| `threat_category` | string | E.g. trojan, ransomware, spyware, dropper, unknown |
| `severity` | enum | `low` \| `medium` \| `high` \| `critical` |
| `summary` | string | 2–3 sentence plain-English explanation |
| `key_indicators` | string[] | Top 3–5 findings that drove the verdict |
| `mitre_techniques` | object[] | `{id, name, tactic, evidence}` for each mapped technique |
| `recommended_action` | string | Quarantine / Monitor / Safe to execute / Further analysis needed |
| `iocs` | object | All extracted IOCs (IPs, URLs, domains, wallets, mutexes) |
| `tools_called` | integer | Total agent tool calls made |
| `analysis_time_seconds` | integer | Total wall clock time |

### 8.2 Analysis Reasoning Chain Schema

| Field | Type | Description |
|---|---|---|
| `steps` | array | Ordered list of agent reasoning steps |
| `steps[n].step_number` | integer | Step index |
| `steps[n].reasoning` | string | Agent's explanation of why it's calling this tool |
| `steps[n].tool_called` | string | Tool name and parameters |
| `steps[n].result_summary` | string | Key findings from the tool result |

### 8.3 Example Report

```json
{
  "job_id": "a3f9c12e-84b1-4d2a-91cc-f0e123456789",
  "mode": "standard",
  "verdict": "malicious",
  "confidence": 97,
  "threat_category": "trojan",
  "severity": "critical",
  "summary": "This file is a UPX-packed trojan dropper. The real payload was recovered from a live memory dump — it was entirely invisible in the on-disk binary. The payload injects a DLL into a remote process, reads browser credentials, establishes persistence via a registry Run key, and contacts a known C2 IP address that has been flagged by threat intelligence with a 97/100 abuse confidence score.",
  "key_indicators": [
    "UPX packing confirmed — real payload only visible in memory dump",
    "Injected PE image at memory offset 0x3f2000 (reflective DLL injection)",
    "Decrypted C2 URL from memory: http://185.220.101.45/gate.php",
    "C2 IP reputation: 97/100 abuse score (AbuseIPDB)",
    "Registry persistence key recovered from memory: HKCU\\...\\Run"
  ],
  "mitre_techniques": [
    { "id": "T1027.002", "name": "Software Packing",               "tactic": "Defense Evasion",   "evidence": "UPX sections confirmed by detect_packer()" },
    { "id": "T1055.001", "name": "DLL Injection",                  "tactic": "Defense Evasion",   "evidence": "Injected PE at 0x3f2000; CreateRemoteThread import" },
    { "id": "T1555.003", "name": "Credentials from Web Browsers",  "tactic": "Credential Access", "evidence": "Chrome Login Data path in strace reads" },
    { "id": "T1547.001", "name": "Registry Run Keys / Startup",    "tactic": "Persistence",       "evidence": "HKCU Run key in memory strings" },
    { "id": "T1041",     "name": "Exfiltration Over C2 Channel",   "tactic": "Exfiltration",      "evidence": "Known C2 IP 185.220.101.45 — abuse score 97/100" }
  ],
  "recommended_action": "Quarantine",
  "iocs": {
    "ips": ["185.220.101.45"],
    "urls": ["http://185.220.101.45/gate.php"],
    "domains": [],
    "mutexes": ["Global\\MicrosoftUpdateMutex_v2"]
  },
  "tools_called": 5,
  "analysis_time_seconds": 48,
  "reasoning_chain": {
    "steps": [
      {
        "step_number": 1,
        "reasoning": "SHA-256 is unknown, file is PE32+, on-disk entropy is 7.8. Very high entropy strongly suggests packing. I'll check PE sections to identify the packer before doing anything else.",
        "tool_called": "get_pe_sections()",
        "result_summary": "Sections .upx0 (entropy 0.04) and .upx1 (entropy 7.91) found — UPX packer confirmed."
      },
      {
        "step_number": 2,
        "reasoning": "UPX confirmed with ~800ms decompression time. I'll run a 15-second sandbox and dump memory at T+3s to catch the payload right after decompression.",
        "tool_called": "run_sandbox(duration=15), capture_memory_dump(timing=3)",
        "result_summary": "7 blocked network attempts, schtasks.exe spawned. 14MB memory dump captured at T+3s."
      },
      {
        "step_number": 3,
        "reasoning": "Blocked network attempts and schtasks are significant. Memory dump ready — scanning for injected PEs and decrypted IOC strings.",
        "tool_called": "scan_pe_headers(target='memdump'), extract_strings_from_memory(filter='ioc')",
        "result_summary": "Second PE at offset 0x3f2000. Decrypted strings: C2 URL, HKCU Run key, CreateRemoteThread, VirtualAllocEx."
      },
      {
        "step_number": 4,
        "reasoning": "Injected PE and C2 URL are strong signals. Checking IP reputation and extracting injected PE imports for full picture.",
        "tool_called": "check_ip_reputation(ip='185.220.101.45'), analyze_injected_pe(offset='0x3f2000')",
        "result_summary": "IP abuse score 97/100 (known C2). Injected PE imports: CreateRemoteThread, VirtualAllocEx, WinHttpOpen, CryptEncrypt."
      },
      {
        "step_number": 5,
        "reasoning": "Evidence is comprehensive and conclusive: confirmed packing, injected DLL, credential-theft behavior, known-malicious C2 with high reputation score. Calling get_report().",
        "tool_called": "get_report(...)",
        "result_summary": "Verdict: malicious / critical. 5 ATT&CK techniques mapped."
      }
    ]
  }
}
```

---

## 9. API Specification

### 9.1 Endpoints

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/analyze` | Submit file + select mode. Returns `job_id` immediately. | API Key |
| `GET` | `/report/{id}` | Fetch report by job ID. Returns live status + current agent step while in progress. | API Key |
| `GET` | `/reports` | List all reports with pagination, verdict filter, and mode filter. | API Key |
| `GET` | `/health` | Service health check. Returns status and queue depth. | None |
| `DELETE` | `/report/{id}` | Delete a report. | API Key |

### 9.2 Request / Response Examples

**Submit a file:**

```http
POST /analyze
Content-Type: multipart/form-data
X-API-Key: your_key_here

file: <binary>
mode: deep_scan        ← "standard" (default) or "deep_scan"
```

```json
{
  "job_id": "a3f9c12e-84b1-4d2a-91cc-f0e123456789",
  "status": "queued",
  "mode": "deep_scan",
  "estimated_seconds": 180
}
```

**Poll during analysis (agent in progress):**

```json
{
  "job_id": "a3f9c12e-...",
  "status": "running",
  "current_step": 3,
  "current_action": "Scanning memory dump for injected PE images...",
  "elapsed_seconds": 34
}
```

**Poll after completion:**

```json
{
  "job_id": "a3f9c12e-...",
  "status": "complete",
  "report": { ... }
}
```

### 9.3 Constraints

- **Max file size:** 50MB
- **Supported types:** `.exe`, `.dll`, `.py`, `.sh`, `.bash`, `.pdf`, `.zip`
- **Concurrent analyses:** 5 per API key
- **Report retention:** 30 days
- **Standard mode timeout:** 90 seconds wall clock (agent is budgeted 60s; 30s buffer for overhead)
- **Deep Scan timeout:** 10 minutes wall clock

---

## 10. Web Dashboard

### 10.1 Upload View

Landing page with a drag-and-drop upload zone, file picker, and a **mode selector**:

- **⚡ Standard** — Fast triage. ~60 seconds. Recommended for most files.
- **🔬 Deep Scan** — Thorough investigation. Up to 5 minutes. For high-priority or suspicious files.

### 10.2 Live Agent Status View

After submission, the view transitions to a real-time agent monitor. Instead of a generic progress bar, the user sees the agent's current reasoning step as it happens — fetched by polling `GET /report/{job_id}` every 2 seconds:

```
🔍 Step 1 of 8 — Checking PE section entropy...
   "SHA-256 unknown, entropy 7.8 — likely packed. Checking sections."

⚙️  Step 2 of 8 — Running sandbox (15s) + capturing memory dump at T+3s...
   "UPX confirmed. Timing dump to post-decompression window."

🧠 Step 3 of 8 — Scanning memory dump for injected PE images...
   "7 blocked network calls and schtasks spawned. Analyzing memory."
```

This is the key UX differentiator: the user watches the agent reason through the investigation in real time rather than staring at a spinner.

### 10.3 Threat Report View

The final report view:

- **Verdict badge** — 🟢 Benign / 🟡 Suspicious / 🔴 Malicious with confidence % and threat category
- **Severity chip** — Low / Medium / High / Critical
- **Summary card** — Gemini's plain-English explanation
- **Key indicators list** — Top findings that drove the verdict
- **MITRE ATT&CK tags** — Technique IDs linking to the ATT&CK knowledge base
- **IOC block** — All extracted IPs, URLs, domains, mutexes with reputation scores
- **Analysis Reasoning Chain** — Full collapsible step-by-step agent investigation log with tool calls, rationale, and result summaries at each step
- **Mode + performance badge** — Standard / Deep Scan, total tool calls, total time
- **Recommended action** — Quarantine / Monitor / Safe / Investigate further

### 10.4 Report History View

Paginated table of all past analyses: filename, mode, verdict badge, threat category, confidence, tool calls used, analysis time, and timestamp. Searchable and filterable by verdict and mode.

---

## 11. Non-Functional Requirements

| Category | Requirement | Target |
|---|---|---|
| Performance | Standard mode: upload → report | < 60 seconds P95 |
| Performance | Deep Scan mode: upload → report | < 5 minutes P95 |
| Performance | Known-hash short-circuit | < 5 seconds |
| Performance | Benign fast-track (no sandbox) | < 15 seconds |
| Performance | `/report` GET (status poll) | < 100ms P99 |
| Security | Docker sandbox isolation | `cap_drop: ALL`, `network_mode: none`, `no-new-privileges`, tmpfs only |
| Security | No host filesystem access from container | Enforced by Docker run config |
| Security | Gemini API key | Stored in environment variable, never logged or exposed in reports |
| Reliability | Worker crash recovery | RQ auto-requeues; max 2 retries per job |
| Reliability | Agent max iteration guard | Forced `get_report()` if max iterations reached — no infinite loops |
| Observability | Per-step structured logging | JSON logs with `job_id` + `step_number` correlation |
| Observability | Tool call timing logged | Each tool call duration recorded for performance analysis |
| Cost | Gemini API spend per Standard job | ~$0.004 (avg 8 calls × ~500 tokens each) |
| Cost | Gemini API spend per Deep Scan job | ~$0.010 (avg 15 calls × ~700 tokens each) |
| Portability | Local setup | `docker-compose up` starts all services |

---

## 12. Technology Stack

| Layer | Technology | Version | Role |
|---|---|---|---|
| Frontend | React + Tailwind CSS | React 18 | Upload, mode select, live agent status, report display |
| API Backend | FastAPI | 0.111+ | File intake, job queue, report serving |
| Job Queue | Redis + RQ | Redis 7 | Async queue; API returns instantly |
| **Agent Brain** | **Google Gemini 1.5 Pro** | **Gemini API** | **Drives the entire analysis via function calling loop** |
| **Tool Executor** | **Python (tool_executor.py)** | **stdlib** | **Receives tool calls from agent, dispatches to implementations, returns JSON** |
| Static Analyzer | Python | stdlib + pefile | Hash, entropy, strings, PE parsing |
| Packer Detector | Python (detect_packer.py) | Custom signatures | UPX, MPRESS, Themida, ASPack, VMProtect |
| Sandbox | Docker | 24+ | Isolated execution environment |
| Syscall Capture | strace | System pkg | Full process syscall trace |
| Behavioral Monitor | Falco | 0.38+ | High-level behavioral event rules |
| Memory Capture | gdb / gcore | System pkg | Live process memory dump |
| RAM Analyzer | Python (memory_analyzer.py) | stdlib | PE scan, string extraction, shellcode detection on dump |
| YARA Engine | yara-python | 4.x | Rule-based pattern matching on file and dump |
| PDF Analyzer | pdfminer.six + pikepdf | Latest | PDF structure and stream analysis |
| IOC Enrichment | AbuseIPDB API / VirusTotal API | Public APIs | IP and domain reputation lookups |
| Database | PostgreSQL | 15 | Report + reasoning chain storage |
| Container Mgmt | Docker Python SDK | Latest | Programmatic container lifecycle |
| Package Manager | Poetry | Latest | Python dependency management |

---

## 13. Build Plan

### Phase 1 — Infrastructure & Sandbox (Hours 0–4)

- Write `docker-compose.yml`: `api`, `worker`, `redis`, `postgres`, `sandbox-base` services.
- Build `malsight-sandbox` Docker image: Ubuntu 22.04 + strace + Falco + gdb + yara + pefile + pdfminer.
- Verify sandbox isolation: `network_mode: none`, `cap_drop: ALL` — confirm no internet access and no host filesystem visibility from inside container.
- Set up PostgreSQL schema: `jobs` table and `reports` table (stores full report JSON including reasoning chain).

### Phase 2 — Tool Implementations (Hours 4–14)

Implement every tool in the catalog as a standalone Python function returning structured JSON. Build and test each independently before wiring to the agent.

- **Threat Intel:** `check_malwarebazaar()`, `check_virustotal()`, `check_ip_reputation()`, `check_domain_reputation()`
- **Static:** `get_file_magic()`, `get_entropy()`, `extract_strings()`, `get_pe_imports()`, `get_pe_sections()`, `detect_packer()`, `check_digital_signature()`, `get_compile_timestamp()`, `analyze_pdf_structure()`, `deobfuscate_script()`
- **Sandbox:** `run_sandbox()`, `capture_memory_dump()`, `monitor_filesystem()`, `get_dropped_files()`
- **Memory:** `scan_pe_headers()`, `extract_strings_from_memory()`, `detect_shellcode()`, `get_memory_entropy()`, `analyze_injected_pe()`, `run_yara()`
- **Anti-analysis:** `detect_anti_debug()`, `detect_anti_vm()`, `detect_anti_sandbox()`
- **IOC + Control:** `extract_iocs()`, `get_report()`

Build `tool_executor.py`: receives a tool name + parameters dict from the agent, dispatches to the correct implementation, and returns the JSON result.

Unit test: every tool individually on known inputs before agent integration.

### Phase 3 — Gemini Agent Loop (Hours 14–20)

- Implement the agent loop in `agent.py` using Gemini's function calling API.
- Convert all 30 tool signatures into Gemini function declarations (name, description, parameter schema).
- Implement the iteration loop: agent generates message with tool calls → execute via `tool_executor` → append result to conversation history → loop until `get_report()` or max iterations.
- Capture agent reasoning text at every step into the `reasoning_chain` list.
- Implement mode-aware system prompt injection (Standard vs. Deep Scan max iterations and instructions).
- Force `get_report()` on max iteration breach with `incomplete_analysis: true` flag.
- Test with 5 labeled samples — 1 benign, 1 known-hash malicious, 1 UPX-packed, 1 PDF, 1 anti-sandbox. Verify agent follows expected patterns for each. See Appendix B for full loop implementation.

### Phase 4 — FastAPI Backend + Queue (Hours 20–25)

- Scaffold FastAPI with `/analyze`, `/report/{id}`, `/reports`, `/health` routes.
- `/analyze`: validate file, save to staging, enqueue RQ job (file_path + mode), return `job_id`.
- RQ worker: call `agent.run(file_path, mode)` → store returned report in PostgreSQL.
- `/report/{id}`: return `{status, current_step, current_action}` while running; full report when complete.
- Update job status at each agent step so polling returns live progress.

### Phase 5 — React Frontend (Hours 25–31)

- Upload page: drag-and-drop zone + mode selector (Standard / Deep Scan) + submit.
- Live agent monitor: poll every 2 seconds, show current step number, tool being called, and agent reasoning text.
- Threat report view: verdict badge, key indicators, ATT&CK tags, IOC block, **Analysis Reasoning Chain** (collapsible, full step-by-step agent investigation log).
- Report history table.
- Connect all views to FastAPI backend.

### Phase 6 — Demo Prep (Hours 31–36)

- Pre-analyze 4 demo samples: benign script (fast-track demo), known-hash malicious (1-call demo), UPX-packed trojan (full agent investigation demo), PDF with embedded JS.
- Cache all reports in PostgreSQL. Never hit live APIs during demo.
- Test `docker-compose down && docker-compose up` — clean environment from scratch.
- Write README: one-command setup, API key configuration guide.
- Rehearse pitch: problem (fixed pipelines) → agent solution → live agent monitor showing real-time reasoning → full report with reasoning chain → why this is better.

---

## 14. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Agent calls wrong tools / loops inefficiently | Medium | Medium | System prompt with explicit strategy guidance. Max iteration cap with forced report. Test against 10+ labeled samples before demo. |
| Agent never calls get_report() | Low | High | Hard cap at max iterations. Force-invoke `get_report()` with current evidence + `incomplete_analysis: true` flag. |
| Gemini function calling format error | Low | Medium | Validate all tool declarations against Gemini schema before runtime. Wrap every agent call in try/except with fallback to fixed pipeline. |
| Docker sandbox escape | Low | Critical | `cap_drop: ALL`, `no-new-privileges`, `network_mode: none`, `user: nobody`, tmpfs-only. Never mount host paths. |
| gcore fails to attach to process | Medium | Low | Non-blocking — agent receives `{"captured": false}` and adjusts strategy. |
| Anti-sandbox malware runs cleanly in Standard mode | Medium | Medium | `detect_anti_vm()` and `detect_anti_sandbox()` flag the evasion as evidence even if sandbox execution was clean. Agent maps this to T1497. |
| Gemini API rate limit during demo | Medium | High | Pre-cache all demo reports. Agent never runs live during the pitch. |
| VirusTotal / AbuseIPDB rate limits | Low | Low | Both tools are optional agent choices, not mandatory. Cache IOC results per-IP per-session. |
| Reasoning chain too verbose for UI | Low | Low | Truncate each reasoning step to 300 chars in the UI. Full text available on expand. |
| Deep Scan exceeds 5-minute budget | Low | Medium | 10-minute hard wall clock timeout in RQ. Agent is budgeted 20 iterations which empirically runs in < 5 minutes. |

---

## 15. Future Roadmap

### V3 — Within 30 Days

- **Multi-file ZIP analysis:** Agent extracts archive, runs child jobs for each file, synthesizes a combined report.
- **Dropped file child analysis:** Agent spawns a sub-agent for each file dropped by the malware during sandbox execution.
- **Agent-generated YARA rules:** After analysis, agent writes a YARA rule capturing the unique behavioral and memory patterns it discovered, exportable from the report.
- **Webhook delivery:** Notify a configured URL when a Deep Scan report completes.

### V4 — Within 90 Days

- **Behavioral similarity clustering:** Agent compares current sample's behavioral fingerprint against historical reports and flags family matches.
- **Network traffic capture:** Controlled DNS/HTTP egress in Deep Scan mode — agent can allow one outbound connection attempt and capture the full C2 handshake.
- **Full memory forensics:** Volatility3 integration as an agent tool — structured extraction of running processes, open handles, loaded modules, and network socket state at dump time.
- **Agent memory across jobs:** Agent accumulates knowledge of malware families it has previously analyzed — new samples of the same family get faster, higher-confidence verdicts.

---

## Appendix A: Gemini API — Tool Calling Reference

### A.1 Setup

```bash
pip install google-generativeai
```

```env
GEMINI_API_KEY=your_api_key_here
```

### A.2 Defining Tools for Function Calling

Each tool in the catalog is registered as a Gemini `FunctionDeclaration`:

```python
import google.generativeai as genai
from google.generativeai.types import FunctionDeclaration, Tool

check_malwarebazaar_fn = FunctionDeclaration(
    name="check_malwarebazaar",
    description="Query MalwareBazaar for the file's SHA-256 hash. "
                "Call this early — a hit means no sandbox is needed.",
    parameters={
        "type": "object",
        "properties": {
            "hash": { "type": "string", "description": "SHA-256 hex string" }
        },
        "required": ["hash"]
    }
)

run_sandbox_fn = FunctionDeclaration(
    name="run_sandbox",
    description="Execute the target file in an isolated Docker container under strace and Falco. "
                "Returns behavioral summary. Only call after static analysis suggests it's needed.",
    parameters={
        "type": "object",
        "properties": {
            "duration":       { "type": "integer", "description": "Execution timeout in seconds (default 30, max 120)" },
            "capture_focus":  { "type": "string",  "description": "One of: all, network, filesystem, process" }
        },
        "required": []
    }
)

# ... register all 30 tools similarly

malsight_tools = Tool(function_declarations=[
    check_malwarebazaar_fn,
    check_virustotal_fn,
    check_ip_reputation_fn,
    check_domain_reputation_fn,
    get_file_magic_fn,
    get_entropy_fn,
    extract_strings_fn,
    get_pe_imports_fn,
    get_pe_sections_fn,
    detect_packer_fn,
    check_digital_signature_fn,
    get_compile_timestamp_fn,
    analyze_pdf_structure_fn,
    deobfuscate_script_fn,
    run_sandbox_fn,
    capture_memory_dump_fn,
    monitor_filesystem_fn,
    get_dropped_files_fn,
    scan_pe_headers_fn,
    extract_strings_from_memory_fn,
    detect_shellcode_fn,
    get_memory_entropy_fn,
    analyze_injected_pe_fn,
    run_yara_fn,
    detect_anti_debug_fn,
    detect_anti_vm_fn,
    detect_anti_sandbox_fn,
    extract_iocs_fn,
    get_report_fn,
])
```

### A.3 Model Configuration

```python
model = genai.GenerativeModel(
    model_name="gemini-1.5-pro",
    tools=[malsight_tools],
    generation_config=genai.GenerationConfig(
        temperature=0.2,      # Slightly higher than pure classification — agent needs to reason
        max_output_tokens=1024,
    ),
    system_instruction=build_system_prompt(mode)
)
```

---

## Appendix B: Agent Loop Implementation

```python
# agent.py
import json
import google.generativeai as genai
from tool_executor import execute_tool

MAX_ITERATIONS = {"standard": 8, "deep_scan": 20}

def run_agent(file_path: str, file_meta: dict, mode: str) -> dict:
    """
    Run the Gemini agent loop for a single file analysis job.
    Returns the completed report dict (including reasoning_chain).
    """
    model    = build_model(mode)
    history  = []
    reasoning_chain = []
    iterations = 0
    report = None

    # Initial user message — file context
    initial_message = {
        "role": "user",
        "parts": [
            f"Analyze this file.\n"
            f"Filename: {file_meta['filename']}\n"
            f"SHA-256: {file_meta['sha256']}\n"
            f"Size: {file_meta['size_bytes']} bytes\n"
            f"Declared type: {file_meta['extension']}\n"
            f"On-disk entropy: {file_meta['entropy']}\n"
            f"Mode: {mode}\n"
            f"Begin your investigation."
        ]
    }
    history.append(initial_message)

    while iterations < MAX_ITERATIONS[mode]:
        iterations += 1

        # Send current history to Gemini
        response = model.generate_content(history)
        candidate = response.candidates[0].content
        history.append({"role": "model", "parts": candidate.parts})

        # Extract agent reasoning text (text parts before tool calls)
        reasoning_text = " ".join(
            part.text for part in candidate.parts
            if hasattr(part, "text") and part.text
        )

        # Extract tool calls
        tool_calls = [
            part.function_call
            for part in candidate.parts
            if hasattr(part, "function_call")
        ]

        if not tool_calls:
            # Agent produced text with no tool call — prompt it to act
            history.append({
                "role": "user",
                "parts": ["Please call a tool to continue the investigation, or call get_report() if you have enough evidence."]
            })
            continue

        # Execute each tool call
        tool_results = []
        for call in tool_calls:
            tool_name   = call.name
            tool_params = dict(call.args)

            # Special case: agent is done
            if tool_name == "get_report":
                report = build_report(tool_params, reasoning_chain, file_meta, mode, iterations)
                return report

            # Execute tool and capture result
            result = execute_tool(tool_name, tool_params, file_path)

            # Capture reasoning step
            reasoning_chain.append({
                "step_number":    iterations,
                "reasoning":      reasoning_text,
                "tool_called":    f"{tool_name}({json.dumps(tool_params)})",
                "result_summary": summarize_result(result),
            })

            tool_results.append({
                "function_response": {
                    "name":     tool_name,
                    "response": result
                }
            })

        # Feed all tool results back into conversation
        history.append({"role": "user", "parts": tool_results})

    # Max iterations reached — force report
    report = build_report(
        verdict_params={"verdict": "unknown", "confidence": 0,
                        "summary": "Analysis incomplete — max iterations reached.",
                        "incomplete_analysis": True},
        reasoning_chain=reasoning_chain,
        file_meta=file_meta,
        mode=mode,
        iterations=iterations
    )
    return report


def execute_tool(tool_name: str, params: dict, file_path: str) -> dict:
    """Dispatch tool call to the correct implementation."""
    from tools import (
        check_malwarebazaar, check_virustotal, check_ip_reputation,
        check_domain_reputation, get_file_magic, get_entropy,
        extract_strings, get_pe_imports, get_pe_sections, detect_packer,
        check_digital_signature, get_compile_timestamp, analyze_pdf_structure,
        deobfuscate_script, run_sandbox, capture_memory_dump,
        monitor_filesystem, get_dropped_files, scan_pe_headers,
        extract_strings_from_memory, detect_shellcode, get_memory_entropy,
        analyze_injected_pe, run_yara, detect_anti_debug, detect_anti_vm,
        detect_anti_sandbox, extract_iocs
    )
    dispatch = {
        "check_malwarebazaar":         lambda p: check_malwarebazaar(p["hash"]),
        "check_virustotal":            lambda p: check_virustotal(p["hash"]),
        "check_ip_reputation":         lambda p: check_ip_reputation(p["ip"]),
        "check_domain_reputation":     lambda p: check_domain_reputation(p["domain"]),
        "get_file_magic":              lambda p: get_file_magic(file_path),
        "get_entropy":                 lambda p: get_entropy(file_path, p.get("region")),
        "extract_strings":             lambda p: extract_strings(file_path, p.get("min_length", 6)),
        "get_pe_imports":              lambda p: get_pe_imports(file_path),
        "get_pe_sections":             lambda p: get_pe_sections(file_path),
        "detect_packer":               lambda p: detect_packer(file_path),
        "check_digital_signature":     lambda p: check_digital_signature(file_path),
        "get_compile_timestamp":       lambda p: get_compile_timestamp(file_path),
        "analyze_pdf_structure":       lambda p: analyze_pdf_structure(file_path),
        "deobfuscate_script":          lambda p: deobfuscate_script(file_path),
        "run_sandbox":                 lambda p: run_sandbox(file_path, p.get("duration", 30), p.get("capture_focus", "all")),
        "capture_memory_dump":         lambda p: capture_memory_dump(p.get("timing", 5)),
        "monitor_filesystem":          lambda p: monitor_filesystem(),
        "get_dropped_files":           lambda p: get_dropped_files(),
        "scan_pe_headers":             lambda p: scan_pe_headers(p.get("target", "memdump")),
        "extract_strings_from_memory": lambda p: extract_strings_from_memory(p.get("filter", "all")),
        "detect_shellcode":            lambda p: detect_shellcode(),
        "get_memory_entropy":          lambda p: get_memory_entropy(p.get("region")),
        "analyze_injected_pe":         lambda p: analyze_injected_pe(p["offset"]),
        "run_yara":                    lambda p: run_yara(p["rules"], p.get("target", "file")),
        "detect_anti_debug":           lambda p: detect_anti_debug(file_path),
        "detect_anti_vm":              lambda p: detect_anti_vm(file_path),
        "detect_anti_sandbox":         lambda p: detect_anti_sandbox(file_path),
        "extract_iocs":                lambda p: extract_iocs(p.get("target", "file")),
    }
    handler = dispatch.get(tool_name)
    if not handler:
        return {"error": f"Unknown tool: {tool_name}"}
    try:
        return handler(params)
    except Exception as e:
        return {"error": str(e), "tool": tool_name}
```

---

## Appendix C: Full Tool Implementations

### C.1 Packer Detector

```python
# tools/detect_packer.py
import pefile

PACKER_SIGNATURES = {
    "UPX":       [b"UPX0", b"UPX1", b"UPX!"],
    "MPRESS":    [b".MPRESS1", b".MPRESS2"],
    "ASPack":    [b".aspack", b".adata"],
    "Themida":   [b".themida"],
    "VMProtect": [b".vmp0", b".vmp1"],
}

UPX_DECOMPRESSION_TIME_MS = {
    "small":  300,   # < 100KB
    "medium": 800,   # 100KB – 1MB
    "large":  2000,  # > 1MB
}

def detect_packer(file_path: str) -> dict:
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": str(e)}

    for packer_name, sigs in PACKER_SIGNATURES.items():
        for sig in sigs:
            if sig in data:
                size_bucket = ("small" if len(data) < 100_000
                               else "medium" if len(data) < 1_000_000
                               else "large")
                return {
                    "packer_detected": True,
                    "packer_name": packer_name,
                    "decompression_time_estimate_ms":
                        UPX_DECOMPRESSION_TIME_MS.get(size_bucket, 1000)
                        if packer_name == "UPX" else 1000,
                }

    # Check PE section names as fallback
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            for packer_name, sigs in PACKER_SIGNATURES.items():
                if any(name.lower() in sig.decode().lower() for sig in sigs):
                    return {"packer_detected": True, "packer_name": packer_name,
                            "decompression_time_estimate_ms": 1000}
    except Exception:
        pass

    return {"packer_detected": False, "packer_name": None}
```

### C.2 Anti-Analysis Detection

```python
# tools/detect_anti_analysis.py
import pefile

ANTI_DEBUG_IMPORTS = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    "FindWindow", "BlockInput",
]

ANTI_VM_REGISTRY_KEYS = [
    b"VMware", b"VirtualBox", b"VBOX", b"QEMU", b"Hyper-V",
    b"vmtoolsd", b"vboxservice", b"vboxtray",
]

ANTI_VM_MAC_PREFIXES = [
    b"\x00\x0C\x29",  # VMware
    b"\x00\x50\x56",  # VMware
    b"\x08\x00\x27",  # VirtualBox
]

ANTI_SANDBOX_PATTERNS = [
    b"GetCursorPos",        # Mouse movement check
    b"GetSystemMetrics",    # Screen resolution check (sandbox = unusual)
    b"GetTickCount",        # Timing-based evasion
    b"NtDelayExecution",    # Long sleep before payload
    b"GetForegroundWindow", # Check for foreground activity
]

def detect_anti_debug(file_path: str) -> dict:
    techniques = []
    try:
        pe = pefile.PE(file_path)
        imports = [
            entry.name.decode("utf-8", errors="ignore")
            for entry in pe.DIRECTORY_ENTRY_IMPORT
            for entry in entry.imports
            if entry.name
        ]
        for name in ANTI_DEBUG_IMPORTS:
            if name in imports:
                techniques.append(f"{name} import detected")
    except Exception:
        pass

    with open(file_path, "rb") as f:
        data = f.read()

    # RDTSC timing check (common debugger detection byte pattern)
    if b"\x0f\x31" in data:
        techniques.append("RDTSC timing check pattern (0F 31)")
    # INT 3 breakpoint scanning
    if data.count(b"\xcc") > 10:
        techniques.append("Excessive INT3 breakpoints — possible debugger scanning")

    return {
        "anti_debug_detected": len(techniques) > 0,
        "techniques": techniques,
    }


def detect_anti_vm(file_path: str) -> dict:
    techniques = []
    with open(file_path, "rb") as f:
        data = f.read()

    for key in ANTI_VM_REGISTRY_KEYS:
        if key in data:
            techniques.append(f"VM registry key reference: {key.decode('utf-8', errors='replace')}")

    for prefix in ANTI_VM_MAC_PREFIXES:
        if prefix in data:
            techniques.append(f"VM MAC prefix detected: {prefix.hex()}")

    # CPUID hypervisor bit check (ECX bit 31)
    if b"\x0f\xa2" in data:
        techniques.append("CPUID instruction — possible hypervisor detection")

    return {
        "anti_vm_detected": len(techniques) > 0,
        "techniques": techniques,
    }


def detect_anti_sandbox(file_path: str) -> dict:
    techniques = []
    with open(file_path, "rb") as f:
        data = f.read()

    for pattern in ANTI_SANDBOX_PATTERNS:
        if pattern in data:
            techniques.append(f"{pattern.decode('utf-8', errors='ignore')} call detected")

    # Very long sleep values in binary (> 60 seconds = 60000ms)
    # NtDelayExecution takes a 100ns interval — 600,000,000 = 60s
    import struct
    offset = 0
    while True:
        idx = data.find(b"\x00\x00\x00\x00", offset)
        if idx == -1:
            break
        try:
            val = struct.unpack_from("<Q", data, idx)[0]
            if val > 600_000_000:   # > 60 seconds in 100ns units
                techniques.append(f"Possible long-sleep value {val} at offset {hex(idx)}")
                break
        except struct.error:
            pass
        offset = idx + 4

    return {
        "anti_sandbox_detected": len(techniques) > 0,
        "techniques": techniques,
    }
```

### C.3 RAM Analyzer (from v2.0, unchanged)

Full implementation in the original `memory_analyzer.py` — `analyze_memory_dump()`, `extract_pe_headers()`, `find_injected_regions()`, `extract_suspicious_strings()`, `calculate_entropy()`, `detect_shellcode_patterns()`, `generate_notes()`. These are called by the agent through the `scan_pe_headers()`, `extract_strings_from_memory()`, `detect_shellcode()`, and `get_memory_entropy()` tool wrappers.

---

## Appendix D: MalwareBazaar Integration

```python
import requests

def check_malwarebazaar(sha256: str) -> dict:
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=5
        )
        data = resp.json()
        if data.get("query_status") == "hash_not_found":
            return {"found": False}
        entry = data.get("data", [{}])[0]
        return {
            "found":           True,
            "malware_family":  entry.get("signature"),
            "tags":            entry.get("tags", []),
            "first_seen":      entry.get("first_seen"),
            "reporter":        entry.get("reporter"),
        }
    except Exception as e:
        return {"found": False, "error": str(e)}
```

> 🚨 **Safety Note:** All malware samples must only be handled inside the isolated Docker sandbox. Never execute samples outside the sandbox. Use the EICAR test string for any live demonstrations. Real MalwareBazaar samples are only appropriate in isolated development and testing environments.

---

*MalSight PRD v2.1 — Hackathon Team — May 2026*
*Changes from v2.0: Replaced fixed sequential pipeline with Gemini Agent Brain. Agent uses Gemini 1.5 Pro function calling to drive the entire analysis — choosing which tools to call based on evidence, in what order, and when to conclude. Added 30-tool catalog across 6 categories (threat intel, static analysis, sandbox execution, memory forensics, anti-analysis detection, IOC extraction). Added Standard mode (8 tool calls, < 60s) and Deep Scan mode (20 tool calls, < 5 min). Agent reasoning chain captured at every step and included in final report. Live agent status shown in dashboard during analysis. Added Appendix A (Gemini function calling), Appendix B (agent loop implementation), Appendix C (packer detector + anti-analysis tools). Updated all sections: architecture, metrics, tech stack, build plan, risks, roadmap.*
