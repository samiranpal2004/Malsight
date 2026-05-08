# Phase 3: Gemini 1.5 Pro agent loop using function calling.
# See PRD Section 5 (Agent Brain), Section 7 (Modes), Section 8 (Report schema),
# Appendix A (Tool calling reference), Appendix B (Agent loop).
import json
import time
import uuid
import logging

import google.generativeai as genai
from google.generativeai.types import FunctionDeclaration, Tool

from tool_executor import execute_tool
from malsight.config import GEMINI_API_KEY

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mode configuration
# ---------------------------------------------------------------------------

MAX_ITERATIONS = {"standard": 8, "deep_scan": 20}

# Module-level live job status — read by the FastAPI worker (Phase 4).
# Shape: {job_id: {"step": int, "action": str, "elapsed_seconds": int}}
JOB_STATUS: dict = {}


# ---------------------------------------------------------------------------
# Tool declarations — the full 30-tool catalog from PRD Appendix A.
# Function names MUST match keys in tool_executor.execute_tool dispatch table.
# ---------------------------------------------------------------------------

# --- Category 1: Threat Intelligence Lookups ---

check_malwarebazaar_fn = FunctionDeclaration(
    name="check_malwarebazaar",
    description=(
        "Query MalwareBazaar for the file's SHA-256 hash. "
        "Call this VERY EARLY in any investigation — a hit returns the known "
        "malware family and means no sandbox execution is needed at all."
    ),
    parameters={
        "type": "object",
        "properties": {
            "hash": {"type": "string", "description": "SHA-256 hex string of the file"},
        },
        "required": ["hash"],
    },
)

check_virustotal_fn = FunctionDeclaration(
    name="check_virustotal",
    description=(
        "Query VirusTotal for multi-engine consensus on the file's SHA-256 hash. "
        "Use after MalwareBazaar miss for a broader detection signal."
    ),
    parameters={
        "type": "object",
        "properties": {
            "hash": {"type": "string", "description": "SHA-256 hex string of the file"},
        },
        "required": ["hash"],
    },
)

check_ip_reputation_fn = FunctionDeclaration(
    name="check_ip_reputation",
    description=(
        "Query AbuseIPDB for an IPv4/IPv6 address. Call after IPs are extracted "
        "from strings, IOCs, or memory — confirms whether contacted hosts are "
        "known C2 / malicious infrastructure."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "IPv4 or IPv6 address"},
        },
        "required": ["ip"],
    },
)

check_domain_reputation_fn = FunctionDeclaration(
    name="check_domain_reputation",
    description=(
        "Query threat intelligence feeds for a domain name. Call after a domain "
        "is extracted from the file or memory dump to flag C2/phishing infrastructure."
    ),
    parameters={
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Fully-qualified domain name"},
        },
        "required": ["domain"],
    },
)

# --- Category 2: Static File Analysis ---

get_file_magic_fn = FunctionDeclaration(
    name="get_file_magic",
    description=(
        "Detect the true file type via libmagic, ignoring the declared extension. "
        "Call early to confirm what you're really looking at (PE32+, PDF, ELF, "
        "OLE2, ZIP, script, etc.) — especially when extension and content may differ."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

get_entropy_fn = FunctionDeclaration(
    name="get_entropy",
    description=(
        "Compute Shannon entropy for the whole file or a specific PE section. "
        "High entropy (> 7.0) strongly indicates packing or encryption. "
        "Use to confirm packing suspicion before calling detect_packer()."
    ),
    parameters={
        "type": "object",
        "properties": {
            "region": {
                "type": "string",
                "description": "Optional named PE section (e.g. '.text', '.upx1'). Omit for whole-file entropy.",
            },
        },
        "required": [],
    },
)

extract_strings_fn = FunctionDeclaration(
    name="extract_strings",
    description=(
        "Extract printable ASCII and UTF-16LE strings from the file on disk, "
        "returning all strings plus a security-relevant subset (URLs, IPs, "
        "registry keys, API names, paths). Useful for unpacked binaries and scripts."
    ),
    parameters={
        "type": "object",
        "properties": {
            "min_length": {"type": "integer", "description": "Minimum string length (default 6)"},
            "encoding": {"type": "string", "description": "Optional encoding filter (e.g. 'ascii', 'utf-16le')"},
        },
        "required": [],
    },
)

get_pe_imports_fn = FunctionDeclaration(
    name="get_pe_imports",
    description=(
        "Parse the PE import table and return imported DLLs and function names. "
        "Suspicious combinations (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) "
        "are near-definitive injection indicators. Call on any PE32/PE32+ sample."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

get_pe_sections_fn = FunctionDeclaration(
    name="get_pe_sections",
    description=(
        "Return PE section headers (name, virtual size, raw size, entropy, flags). "
        "Abnormal section names (.upx0, .aspack), rwx flags, or high-entropy "
        "executable sections strongly suggest packing or self-modification."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

detect_packer_fn = FunctionDeclaration(
    name="detect_packer",
    description=(
        "Identify the specific packer/protector (UPX, MPRESS, Themida, ASPack, "
        "VMProtect, Enigma) and estimate decompression time. Call after entropy "
        "indicates packing — knowing the packer tells you when to capture memory."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

check_digital_signature_fn = FunctionDeclaration(
    name="check_digital_signature",
    description=(
        "Verify the PE Authenticode digital signature and certificate chain. "
        "Forged, expired, or self-signed certificates that claim a major vendor "
        "are a significant red flag. Call on any signed PE."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

get_compile_timestamp_fn = FunctionDeclaration(
    name="get_compile_timestamp",
    description=(
        "Extract the PE compile timestamp; flag zeroed or suspiciously round "
        "values (common faking technique). Cheap signal — use opportunistically on PEs."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

analyze_pdf_structure_fn = FunctionDeclaration(
    name="analyze_pdf_structure",
    description=(
        "Deep PDF structural analysis — extracts JavaScript objects, embedded "
        "files, suspicious actions (/Launch, /JavaScript, /OpenAction), and "
        "filter chains. Call first whenever the file is a PDF."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

deobfuscate_script_fn = FunctionDeclaration(
    name="deobfuscate_script",
    description=(
        "Statically deobfuscate Python / JavaScript / PowerShell / shell scripts "
        "(base64, hex, string concat, simple eval chains). Call on any script "
        "file before judging it benign — obfuscation usually hides malicious payload."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

# --- Category 3: Sandbox Execution ---

run_sandbox_fn = FunctionDeclaration(
    name="run_sandbox",
    description=(
        "Execute the target file in an isolated Docker container under strace and Falco. "
        "Returns behavioral summary (file ops, network attempts, child processes, Falco events). "
        "Only call after static analysis suggests it's needed — sandbox execution is expensive."
    ),
    parameters={
        "type": "object",
        "properties": {
            "duration": {
                "type": "integer",
                "description": "Execution timeout in seconds (default 30, max 120 in deep_scan)",
            },
            "capture_focus": {
                "type": "string",
                "description": "One of: all, network, filesystem, process",
            },
        },
        "required": [],
    },
)

capture_memory_dump_fn = FunctionDeclaration(
    name="capture_memory_dump",
    description=(
        "Capture a gcore memory dump of the running sandboxed process at "
        "`timing` seconds after execution start. Time the dump to land just "
        "after packer decompression for the best chance of seeing the real payload."
    ),
    parameters={
        "type": "object",
        "properties": {
            "timing": {
                "type": "integer",
                "description": "Seconds after execution start to capture the dump (default 5)",
            },
        },
        "required": [],
    },
)

monitor_filesystem_fn = FunctionDeclaration(
    name="monitor_filesystem",
    description=(
        "Capture real-time filesystem change events (inotifywait) during sandbox "
        "execution — every file created/modified/deleted by the sample. Useful "
        "for catching droppers."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

get_dropped_files_fn = FunctionDeclaration(
    name="get_dropped_files",
    description=(
        "Retrieve content, SHA-256 hashes, and MIME types of files dropped by "
        "the sample during sandbox execution. Call after monitor_filesystem() "
        "reports new files."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

# --- Category 4: Memory Forensics ---

scan_pe_headers_fn = FunctionDeclaration(
    name="scan_pe_headers",
    description=(
        "Scan the memory dump for embedded PE images (MZ + PE signatures). "
        "Any PE found at a non-zero offset is a likely injected DLL or hollowed payload. "
        "Call after capture_memory_dump() on any packed or suspicious sample."
    ),
    parameters={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "'memdump' (default) or 'file'",
            },
        },
        "required": [],
    },
)

extract_strings_from_memory_fn = FunctionDeclaration(
    name="extract_strings_from_memory",
    description=(
        "Extract strings from the memory dump that were not present on disk — "
        "decrypted C2 URLs, registry keys, API names, etc. Filter by 'ioc', "
        "'registry', 'api', or 'all'. The single most valuable post-dump tool."
    ),
    parameters={
        "type": "object",
        "properties": {
            "filter": {
                "type": "string",
                "description": "One of: ioc, registry, api, all (default all)",
            },
        },
        "required": [],
    },
)

detect_shellcode_fn = FunctionDeclaration(
    name="detect_shellcode",
    description=(
        "Scan the memory dump for shellcode patterns (PEB walk, ROR-13 hash "
        "loops, indirect call-register, NOP sleds). Call when injection is "
        "suspected but no full PE is visible."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

get_memory_entropy_fn = FunctionDeclaration(
    name="get_memory_entropy",
    description=(
        "Per-region entropy across the memory dump. Persistently high entropy "
        "in an executable region post-decompression points to a second-stage "
        "payload still encoded in memory."
    ),
    parameters={
        "type": "object",
        "properties": {
            "region": {
                "type": "string",
                "description": "Optional address range or named region",
            },
        },
        "required": [],
    },
)

analyze_injected_pe_fn = FunctionDeclaration(
    name="analyze_injected_pe",
    description=(
        "Extract the PE image at the given memory offset and run the full static "
        "analysis suite (imports, sections, strings, packer) against it. This is "
        "how you investigate the actual payload independent of the loader."
    ),
    parameters={
        "type": "object",
        "properties": {
            "offset": {
                "type": "string",
                "description": "Hex offset of the injected PE in the memory dump (e.g. '0x3f2000')",
            },
        },
        "required": ["offset"],
    },
)

run_yara_fn = FunctionDeclaration(
    name="run_yara",
    description=(
        "Run named YARA rule sets ('ransomware', 'banker', 'rat', 'coinminer', "
        "'webshell') against the file or memory dump. Returns matched rules and "
        "trigger byte patterns. Cheap signal — use whenever you suspect a family."
    ),
    parameters={
        "type": "object",
        "properties": {
            "rules": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of rule-set names to run",
            },
            "target": {
                "type": "string",
                "description": "'file' (default) or 'memdump'",
            },
        },
        "required": ["rules"],
    },
)

# --- Category 5: Anti-Analysis Detection ---

detect_anti_debug_fn = FunctionDeclaration(
    name="detect_anti_debug",
    description=(
        "Detect anti-debugging techniques (IsDebuggerPresent, RDTSC timing, "
        "NtQueryInformationProcess debug-port checks, SEH tricks). Their presence "
        "is itself a malware indicator and a hint to dump memory rather than trace."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

detect_anti_vm_fn = FunctionDeclaration(
    name="detect_anti_vm",
    description=(
        "Detect VM-detection techniques (CPUID hypervisor bit, VMware/VBox "
        "registry keys, vmtoolsd/vboxservice process checks, VM MAC prefixes). "
        "Anti-VM samples often behave benignly in sandboxes — call this when a "
        "sandbox run produced a near-empty trace."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

detect_anti_sandbox_fn = FunctionDeclaration(
    name="detect_anti_sandbox",
    description=(
        "Detect sandbox-evasion techniques (long sleeps, mouse-movement checks, "
        "low-process-count checks, recently-accessed-file probes). Call when "
        "sandbox execution produced suspiciously little behavior."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
)

# --- Category 6: IOC Extraction & Control ---

extract_iocs_fn = FunctionDeclaration(
    name="extract_iocs",
    description=(
        "Extract all IOCs (IPs, URLs, domains, emails, crypto wallets, mutexes) "
        "from the file on disk or the memory dump, deduplicated and categorized. "
        "Run before reputation checks so you know what to enrich."
    ),
    parameters={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "'file' (default) or 'memdump'",
            },
        },
        "required": [],
    },
)

get_report_fn = FunctionDeclaration(
    name="get_report",
    description=(
        "Signal that the investigation is complete. Call this only when you have "
        "enough evidence to commit to a verdict. Pass the full structured verdict: "
        "verdict, confidence, threat_category, severity, summary, key_indicators, "
        "mitre_techniques, recommended_action, iocs. This terminates the agent loop."
    ),
    parameters={
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "description": "One of: benign, suspicious, malicious",
            },
            "confidence": {
                "type": "integer",
                "description": "0-100, agent's confidence in the verdict",
            },
            "threat_category": {
                "type": "string",
                "description": "E.g. trojan, ransomware, spyware, dropper, unknown",
            },
            "severity": {
                "type": "string",
                "description": "One of: low, medium, high, critical",
            },
            "summary": {
                "type": "string",
                "description": "2-3 sentence plain-English explanation of the verdict",
            },
            "key_indicators": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Top 3-5 findings that drove the verdict",
            },
            "mitre_techniques": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                        "tactic": {"type": "string"},
                        "evidence": {"type": "string"},
                    },
                },
                "description": "MITRE ATT&CK techniques mapped to evidence",
            },
            "recommended_action": {
                "type": "string",
                "description": "Quarantine | Monitor | Safe to execute | Further analysis needed",
            },
            "iocs": {
                "type": "object",
                "description": "Extracted IOCs grouped by type (ips, urls, domains, emails, crypto_wallets, mutexes)",
            },
        },
        "required": ["verdict", "confidence", "summary"],
    },
)


# Single Tool object containing all 30 declarations (29 analysis tools + get_report).
malsight_tools = Tool(
    function_declarations=[
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
    ]
)


# Compact catalog summary injected into the system prompt so the agent has
# the tool list inline (in addition to the formal FunctionDeclarations).
_TOOL_CATALOG_SUMMARY = """\
Threat Intelligence (call these early — fast, cheap):
  - check_malwarebazaar(hash): MalwareBazaar SHA-256 lookup. A hit ends the investigation fast.
  - check_virustotal(hash): VirusTotal multi-engine consensus.
  - check_ip_reputation(ip): AbuseIPDB lookup for an extracted IP.
  - check_domain_reputation(domain): TI feeds for an extracted domain.

Static File Analysis (pre-execution, on-disk):
  - get_file_magic(): true file type via libmagic.
  - get_entropy(region?): Shannon entropy, whole file or named PE section.
  - extract_strings(min_length?, encoding?): printable strings + suspicious subset.
  - get_pe_imports(): imported DLLs/functions; flags injection/network APIs.
  - get_pe_sections(): section headers, entropy, flags.
  - detect_packer(): identify UPX/MPRESS/Themida/ASPack/VMProtect/Enigma + decompression timing.
  - check_digital_signature(): Authenticode verification.
  - get_compile_timestamp(): PE timestamp + faked-timestamp flag.
  - analyze_pdf_structure(): JS, embedded files, /Launch, /OpenAction, filters.
  - deobfuscate_script(): Python/JS/PowerShell/shell static deobfuscation.

Sandbox Execution (only after static analysis suggests it's needed):
  - run_sandbox(duration?, capture_focus?): isolated Docker run under strace+Falco.
  - capture_memory_dump(timing?): gcore dump at timing seconds.
  - monitor_filesystem(): inotifywait file events during execution.
  - get_dropped_files(): content + hashes of dropped files.

Memory Forensics (after capture_memory_dump):
  - scan_pe_headers(target?): find embedded/injected PE images in the dump.
  - extract_strings_from_memory(filter?): runtime-decrypted strings (ioc/registry/api/all).
  - detect_shellcode(): PEB walks, ROR-13 hash loops, NOP sleds.
  - get_memory_entropy(region?): per-region entropy in the dump.
  - analyze_injected_pe(offset): full static suite on a PE found at a memory offset.
  - run_yara(rules, target?): named YARA rule sets vs file or memdump.

Anti-Analysis Detection (call when sandbox produced little behavior):
  - detect_anti_debug(): IsDebuggerPresent, RDTSC, NtQueryInformationProcess.
  - detect_anti_vm(): CPUID/VMware/VBox/process-name/MAC checks.
  - detect_anti_sandbox(): long sleeps, mouse checks, process-count checks.

IOC Extraction & Control:
  - extract_iocs(target?): IPs, URLs, domains, emails, crypto wallets, mutexes.
  - get_report(...): TERMINATES the loop. Provide your final verdict and all fields.
"""


# ---------------------------------------------------------------------------
# System prompt builder
# ---------------------------------------------------------------------------

def build_system_prompt(mode: str) -> str:
    """Return the full agent system prompt with tool catalog and mode-specific limit."""
    if mode not in MAX_ITERATIONS:
        raise ValueError(f"Unknown mode: {mode!r}. Must be 'standard' or 'deep_scan'.")
    call_limit = MAX_ITERATIONS[mode]
    return (
        "You are MalSight, an expert malware analyst AI. You have access to a catalog of\n"
        "analysis tools. Your job is to investigate a suspicious file by calling tools\n"
        "strategically — not exhaustively. Think like a senior analyst: form a hypothesis\n"
        "from initial signals, call the tools most likely to confirm or refute it, and\n"
        "follow interesting findings.\n"
        "\n"
        "Rules:\n"
        "1. At each step, briefly explain your reasoning BEFORE calling a tool.\n"
        "   This reasoning will be shown to the analyst in the final report.\n"
        "2. Do not call a tool whose result you can already infer from prior results.\n"
        "3. If the file is clearly benign (low entropy, benign strings, clean hash,\n"
        "   no suspicious imports), call get_report() early — do not waste time.\n"
        "4. If you find something unexpected (injected PE, anti-sandbox code, unknown\n"
        "   packer), follow it — call additional tools to understand it fully.\n"
        "5. Always check the hash before sandboxing — avoid unnecessary execution.\n"
        f"6. You are running in '{mode}' mode. Target ≤ {call_limit} tool calls total. "
        "If you exceed this budget the loop will be force-terminated, so plan your "
        "investigation accordingly.\n"
        "7. When you call get_report(), provide your final verdict, confidence,\n"
        "   threat category, severity, summary, key indicators, and MITRE ATT&CK\n"
        "   technique mappings as a structured JSON object.\n"
        "\n"
        "You have the following tools available:\n"
        f"{_TOOL_CATALOG_SUMMARY}"
    )


# ---------------------------------------------------------------------------
# Gemini model builder
# ---------------------------------------------------------------------------

def build_model(mode: str):
    """Configure and return a Gemini GenerativeModel for the given mode."""
    genai.configure(api_key=GEMINI_API_KEY())

    return genai.GenerativeModel(
        model_name="gemini-1.5-pro",
        tools=[malsight_tools],
        generation_config=genai.GenerationConfig(
            temperature=0.2,
            max_output_tokens=1024,
        ),
        system_instruction=build_system_prompt(mode),
    )


# ---------------------------------------------------------------------------
# Job status updater (Phase 4 worker reads from this)
# ---------------------------------------------------------------------------

def update_job_status(job_id: str, step: int, action: str, start_time: float) -> None:
    """Record live agent progress so the API can stream it to the dashboard."""
    JOB_STATUS[job_id] = {
        "step": step,
        "action": action,
        "elapsed_seconds": int(time.time() - start_time),
    }


# ---------------------------------------------------------------------------
# Result summarization
# ---------------------------------------------------------------------------

def _summarize_result(tool_name: str, result: dict) -> str:
    """Produce a max 200-char plain-English summary of a tool result."""
    if not isinstance(result, dict):
        return str(result)[:200]

    if "error" in result:
        return f"Error in {tool_name}: {str(result['error'])[:160]}"

    # Lightweight per-tool synopses
    summary: str
    if tool_name in ("check_malwarebazaar", "check_virustotal"):
        if result.get("found"):
            family = result.get("malware_family") or result.get("majority_verdict") or "match"
            extra = f" ({result['detections']}/{result['total_engines']})" if "detections" in result else ""
            summary = f"Hit: {family}{extra}"
        else:
            summary = "No hit in threat-intel database."
    elif tool_name == "check_ip_reputation":
        score = result.get("abuse_confidence_score")
        cats = ",".join(result.get("categories", []) or [])
        summary = f"IP {result.get('ip','?')} abuse score {score}; categories: {cats or 'none'}"
    elif tool_name == "check_domain_reputation":
        summary = f"Domain {result.get('domain','?')} verdict: {result.get('verdict','unknown')}"
    elif tool_name == "get_file_magic":
        summary = f"Magic: {result.get('magic_type','unknown')}"
    elif tool_name == "get_entropy":
        summary = f"Overall entropy {result.get('overall_entropy','?')}"
    elif tool_name == "extract_strings":
        susp = len(result.get("suspicious", []) or [])
        total = result.get("total_strings", "?")
        summary = f"{total} strings, {susp} flagged suspicious."
    elif tool_name == "get_pe_imports":
        susp = result.get("suspicious_imports", []) or []
        summary = f"{len(result.get('dlls', []) or [])} DLLs, suspicious imports: {susp[:5]}"
    elif tool_name == "get_pe_sections":
        names = [s.get("name") for s in result if isinstance(s, dict)] if isinstance(result, list) else []
        summary = f"Sections: {names[:6]}"
    elif tool_name == "detect_packer":
        if result.get("packer_detected"):
            summary = f"Packer: {result.get('packer_name','?')} v{result.get('version','?')}"
        else:
            summary = "No packer detected."
    elif tool_name == "check_digital_signature":
        if result.get("signed"):
            summary = f"Signed by {result.get('signer','?')}, valid={result.get('valid')}"
        else:
            summary = "Unsigned binary."
    elif tool_name == "get_compile_timestamp":
        summary = f"Timestamp {result.get('timestamp','?')}, suspicious={result.get('suspicious')}"
    elif tool_name == "analyze_pdf_structure":
        summary = (
            f"PDF: js={result.get('has_javascript')}, embedded={result.get('embedded_files',0)}, "
            f"actions={result.get('suspicious_actions',[])}"
        )
    elif tool_name == "deobfuscate_script":
        summary = f"Obfuscation={result.get('obfuscation_detected')}, techniques={result.get('techniques',[])}"
    elif tool_name == "run_sandbox":
        net = result.get("network_attempts", {}) or {}
        procs = result.get("processes_spawned", []) or []
        summary = f"Sandbox: {net.get('count',0)} net attempts, procs={procs[:3]}"
    elif tool_name == "capture_memory_dump":
        summary = (
            f"Dump captured={result.get('captured')} at T+{result.get('timing_seconds','?')}s, "
            f"size={result.get('dump_size_bytes','?')}B"
        )
    elif tool_name == "monitor_filesystem":
        created = result.get("created", []) or []
        summary = f"FS events: created={len(created)}, modified={len(result.get('modified',[]) or [])}"
    elif tool_name == "get_dropped_files":
        n = len(result) if isinstance(result, list) else 0
        summary = f"{n} dropped file(s) recovered."
    elif tool_name == "scan_pe_headers":
        n = result.get("pe_images_found", 0)
        summary = f"{n} PE image(s) found in dump."
    elif tool_name == "extract_strings_from_memory":
        new = result.get("new_strings_vs_disk", []) or []
        summary = f"{len(new)} new strings vs disk; sample: {new[:2]}"
    elif tool_name == "detect_shellcode":
        if result.get("shellcode_detected"):
            inds = result.get("indicators", []) or []
            summary = f"Shellcode detected: {len(inds)} indicator(s)."
        else:
            summary = "No shellcode patterns found."
    elif tool_name == "get_memory_entropy":
        summary = f"Memory overall entropy {result.get('overall','?')}"
    elif tool_name == "analyze_injected_pe":
        imps = result.get("imports", []) or []
        summary = f"Injected PE {result.get('pe_type','?')} imports: {imps[:5]}"
    elif tool_name == "run_yara":
        matches = result.get("matches", []) or []
        rules = [m.get("rule") for m in matches if isinstance(m, dict)]
        summary = f"YARA matches: {rules}" if rules else "No YARA matches."
    elif tool_name in ("detect_anti_debug", "detect_anti_vm", "detect_anti_sandbox"):
        key = {
            "detect_anti_debug": "anti_debug_detected",
            "detect_anti_vm": "anti_vm_detected",
            "detect_anti_sandbox": "anti_sandbox_detected",
        }[tool_name]
        techs = result.get("techniques", []) or []
        summary = f"{tool_name}: detected={result.get(key)}, techniques={techs[:3]}"
    elif tool_name == "extract_iocs":
        summary = (
            f"IOCs: ips={len(result.get('ips',[]) or [])}, urls={len(result.get('urls',[]) or [])}, "
            f"domains={len(result.get('domains',[]) or [])}"
        )
    else:
        # Fallback — short JSON dump
        try:
            summary = json.dumps(result, default=str)
        except Exception:
            summary = str(result)

    return summary[:200]


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_report(
    verdict_params: dict,
    reasoning_chain: list,
    file_meta: dict,
    mode: str,
    iterations: int,
    start_time: float | None = None,
) -> dict:
    """Assemble the final structured report (PRD Section 8.1 + 8.2)."""
    if start_time is None:
        analysis_time = 0
    else:
        analysis_time = int(time.time() - start_time)

    vp = verdict_params or {}

    report = {
        "job_id": str(uuid.uuid4()),
        "mode": mode,
        "verdict": vp.get("verdict", "unknown"),
        "confidence": int(vp.get("confidence", 0) or 0),
        "threat_category": vp.get("threat_category", "unknown"),
        "severity": vp.get("severity", "low"),
        "summary": vp.get("summary", ""),
        "key_indicators": list(vp.get("key_indicators", []) or []),
        "mitre_techniques": list(vp.get("mitre_techniques", []) or []),
        "recommended_action": vp.get("recommended_action", "Further analysis needed"),
        "iocs": dict(vp.get("iocs", {}) or {}),
        "tools_called": iterations,
        "analysis_time_seconds": analysis_time,
        "reasoning_chain": {"steps": list(reasoning_chain or [])},
        "file_meta": dict(file_meta or {}),
    }

    if vp.get("incomplete_analysis"):
        report["incomplete_analysis"] = True

    return report


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def _normalize_args(args) -> dict:
    """Gemini returns args as a proto-Map; coerce to a plain dict."""
    if args is None:
        return {}
    try:
        return {k: v for k, v in args.items()}
    except AttributeError:
        try:
            return dict(args)
        except Exception:
            return {}


def run_agent(file_path: str, file_meta: dict, mode: str) -> dict:
    """
    Drive the Gemini agent loop for a single file.
    Returns the completed report dict (PRD Section 8) including reasoning_chain.
    """
    if mode not in MAX_ITERATIONS:
        raise ValueError(f"Unknown mode: {mode!r}. Must be 'standard' or 'deep_scan'.")

    start_time = time.time()
    # Phase 4 worker passes its own job_id via file_meta so the dashboard can
    # read JOB_STATUS by the same key. Otherwise mint a transient one.
    job_id = file_meta.get("job_id") if isinstance(file_meta, dict) else None
    job_id = job_id or str(uuid.uuid4())
    max_iters = MAX_ITERATIONS[mode]

    model = build_model(mode)
    history: list = []
    reasoning_chain: list = []
    iterations = 0

    initial_message = {
        "role": "user",
        "parts": [
            (
                "Analyze this file.\n"
                f"Filename: {file_meta.get('filename','?')}\n"
                f"SHA-256: {file_meta.get('sha256','?')}\n"
                f"Size: {file_meta.get('size_bytes','?')} bytes\n"
                f"Declared type: {file_meta.get('extension','?')}\n"
                f"On-disk entropy: {file_meta.get('entropy','?')}\n"
                f"Mode: {mode}\n"
                "Begin your investigation."
            )
        ],
    }
    history.append(initial_message)

    update_job_status(job_id, 0, "Step 0 — Briefing the agent on initial file metadata...", start_time)

    while iterations < max_iters:
        iterations += 1

        update_job_status(
            job_id,
            iterations,
            f"Step {iterations} — Agent reasoning and selecting next tool...",
            start_time,
        )

        try:
            response = model.generate_content(history)
        except Exception as e:
            logger.exception("Gemini API call failed at iteration %d", iterations)
            raise

        try:
            candidate = response.candidates[0].content
        except (AttributeError, IndexError, TypeError) as e:
            logger.warning("Malformed Gemini response at iter %d: %s", iterations, e)
            history.append({
                "role": "user",
                "parts": [
                    "Your previous response was malformed. Please call a tool to "
                    "continue the investigation, or call get_report() if you have enough evidence."
                ],
            })
            continue

        history.append({"role": "model", "parts": candidate.parts})

        # Extract reasoning text (text parts, in order, before tool calls)
        reasoning_text = " ".join(
            part.text
            for part in candidate.parts
            if getattr(part, "text", None)
        ).strip()

        # Extract function calls — guard against malformed parts
        tool_calls = []
        for part in candidate.parts:
            fc = getattr(part, "function_call", None)
            if fc and getattr(fc, "name", None):
                tool_calls.append(fc)

        if not tool_calls:
            update_job_status(
                job_id,
                iterations,
                f"Step {iterations} — Agent produced text only; nudging toward tool call...",
                start_time,
            )
            history.append({
                "role": "user",
                "parts": [
                    "Please call a tool to continue, or call get_report() if you have enough evidence."
                ],
            })
            continue

        tool_results = []
        for call in tool_calls:
            tool_name = call.name
            tool_params = _normalize_args(getattr(call, "args", {}))

            # Termination signal — agent says it's done
            if tool_name == "get_report":
                reasoning_chain.append({
                    "step_number": iterations,
                    "reasoning": reasoning_text,
                    "tool_called": "get_report(...)",
                    "result_summary": (
                        f"Verdict: {tool_params.get('verdict','unknown')} "
                        f"(confidence {tool_params.get('confidence','?')})."
                    )[:200],
                })
                update_job_status(
                    job_id,
                    iterations,
                    f"Step {iterations} — Agent committed final verdict. Building report...",
                    start_time,
                )
                return build_report(
                    verdict_params=tool_params,
                    reasoning_chain=reasoning_chain,
                    file_meta=file_meta,
                    mode=mode,
                    iterations=iterations,
                    start_time=start_time,
                )

            update_job_status(
                job_id,
                iterations,
                f"Step {iterations} — Calling {tool_name}({_short_args(tool_params)})...",
                start_time,
            )

            try:
                result = execute_tool(tool_name, tool_params, file_path)
            except Exception as e:
                logger.exception("execute_tool raised for %s", tool_name)
                result = {"error": str(e), "tool": tool_name}

            try:
                params_json = json.dumps(tool_params, default=str)
            except Exception:
                params_json = str(tool_params)

            reasoning_chain.append({
                "step_number": iterations,
                "reasoning": reasoning_text,
                "tool_called": f"{tool_name}({params_json})",
                "result_summary": _summarize_result(tool_name, result),
            })

            tool_results.append({
                "function_response": {
                    "name": tool_name,
                    "response": result,
                }
            })

        history.append({"role": "user", "parts": tool_results})

    # Max iterations reached without get_report() — force-terminate.
    update_job_status(
        job_id,
        iterations,
        f"Step {iterations} — Max iterations hit; force-terminating with incomplete verdict.",
        start_time,
    )
    return build_report(
        verdict_params={
            "verdict": "unknown",
            "confidence": 0,
            "threat_category": "unknown",
            "severity": "low",
            "summary": "Analysis incomplete — max iterations reached before agent committed a verdict.",
            "incomplete_analysis": True,
        },
        reasoning_chain=reasoning_chain,
        file_meta=file_meta,
        mode=mode,
        iterations=iterations,
        start_time=start_time,
    )


def _short_args(params: dict) -> str:
    """Tiny helper to format args for the live status string without flooding it."""
    try:
        s = json.dumps(params, default=str)
    except Exception:
        s = str(params)
    return s if len(s) <= 80 else s[:77] + "..."
