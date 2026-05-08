# Phase 2: dispatches agent tool calls to the correct tool implementation
# Full dispatch table from PRD Appendix B, extended to pass file_path to tools that need it.
from tools.threat_intel import (
    check_malwarebazaar, check_virustotal, check_ip_reputation, check_domain_reputation,
)
from tools.static_analysis import (
    get_file_magic, get_entropy, extract_strings, get_pe_imports, get_pe_sections,
    detect_packer, check_digital_signature, get_compile_timestamp,
    analyze_pdf_structure, deobfuscate_script,
)
from tools.sandbox import run_sandbox, capture_memory_dump, monitor_filesystem, get_dropped_files
from tools.memory import (
    scan_pe_headers, extract_strings_from_memory, detect_shellcode,
    get_memory_entropy, analyze_injected_pe, run_yara,
)
from tools.anti_analysis import detect_anti_debug, detect_anti_vm, detect_anti_sandbox
from tools.ioc import extract_iocs, get_report


def execute_tool(tool_name: str, params: dict, file_path: str) -> dict:
    """Dispatch a tool call by name to its implementation; return structured JSON result."""

    dispatch = {
        # --- Threat Intelligence ---
        "check_malwarebazaar": lambda p: check_malwarebazaar(p["hash"]),
        "check_virustotal":    lambda p: check_virustotal(p["hash"]),
        "check_ip_reputation": lambda p: check_ip_reputation(p["ip"]),
        "check_domain_reputation": lambda p: check_domain_reputation(p["domain"]),

        # --- Static Analysis ---
        "get_file_magic":          lambda p: get_file_magic(file_path),
        "get_entropy":             lambda p: get_entropy(file_path, p.get("region")),
        "extract_strings":         lambda p: extract_strings(
                                        file_path,
                                        p.get("min_length", 6),
                                        p.get("encoding"),
                                    ),
        "get_pe_imports":          lambda p: get_pe_imports(file_path),
        "get_pe_sections":         lambda p: get_pe_sections(file_path),
        "detect_packer":           lambda p: detect_packer(file_path),
        "check_digital_signature": lambda p: check_digital_signature(file_path),
        "get_compile_timestamp":   lambda p: get_compile_timestamp(file_path),
        "analyze_pdf_structure":   lambda p: analyze_pdf_structure(file_path),
        "deobfuscate_script":      lambda p: deobfuscate_script(file_path),

        # --- Sandbox Execution ---
        "run_sandbox":        lambda p: run_sandbox(
                                    file_path,
                                    p.get("duration", 30),
                                    p.get("capture_focus", "all"),
                                ),
        "capture_memory_dump": lambda p: capture_memory_dump(p.get("timing", 5)),
        "monitor_filesystem":  lambda p: monitor_filesystem(file_path),
        "get_dropped_files":   lambda p: get_dropped_files(),

        # --- Memory Forensics ---
        "scan_pe_headers":             lambda p: scan_pe_headers(p.get("target", "memdump")),
        "extract_strings_from_memory": lambda p: extract_strings_from_memory(
                                            p.get("filter", "all"),
                                            file_path,
                                        ),
        "detect_shellcode":    lambda p: detect_shellcode(),
        "get_memory_entropy":  lambda p: get_memory_entropy(p.get("region")),
        "analyze_injected_pe": lambda p: analyze_injected_pe(p["offset"]),
        "run_yara":            lambda p: run_yara(p["rules"], p.get("target", "file")),

        # --- Anti-Analysis Detection ---
        "detect_anti_debug":   lambda p: detect_anti_debug(file_path),
        "detect_anti_vm":      lambda p: detect_anti_vm(file_path),
        "detect_anti_sandbox": lambda p: detect_anti_sandbox(file_path),

        # --- IOC Extraction & Control ---
        "extract_iocs": lambda p: extract_iocs(p.get("target", "file"), file_path),
        # get_report is handled directly by the agent loop — not dispatched here
    }

    handler = dispatch.get(tool_name)
    if handler is None:
        return {"error": f"Unknown tool: {tool_name}"}

    try:
        return handler(params)
    except Exception as e:
        return {"error": str(e), "tool": tool_name}
