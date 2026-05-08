# Exports all 30 tool functions for use by the agent and tool executor
from .threat_intel import check_malwarebazaar, check_virustotal, check_ip_reputation, check_domain_reputation
from .static_analysis import (
    get_file_magic, get_entropy, extract_strings, get_pe_imports,
    get_pe_sections, detect_packer, check_digital_signature,
    get_compile_timestamp, analyze_pdf_structure, deobfuscate_script,
)
from .sandbox import run_sandbox, capture_memory_dump, monitor_filesystem, get_dropped_files
from .memory import (
    scan_pe_headers, extract_strings_from_memory, detect_shellcode,
    get_memory_entropy, analyze_injected_pe, run_yara,
)
from .anti_analysis import detect_anti_debug, detect_anti_vm, detect_anti_sandbox
from .ioc import extract_iocs, get_report

__all__ = [
    "check_malwarebazaar", "check_virustotal", "check_ip_reputation", "check_domain_reputation",
    "get_file_magic", "get_entropy", "extract_strings", "get_pe_imports", "get_pe_sections",
    "detect_packer", "check_digital_signature", "get_compile_timestamp", "analyze_pdf_structure",
    "deobfuscate_script", "run_sandbox", "capture_memory_dump", "monitor_filesystem",
    "get_dropped_files", "scan_pe_headers", "extract_strings_from_memory", "detect_shellcode",
    "get_memory_entropy", "analyze_injected_pe", "run_yara", "detect_anti_debug",
    "detect_anti_vm", "detect_anti_sandbox", "extract_iocs", "get_report",
]
