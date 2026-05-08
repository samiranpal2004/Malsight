# Phase 2: detect_anti_debug, detect_anti_vm, detect_anti_sandbox
# Full implementation from PRD Appendix C.2, expanded.
import struct

try:
    import pefile as _pefile
    _PEFILE_AVAILABLE = True
except ImportError:
    _PEFILE_AVAILABLE = False


ANTI_DEBUG_IMPORTS = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "FindWindowA",
    "FindWindowW",
    "BlockInput",
    "ZwQueryInformationProcess",
    "NtSetInformationThread",
]

ANTI_VM_REGISTRY_KEYS = [
    b"VMware",
    b"VirtualBox",
    b"VBOX",
    b"QEMU",
    b"Hyper-V",
    b"vmtoolsd",
    b"vboxservice",
    b"vboxtray",
    b"vmwaretray",
    b"vmwareuser",
    b"Xen",
    b"KVMKVMKVM",
]

ANTI_VM_MAC_PREFIXES = [
    b"\x00\x0c\x29",  # VMware
    b"\x00\x50\x56",  # VMware
    b"\x08\x00\x27",  # VirtualBox
    b"\x00\x15\x5d",  # Hyper-V
    b"\x52\x54\x00",  # QEMU/KVM
]

ANTI_SANDBOX_PATTERNS = [
    b"GetCursorPos",        # Mouse movement check
    b"GetSystemMetrics",    # Screen resolution / UI metric check
    b"GetTickCount",        # Timing-based evasion
    b"NtDelayExecution",    # Long sleep before payload
    b"GetForegroundWindow", # Check for foreground activity
    b"SleepEx",             # Extended sleep with alertable flag
    b"GetLastInputInfo",    # Time since last user input
    b"GetProcessHeap",      # Heap inspection (some sandboxes have unique heaps)
    b"EnumWindows",         # Window enumeration (sandbox has few windows)
]


def detect_anti_debug(file_path: str) -> dict:
    """Detect anti-debugging: import-based checks, RDTSC pattern, INT3 scanning."""
    techniques: list = []

    # PE import-based detection
    if _PEFILE_AVAILABLE:
        try:
            pe = _pefile.PE(file_path)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode("utf-8", errors="ignore")
                            if name in ANTI_DEBUG_IMPORTS:
                                techniques.append(f"{name} import detected")
            pe.close()
        except Exception:
            pass

    # Byte-level pattern scan
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": str(e)}

    # RDTSC timing check (opcode 0F 31)
    if b"\x0f\x31" in data:
        techniques.append("RDTSC timing check pattern (0F 31)")

    # INT 3 breakpoint scanning — more than 10 occurrences is suspicious
    if data.count(b"\xcc") > 10:
        techniques.append("Excessive INT3 breakpoints — possible debugger scanning")

    # NtQueryInformationProcess ProcessDebugPort pattern (common sequence)
    if b"\x07\x00\x00\x00" in data and b"NtQueryInformationProcess" in data:
        techniques.append("NtQueryInformationProcess(ProcessDebugPort) pattern")

    return {
        "anti_debug_detected": len(techniques) > 0,
        "techniques": techniques,
    }


def detect_anti_vm(file_path: str) -> dict:
    """Detect VM detection: registry key references, MAC prefixes, CPUID instruction."""
    techniques: list = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": str(e)}

    # Registry key string references
    for key in ANTI_VM_REGISTRY_KEYS:
        if key in data:
            techniques.append(
                f"VM registry key reference: {key.decode('utf-8', errors='replace')}"
            )

    # VM vendor MAC address prefixes embedded as bytes
    for prefix in ANTI_VM_MAC_PREFIXES:
        if prefix in data:
            techniques.append(f"VM MAC prefix detected: {prefix.hex()}")

    # CPUID instruction (0F A2) — hypervisor bit check
    if b"\x0f\xa2" in data:
        techniques.append("CPUID instruction — possible hypervisor detection (ECX bit 31)")

    # VM process name strings
    vm_proc_names = [b"vmtoolsd.exe", b"vboxservice.exe", b"vboxtray.exe",
                     b"vmwaretray.exe", b"qemu-ga.exe"]
    for proc in vm_proc_names:
        if proc.lower() in data.lower():
            techniques.append(f"VM process name check: {proc.decode('utf-8', errors='ignore')}")

    return {
        "anti_vm_detected": len(techniques) > 0,
        "techniques": techniques,
    }


def detect_anti_sandbox(file_path: str) -> dict:
    """Detect sandbox evasion: sleep patterns, mouse/UI checks, environment probing."""
    techniques: list = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": str(e)}

    # API pattern scan
    for pattern in ANTI_SANDBOX_PATTERNS:
        if pattern in data:
            techniques.append(f"{pattern.decode('utf-8', errors='ignore')} call detected")

    # Very long sleep values (NtDelayExecution uses 100 ns intervals; 600 000 000 = 60 s)
    offset = 0
    while True:
        idx = data.find(b"\x00\x00\x00\x00", offset)
        if idx == -1:
            break
        try:
            if idx + 8 <= len(data):
                val = struct.unpack_from("<Q", data, idx)[0]
                if val > 600_000_000:   # > 60 seconds in 100 ns units
                    techniques.append(
                        f"Possible long-sleep value {val} at offset {hex(idx)} "
                        f"(~{val // 10_000_000}s)"
                    )
                    break
        except struct.error:
            pass
        offset = idx + 4

    # GetSystemInfo / GetProcessorCount — low CPU count = sandbox heuristic
    if b"GetSystemInfo" in data or b"GetNativeSystemInfo" in data:
        techniques.append("GetSystemInfo() — may check processor count (< 2 = sandbox)")

    return {
        "anti_sandbox_detected": len(techniques) > 0,
        "techniques": techniques,
    }
