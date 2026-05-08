# Phase 2: scan_pe_headers, extract_strings_from_memory, detect_shellcode,
#          get_memory_entropy, analyze_injected_pe, run_yara
import math
import os
import re
import struct
import tempfile

DEFAULT_DUMP_PATH = "/tmp/results/memdump.bin"

# ---------------------------------------------------------------------------
# Embedded YARA rule library
# ---------------------------------------------------------------------------

YARA_RULESETS: dict[str, str] = {
    "ransomware": r"""
rule Ransomware_Generic {
    meta: description = "Generic ransomware indicators"
    strings:
        $enc1  = "CryptEncrypt" ascii
        $enc2  = "CryptGenKey" ascii
        $r1    = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $r2    = "RECOVER_FILES" ascii wide nocase
        $r3    = "DECRYPT_INSTRUCTIONS" ascii wide nocase
        $shadow = "vssadmin Delete Shadows" ascii wide nocase
        $ext1  = ".locked" ascii
        $ext2  = ".encrypted" ascii
    condition:
        2 of ($enc*) or 1 of ($r*) or $shadow or 1 of ($ext*)
}
""",
    "banker": r"""
rule Banker_Generic {
    meta: description = "Banking trojan indicators"
    strings:
        $hook   = "SetWindowsHookEx" ascii
        $inj1   = "CreateRemoteThread" ascii
        $inj2   = "WriteProcessMemory" ascii
        $br1    = "Chrome" ascii wide nocase
        $br2    = "Firefox" ascii wide nocase
        $br3    = "Login Data" ascii
        $fg     = "VirtualAllocEx" ascii
    condition:
        ($hook or 2 of ($inj*, $fg)) and 1 of ($br*)
}
""",
    "rat": r"""
rule RAT_Generic {
    meta: description = "Remote access trojan indicators"
    strings:
        $c2a   = "socket" ascii
        $c2b   = "recv" ascii
        $c2c   = "send" ascii
        $key   = "GetAsyncKeyState" ascii
        $screen = "BitBlt" ascii
        $shell  = "cmd.exe" ascii wide
        $shell2 = "powershell" ascii wide nocase
    condition:
        (3 of ($c2*)) or ($key and ($shell or $shell2)) or ($screen and ($shell or $shell2))
}
""",
    "coinminer": r"""
rule CoinMiner_Generic {
    meta: description = "Cryptocurrency miner indicators"
    strings:
        $pool1  = "stratum+tcp://" ascii
        $pool2  = "stratum+ssl://" ascii
        $algo1  = "cryptonight" ascii wide nocase
        $algo2  = "monero" ascii wide nocase
        $algo3  = "xmrig" ascii wide nocase
        $cpu    = "cpuminer" ascii wide nocase
    condition:
        1 of ($pool*) or 2 of ($algo*, $cpu)
}
""",
    "webshell": r"""
rule Webshell_Generic {
    meta: description = "Web shell indicators"
    strings:
        $php    = "<?php" ascii
        $exec1  = "eval(" ascii
        $exec2  = "exec(" ascii
        $exec3  = "system(" ascii
        $exec4  = "passthru(" ascii
        $exec5  = "shell_exec(" ascii
        $b64    = "base64_decode(" ascii
        $cmd    = "$_REQUEST" ascii
        $cmd2   = "$_POST" ascii
    condition:
        $php and (2 of ($exec*) or ($b64 and 1 of ($exec*)) or ($cmd and 1 of ($exec*)))
}
""",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _read_dump(dump_path: str | None = None) -> bytes | None:
    path = dump_path or DEFAULT_DUMP_PATH
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------

def scan_pe_headers(target: str = "memdump") -> dict:
    """Scan memory dump for MZ+PE signatures; flag any PE beyond offset 0 as injected."""
    dump_path = None if target == "memdump" else target
    data = _read_dump(dump_path)
    if data is None:
        return {"error": f"memory dump not found at {dump_path or DEFAULT_DUMP_PATH}"}

    images: list = []
    offset = 0
    while True:
        idx = data.find(b"MZ", offset)
        if idx == -1:
            break
        # Validate: read e_lfanew at offset+0x3c and check PE signature
        if idx + 0x40 <= len(data):
            e_lfanew_raw = data[idx + 0x3c: idx + 0x40]
            if len(e_lfanew_raw) == 4:
                e_lfanew = struct.unpack_from("<I", e_lfanew_raw)[0]
                pe_sig_offset = idx + e_lfanew
                if pe_sig_offset + 6 <= len(data):
                    if data[pe_sig_offset: pe_sig_offset + 4] == b"PE\x00\x00":
                        # Determine PE type from Optional Header magic
                        pe_type = "PE32"
                        machine_offset = pe_sig_offset + 4
                        opt_magic_offset = pe_sig_offset + 24
                        if opt_magic_offset + 2 <= len(data):
                            magic = struct.unpack_from("<H", data, opt_magic_offset)[0]
                            if magic == 0x20B:
                                pe_type = "PE32+"
                        note = (
                            "primary process image" if idx == 0
                            else "possible injected PE"
                        )
                        images.append({
                            "offset": hex(idx),
                            "pe_type": pe_type,
                            "note": note,
                        })
        offset = idx + 2

    return {"pe_images_found": len(images), "images": images}


def extract_strings_from_memory(filter: str = "all", disk_file_path: str = None) -> dict:
    """Extract strings from memory dump; return only strings absent from the on-disk binary."""
    data = _read_dump()
    if data is None:
        return {"error": f"memory dump not found at {DEFAULT_DUMP_PATH}"}

    # Build set of strings already present on disk to find novel (runtime-decrypted) strings
    disk_strings: set = set()
    if disk_file_path and os.path.exists(disk_file_path):
        try:
            with open(disk_file_path, "rb") as f:
                disk_data = f.read()
            pat = re.compile(b"[\x20-\x7e]{6,}")
            disk_strings = {s.decode("ascii", errors="ignore") for s in pat.findall(disk_data)}
        except Exception:
            pass

    # Extract ASCII + UTF-16LE strings from dump
    ascii_pat = re.compile(b"[\x20-\x7e]{6,}")
    utf16_pat = re.compile(b"(?:[\x20-\x7e]\x00){6,}")
    raw_strings = [s.decode("ascii", errors="ignore") for s in ascii_pat.findall(data)]
    raw_strings += [s.decode("utf-16-le", errors="ignore") for s in utf16_pat.findall(data)]
    all_strings = list(dict.fromkeys(raw_strings))  # dedup

    # Novel strings only (not on disk)
    novel = [s for s in all_strings if s not in disk_strings]

    # Apply filter
    ioc_pat = re.compile(
        r"https?://\S+|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-z]{2,}"
    )
    reg_pat = re.compile(r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\")
    api_pat = re.compile(
        r"(?:VirtualAlloc|WriteProcess|CreateRemote|WinHttp|CryptEncrypt|"
        r"CreateProcess|ShellExecute|LoadLibrary|GetProcAddress|RegSetValue)"
    )

    if filter == "ioc":
        filtered = [s for s in novel if ioc_pat.search(s)]
    elif filter == "registry":
        filtered = [s for s in novel if reg_pat.search(s)]
    elif filter == "api":
        filtered = [s for s in novel if api_pat.search(s)]
    else:
        filtered = novel

    return {"new_strings_vs_disk": filtered[:200]}


def detect_shellcode() -> dict:
    """Scan memory dump for PEB-walk patterns, ROR-13 loops, indirect call-register, NOP sleds."""
    data = _read_dump()
    if data is None:
        return {"error": f"memory dump not found at {DEFAULT_DUMP_PATH}"}

    indicators: list = []

    # PEB walk: typical sequence — mov eax, fs:[0x30] or gs:[0x60] (64-bit)
    # 64-bit: 65 48 8B 04 25 60 00 00 00 (mov rax, gs:[0x60])
    if b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" in data:
        idx = data.index(b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00")
        indicators.append({"pattern": "peb_walk", "offset": hex(idx)})
    # 32-bit: 64 8B 40 30
    elif b"\x64\x8b\x40\x30" in data:
        idx = data.index(b"\x64\x8b\x40\x30")
        indicators.append({"pattern": "peb_walk", "offset": hex(idx)})

    # ROR-13 API hash loop: ROR instruction 0xC1 0xC8 0x0D or 0xD1 0xC8 variants
    ror13_patterns = [b"\xc1\xc8\x0d", b"\xd1\xc8"]
    for pat in ror13_patterns:
        if pat in data:
            idx = data.index(pat)
            indicators.append({"pattern": "ror13_api_hash_loop", "offset": hex(idx)})
            break

    # Indirect call-register: call eax (FF D0), call ecx (FF D1), call edx (FF D2)
    for opcode, reg in [(b"\xff\xd0", "eax"), (b"\xff\xd1", "ecx"), (b"\xff\xd2", "edx")]:
        if opcode in data:
            idx = data.index(opcode)
            indicators.append({
                "pattern": "indirect_call_register",
                "offset": hex(idx),
                "register": reg,
            })
            break

    # NOP sled: 16+ consecutive 0x90 bytes
    nop_pat = re.compile(b"\x90{16,}")
    m = nop_pat.search(data)
    if m:
        indicators.append({"pattern": "nop_sled", "offset": hex(m.start()), "length": len(m.group())})

    return {
        "shellcode_detected": len(indicators) > 0,
        "indicators": indicators,
    }


def get_memory_entropy(region: str = None) -> dict:
    """Compute entropy per 4 KB chunk of the memory dump; flag executable-like regions > 7.0."""
    data = _read_dump()
    if data is None:
        return {"error": f"memory dump not found at {DEFAULT_DUMP_PATH}"}

    chunk_size = 0x1000  # 4 KB
    overall = round(_shannon_entropy(data), 2)
    regions: list = []

    for start in range(0, len(data), chunk_size):
        chunk = data[start: start + chunk_size]
        entropy = round(_shannon_entropy(chunk), 2)
        region_type = "unknown — high entropy in executable region" if entropy > 7.0 else "normal"
        regions.append({
            "range": f"{hex(start)}–{hex(start + len(chunk))}",
            "entropy": entropy,
            "type": region_type,
        })

    # If caller requested a specific range (e.g. "0x3f2000-0x3f3000"), filter
    filtered = regions
    if region:
        m = re.match(r"(0x[0-9a-fA-F]+)[-–](0x[0-9a-fA-F]+)", region)
        if m:
            rstart = int(m.group(1), 16)
            rend = int(m.group(2), 16)
            filtered = [
                r for r in regions
                if int(r["range"].split("–")[0], 16) >= rstart
                and int(r["range"].split("–")[0], 16) < rend
            ]

    high_entropy = [r for r in filtered if r["entropy"] > 7.0]

    return {
        "overall": overall,
        "regions": filtered[:50],
        "high_entropy_regions": high_entropy,
    }


def analyze_injected_pe(offset: str) -> dict:
    """Extract PE at hex offset from memory dump and run full static analysis."""
    data = _read_dump()
    if data is None:
        return {"error": f"memory dump not found at {DEFAULT_DUMP_PATH}"}

    try:
        byte_offset = int(offset, 16)
    except ValueError:
        return {"error": f"Invalid hex offset: {offset}"}

    if byte_offset >= len(data):
        return {"error": f"Offset {offset} is beyond dump size ({hex(len(data))})"}

    pe_data = data[byte_offset:]
    if pe_data[:2] != b"MZ":
        return {"error": f"No MZ signature at offset {offset}"}

    # Write extracted PE to a temp file for pefile analysis
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(pe_data)
        tmp_path = tmp.name

    result: dict = {"pe_type": "unknown", "imports": [], "sections": [], "strings": [], "packer": "none"}
    try:
        import pefile

        pe = pefile.PE(tmp_path)

        # Determine PE type
        if hasattr(pe, "OPTIONAL_HEADER"):
            result["pe_type"] = "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32"

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            from .static_analysis import SUSPICIOUS_IMPORT_NAMES
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("utf-8", errors="ignore")
                        if name in SUSPICIOUS_IMPORT_NAMES and name not in result["imports"]:
                            result["imports"].append(name)

        # Sections
        for sec in pe.sections:
            from .static_analysis import _shannon_entropy as _se
            name = sec.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            entropy = round(_se(sec.get_data()), 2)
            result["sections"].append({"name": name, "entropy": entropy})

        pe.close()

        # Strings
        str_pat = re.compile(b"[\x20-\x7e]{6,}")
        all_s = [s.decode("ascii", errors="ignore") for s in str_pat.findall(pe_data[:2_000_000])]
        suspicious_kw = re.compile(
            r"https?://|HKEY_|cmd\.exe|powershell|VirtualAlloc|CreateRemote|WinHttp"
        )
        result["strings"] = [s for s in all_s if suspicious_kw.search(s)][:50]

        # Packer check
        from .static_analysis import detect_packer as _dp
        packer_result = _dp(tmp_path)
        result["packer"] = (
            f"{packer_result['packer_name']} (v{packer_result.get('version', '?')})"
            if packer_result.get("packer_detected")
            else "none — plaintext payload"
        )
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return result


def run_yara(rules: list, target: str = "file") -> dict:
    """Run named YARA rulesets against file or memory dump; return matching rules and strings."""
    try:
        import yara
    except ImportError:
        return {"error": "yara-python not installed (pip install yara-python)"}

    # Resolve target path
    if target == "memdump":
        scan_path = DEFAULT_DUMP_PATH
    elif target == "file":
        # Use sandbox state for current file path
        from .sandbox import _state as _sb_state
        scan_path = _sb_state.get("file_path", "")
    else:
        scan_path = target

    if not scan_path or not os.path.exists(scan_path):
        return {"error": f"target file not found: {scan_path}"}

    # Compile requested rulesets
    unknown_rules = [r for r in rules if r not in YARA_RULESETS]
    if unknown_rules:
        return {"error": f"Unknown rulesets: {unknown_rules}. Valid: {list(YARA_RULESETS)}"}

    combined_source = "\n".join(YARA_RULESETS[r] for r in rules)
    try:
        compiled = yara.compile(source=combined_source)
    except yara.SyntaxError as e:
        return {"error": f"YARA compile error: {e}"}

    try:
        yara_matches = compiled.match(scan_path)
    except Exception as e:
        return {"error": f"YARA match error: {e}"}

    matches: list = []
    for m in yara_matches:
        # Determine which ruleset this match came from
        ruleset = next(
            (r for r in rules if m.rule in YARA_RULESETS[r]),
            rules[0] if rules else "unknown",
        )
        matched_strings = [s.identifier for s in m.strings] if hasattr(m, "strings") else []
        matches.append({
            "rule": m.rule,
            "ruleset": ruleset,
            "matched_strings": matched_strings,
        })

    return {"matches": matches}
