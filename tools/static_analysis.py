# Phase 2: get_file_magic, get_entropy, extract_strings, get_pe_imports, get_pe_sections,
#          detect_packer, check_digital_signature, get_compile_timestamp,
#          analyze_pdf_structure, deobfuscate_script
import base64
import math
import os
import re
import struct
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


PACKER_SIGNATURES = {
    "UPX":       [b"UPX0", b"UPX1", b"UPX!"],
    "MPRESS":    [b".MPRESS1", b".MPRESS2"],
    "ASPack":    [b".aspack", b".adata"],
    "Themida":   [b".themida"],
    "VMProtect": [b".vmp0", b".vmp1"],
    "Enigma":    [b".enigma1", b".enigma2"],
}

UPX_DECOMPRESSION_TIME_MS = {
    "small":  300,   # < 100 KB
    "medium": 800,   # 100 KB – 1 MB
    "large":  2000,  # > 1 MB
}

SUSPICIOUS_IMPORT_NAMES = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "WinHttpOpen",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "LoadLibraryA", "LoadLibraryW",
    "GetProcAddress", "SetWindowsHookEx", "OpenProcess", "ReadProcessMemory",
    "VirtualProtect", "VirtualProtectEx", "WinHttpConnect", "WinHttpSendRequest",
    "InternetOpen", "InternetOpenUrl", "URLDownloadToFile", "ShellExecuteA",
    "ShellExecuteW", "ShellExecuteExA", "CreateProcessA", "CreateProcessW",
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "CryptEncrypt", "CryptDecrypt", "NtCreateSection", "MapViewOfSection",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
}

INJECTION_APIS = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                  "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetWindowsHookEx"}
NETWORK_APIS = {"WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
                "InternetOpen", "InternetOpenUrl", "URLDownloadToFile"}

# Byte patterns for suspicious strings (operate on raw bytes)
_SUSPICIOUS_BYTE_PATTERNS = [
    re.compile(rb"https?://[\x21-\x7e]{4,}", re.I),
    re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}"),
    re.compile(rb"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)[\\\x00][^\x00\r\n]{2,}"),
    re.compile(rb"cmd(?:\.exe)?\s+/[a-zA-Z]", re.I),
    re.compile(rb"powershell(?:\.exe)?", re.I),
    re.compile(rb"(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|WinHttpOpen|"
               rb"URLDownloadToFile|ShellExecute|CreateProcess|RegSetValue)", re.I),
    re.compile(rb"[C-Zc-z]:\\(?:[^\x00\r\n\\:*?\"<>|]{1,255}\\){1,8}[^\x00\r\n]{0,64}"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _zip_note(file_path: str) -> str | None:
    """Return a standard note when the target is a zip; None otherwise."""
    try:
        import zipfile
        if zipfile.is_zipfile(file_path):
            return "zip file — contents analyzed inside sandbox only"
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------

def get_file_magic(file_path: str) -> dict:
    """Detect true file type using libmagic, independent of file extension."""
    try:
        import magic
        magic_type = magic.from_file(file_path)
        mime = magic.from_file(file_path, mime=True)
        result = {"magic_type": magic_type, "mime": mime}
        note = _zip_note(file_path)
        if note:
            result["note"] = note
        return result
    except Exception as e:
        return {"error": str(e)}


def get_entropy(file_path: str, region: str = None) -> dict:
    """Return Shannon entropy for the whole file, or a specific PE section if region is given."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        overall = round(_shannon_entropy(data), 2)
        result: dict = {"overall_entropy": overall}

        sections: dict = {}
        try:
            import pefile
            pe = pefile.PE(file_path)
            for sec in pe.sections:
                name = sec.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                sections[name] = round(_shannon_entropy(sec.get_data()), 2)
            pe.close()
        except Exception:
            pass

        if sections:
            result["sections"] = sections
        if region and region in sections:
            result["region_entropy"] = sections[region]
        note = _zip_note(file_path)
        if note:
            result["note"] = note
        return result
    except Exception as e:
        return {"error": str(e)}


def extract_strings(file_path: str, min_length: int = 6, encoding: str = None) -> dict:
    """Extract ASCII + UTF-16LE strings; return total count + suspicious subset."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # ASCII strings
        pattern_ascii = re.compile(b"[\x20-\x7e]{" + str(min_length).encode() + b",}")
        ascii_strs = [s.decode("ascii", errors="ignore") for s in pattern_ascii.findall(data)]

        # UTF-16LE strings
        pattern_utf16 = re.compile(b"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + b",}")
        utf16_strs = [s.decode("utf-16-le", errors="ignore") for s in pattern_utf16.findall(data)]

        all_strings = list(dict.fromkeys(ascii_strs + utf16_strs))  # dedup, preserve order

        # Suspicious subset via byte-level pattern matching
        suspicious: list = []
        seen: set = set()
        for pat in _SUSPICIOUS_BYTE_PATTERNS:
            for m in pat.findall(data):
                decoded = m.decode("utf-8", errors="ignore").strip()
                if decoded and decoded not in seen:
                    suspicious.append(decoded)
                    seen.add(decoded)

        result = {
            "total_strings": len(all_strings),
            "suspicious": suspicious[:100],
        }
        note = _zip_note(file_path)
        if note:
            result["note"] = note
        return result
    except Exception as e:
        return {"error": str(e)}


def get_pe_imports(file_path: str) -> dict:
    """Parse PE import table; flag injection and network APIs."""
    try:
        import pefile
        pe = pefile.PE(file_path)
        dlls: list = []
        suspicious: list = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                dlls.append(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("utf-8", errors="ignore")
                        if name in SUSPICIOUS_IMPORT_NAMES and name not in suspicious:
                            suspicious.append(name)
        pe.close()
        injection_present = any(api in suspicious for api in INJECTION_APIS)
        network_present = any(api in suspicious for api in NETWORK_APIS)
        return {
            "dlls": dlls,
            "suspicious_imports": suspicious,
            "injection_apis_present": injection_present,
            "network_apis_present": network_present,
        }
    except Exception as e:
        return {"error": str(e)}


def get_pe_sections(file_path: str) -> list:
    """Return PE section headers with name, entropy, virtual/raw size, and flags."""
    try:
        import pefile
        pe = pefile.PE(file_path)
        sections = []
        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            entropy = round(_shannon_entropy(sec.get_data()), 2)
            flags = []
            if sec.Characteristics & 0x20000000:
                flags.append("executable")
            if sec.Characteristics & 0x40000000:
                flags.append("readable")
            if sec.Characteristics & 0x80000000:
                flags.append("writable")
            sections.append({
                "name": name,
                "entropy": entropy,
                "flags": flags,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
            })
        pe.close()
        return sections
    except Exception as e:
        return {"error": str(e)}


def detect_packer(file_path: str) -> dict:
    """Identify packer/protector via signature database; estimate UPX decompression timing."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": str(e)}

    file_size = len(data)
    size_bucket = (
        "small"  if file_size < 100_000 else
        "medium" if file_size < 1_000_000 else
        "large"
    )

    # Byte-pattern scan
    for packer_name, sigs in PACKER_SIGNATURES.items():
        for sig in sigs:
            if sig in data:
                version = "unknown"
                if packer_name == "UPX":
                    # Attempt to extract UPX version string near the UPX! marker
                    idx = data.find(b"UPX!")
                    if idx != -1:
                        chunk = data[max(0, idx - 64): idx + 64]
                        m = re.search(rb"\d+\.\d+", chunk)
                        if m:
                            version = m.group().decode("ascii", errors="ignore")
                decompression_ms = (
                    UPX_DECOMPRESSION_TIME_MS.get(size_bucket, 1000)
                    if packer_name == "UPX"
                    else 1000
                )
                return {
                    "packer_detected": True,
                    "packer_name": packer_name,
                    "version": version,
                    "decompression_time_estimate_ms": decompression_ms,
                }

    # Fallback: PE section name scan
    try:
        import pefile
        pe = pefile.PE(file_path)
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00").lower()
            for packer_name, sigs in PACKER_SIGNATURES.items():
                if any(sig.decode("utf-8", errors="ignore").lower().strip(".") in name
                       for sig in sigs):
                    pe.close()
                    return {
                        "packer_detected": True,
                        "packer_name": packer_name,
                        "version": "unknown",
                        "decompression_time_estimate_ms": 1000,
                    }
        pe.close()
    except Exception:
        pass

    return {"packer_detected": False, "packer_name": None, "version": None,
            "decompression_time_estimate_ms": 0}


def check_digital_signature(file_path: str) -> dict:
    """Verify PE Authenticode signature using signify (with pefile fallback)."""
    try:
        import pefile
        pe = pefile.PE(file_path)
        has_security_dir = (
            hasattr(pe, "OPTIONAL_HEADER")
            and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY")
            and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4
            and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0
        )
        pe.close()

        if not has_security_dir:
            return {
                "signed": False,
                "valid": False,
                "signer": None,
                "reason": "No digital signature present",
                "cert_expired": False,
            }
    except Exception:
        has_security_dir = False

    if not has_security_dir:
        return {
            "signed": False,
            "valid": False,
            "signer": None,
            "reason": "No digital signature present",
            "cert_expired": False,
        }

    # Try signify for full Authenticode validation
    try:
        from signify.authenticode import SignedPEFile
        with open(file_path, "rb") as f:
            signed_pe = SignedPEFile(f)
        valid = False
        reason = "Unknown validation error"
        signer = None
        cert_expired = False
        try:
            signed_pe.verify()
            valid = True
            reason = "Valid Authenticode signature"
        except Exception as ve:
            reason = str(ve)
        try:
            for sig in signed_pe.signed_datas:
                certs = list(sig.certificates)
                if certs:
                    signer = str(certs[0].subject.get("commonName", certs[0].subject))
                    for cert in certs:
                        if hasattr(cert, "not_after") and cert.not_after < datetime.utcnow():
                            cert_expired = True
        except Exception:
            pass
        return {
            "signed": True,
            "valid": valid,
            "signer": signer,
            "reason": reason,
            "cert_expired": cert_expired,
        }
    except ImportError:
        return {
            "signed": True,
            "valid": None,
            "signer": None,
            "reason": "Signature present; install signify for full Authenticode validation",
            "cert_expired": None,
        }
    except Exception as e:
        return {"error": str(e)}


def get_compile_timestamp(file_path: str) -> dict:
    """Extract PE compilation timestamp and flag if zeroed or suspiciously round."""
    try:
        import pefile
        pe = pefile.PE(file_path)
        ts = pe.FILE_HEADER.TimeDateStamp
        pe.close()

        if ts == 0:
            return {
                "timestamp": "1970-01-01T00:00:00Z",
                "suspicious": True,
                "reason": "Timestamp is zeroed — likely intentionally wiped",
            }

        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        timestamp_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        suspicious = False
        reason = None

        if dt > datetime.now(tz=timezone.utc):
            suspicious = True
            reason = "Timestamp is in the future"
        elif dt.hour == 0 and dt.minute == 0 and dt.second == 0:
            suspicious = True
            reason = "Timestamp is exactly midnight — likely zeroed or faked"
        elif ts % 86400 == 0:
            suspicious = True
            reason = "Timestamp rounded to exact day — possibly forged"
        elif dt.year < 2000:
            suspicious = True
            reason = "Timestamp predates PE format — likely forged"

        return {"timestamp": timestamp_str, "suspicious": suspicious, "reason": reason}
    except Exception as e:
        return {"error": str(e)}


def analyze_pdf_structure(file_path: str) -> dict:
    """Deep structural analysis of PDF: JavaScript, embedded files, suspicious actions, filters."""
    result = {
        "has_javascript": False,
        "embedded_files": 0,
        "suspicious_actions": [],
        "stream_filters": [],
        "obfuscated_js": False,
    }
    try:
        import pikepdf

        SUSPICIOUS_KEYS = {"/JavaScript", "/JS", "/OpenAction", "/Launch",
                           "/URI", "/SubmitForm", "/ImportData", "/AA"}
        FILTER_KEYS = {"/Filter", "/FFilter"}

        def _walk(obj, depth: int = 0) -> None:
            if depth > 15:
                return
            try:
                if isinstance(obj, pikepdf.Dictionary):
                    for k, v in obj.items():
                        ks = str(k)
                        if ks in {"/JS", "/JavaScript"}:
                            result["has_javascript"] = True
                        if ks in SUSPICIOUS_KEYS and ks not in result["suspicious_actions"]:
                            result["suspicious_actions"].append(ks)
                        if ks in FILTER_KEYS:
                            if isinstance(v, pikepdf.Array):
                                for fv in v:
                                    fstr = str(fv)
                                    if fstr not in result["stream_filters"]:
                                        result["stream_filters"].append(fstr)
                            else:
                                fstr = str(v)
                                if fstr not in result["stream_filters"]:
                                    result["stream_filters"].append(fstr)
                        _walk(v, depth + 1)
                elif isinstance(obj, pikepdf.Array):
                    for item in obj:
                        _walk(item, depth + 1)
            except Exception:
                pass

        pdf = pikepdf.open(file_path)
        _walk(pdf.Root)
        for page in pdf.pages:
            _walk(page)

        # Count embedded files via /EmbeddedFiles name tree
        try:
            names = pdf.Root.get("/Names")
            if names and "/EmbeddedFiles" in names:
                ef = names["/EmbeddedFiles"]
                if isinstance(ef, pikepdf.Dictionary) and "/Names" in ef:
                    arr = ef["/Names"]
                    result["embedded_files"] = len(arr) // 2
        except Exception:
            pass

        # Obfuscated JS heuristic: JS present + multiple stream encode layers
        if result["has_javascript"] and len(result["stream_filters"]) > 1:
            result["obfuscated_js"] = True

    except ImportError:
        result["error"] = "pikepdf not installed"
    except Exception as e:
        result["error"] = str(e)

    return result


def deobfuscate_script(file_path: str) -> dict:
    """Detect and partially decode base64, hex, string-concat, eval chains in scripts."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        techniques: list = []
        deobfuscated = content

        # Base64 decoding
        b64_pat = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
        for m in b64_pat.findall(content):
            try:
                decoded = base64.b64decode(m + "==").decode("utf-8", errors="ignore")
                if len(decoded) > 10 and decoded.isprintable():
                    if "base64_encoding" not in techniques:
                        techniques.append("base64_encoding")
                    deobfuscated = deobfuscated.replace(m, f"/*B64:{decoded[:120]}*/", 1)
            except Exception:
                pass

        # Hex-encoded byte arrays  e.g.  \x41\x42  or  0x41, 0x42
        if re.search(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?:0x[0-9a-fA-F]{2},\s*){6,}", content):
            techniques.append("hex_encoding")

        # String concatenation obfuscation
        if re.search(r'["\'][^"\']{1,40}["\'][\s]*\+[\s]*["\'][^"\']{1,40}["\']', content):
            techniques.append("string_concatenation")

        # eval / exec chains
        if re.search(r"\beval\s*\(|\bexec\s*\(", content, re.I):
            techniques.append("eval_exec")

        # PowerShell encoded command
        if re.search(r"-enc(?:odedCommand)?\s+[A-Za-z0-9+/=]{20,}", content, re.I):
            techniques.append("powershell_encoded_command")
            # Decode the payload
            m = re.search(r"-enc(?:odedCommand)?\s+([A-Za-z0-9+/=]{20,})", content, re.I)
            if m:
                try:
                    decoded = base64.b64decode(m.group(1)).decode("utf-16-le", errors="ignore")
                    deobfuscated = deobfuscated.replace(m.group(0), f"/*PS_ENC:{decoded[:120]}*/", 1)
                except Exception:
                    pass

        snippet = deobfuscated[:600] if len(deobfuscated) > 600 else deobfuscated
        return {
            "obfuscation_detected": len(techniques) > 0,
            "techniques": techniques,
            "deobfuscated_snippet": snippet,
        }
    except Exception as e:
        return {"error": str(e)}
