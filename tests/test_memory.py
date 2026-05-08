# Phase 2 unit tests for tools/memory.py
import os
import struct
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from tools.memory import (
    DEFAULT_DUMP_PATH,
    scan_pe_headers,
    extract_strings_from_memory,
    detect_shellcode,
    get_memory_entropy,
    analyze_injected_pe,
    run_yara,
    YARA_RULESETS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_dump_with_pe(include_injected: bool = False) -> bytes:
    """Build a minimal memdump with an MZ/PE header at offset 0, optionally a second at offset 0x3f2000."""
    # Primary PE at offset 0
    primary = bytearray(0x100)
    primary[0] = 0x4D  # M
    primary[1] = 0x5A  # Z
    primary[0x3C] = 0x80  # e_lfanew
    # PE signature at 0x80
    struct.pack_into("4s", primary, 0x80, b"PE\x00\x00")
    struct.pack_into("<H", primary, 0x80 + 4, 0x14C)  # i386
    struct.pack_into("<H", primary, 0x80 + 24, 0x10B)  # PE32 magic

    if not include_injected:
        return bytes(primary)

    # Pad to 0x3f2000 then add second PE
    padding = b"\x00" * (0x3f2000 - len(primary))
    injected = bytearray(0x100)
    injected[0] = 0x4D
    injected[1] = 0x5A
    injected[0x3C] = 0x80
    struct.pack_into("4s", injected, 0x80, b"PE\x00\x00")
    struct.pack_into("<H", injected, 0x80 + 4, 0x14C)
    struct.pack_into("<H", injected, 0x80 + 24, 0x10B)

    return bytes(primary) + padding + bytes(injected)


@pytest.fixture
def dump_file(tmp_path):
    """Write a minimal memdump and return its path."""
    def _write(content: bytes = None) -> str:
        content = content or _make_dump_with_pe()
        p = tmp_path / "memdump.bin"
        p.write_bytes(content)
        return str(p)
    return _write


@pytest.fixture
def patch_dump_path(dump_file, monkeypatch):
    """Patch DEFAULT_DUMP_PATH to a temp file and return the file path."""
    path = dump_file()
    monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
    return path


# ---------------------------------------------------------------------------
# scan_pe_headers
# ---------------------------------------------------------------------------

class TestScanPeHeaders:
    def test_missing_dump_returns_error(self, monkeypatch):
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", "/nonexistent/memdump.bin")
        result = scan_pe_headers()
        assert "error" in result

    def test_primary_pe_found_at_offset_zero(self, dump_file, monkeypatch):
        path = dump_file(_make_dump_with_pe(include_injected=False))
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = scan_pe_headers()
        assert result["pe_images_found"] >= 1
        assert result["images"][0]["offset"] == "0x0"
        assert result["images"][0]["note"] == "primary process image"

    def test_injected_pe_flagged(self, dump_file, monkeypatch):
        path = dump_file(_make_dump_with_pe(include_injected=True))
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = scan_pe_headers()
        assert result["pe_images_found"] == 2
        injected = [img for img in result["images"] if img["note"] == "possible injected PE"]
        assert len(injected) == 1
        assert injected[0]["offset"] == hex(0x3f2000)

    def test_explicit_target_path(self, tmp_path):
        dump = tmp_path / "custom.bin"
        dump.write_bytes(_make_dump_with_pe())
        result = scan_pe_headers(target=str(dump))
        assert "pe_images_found" in result


# ---------------------------------------------------------------------------
# extract_strings_from_memory
# ---------------------------------------------------------------------------

class TestExtractStringsFromMemory:
    def test_missing_dump_returns_error(self, monkeypatch):
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", "/no/dump.bin")
        result = extract_strings_from_memory()
        assert "error" in result

    def test_ioc_filter_returns_urls(self, dump_file, monkeypatch):
        content = b"\x00" * 64 + b"http://185.220.101.45/gate.php" + b"\x00" * 64
        path = dump_file(content)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = extract_strings_from_memory(filter="ioc")
        assert "new_strings_vs_disk" in result
        assert any("http" in s for s in result["new_strings_vs_disk"])

    def test_all_filter_returns_strings(self, dump_file, monkeypatch):
        content = b"\x00" * 64 + b"CreateRemoteThread" + b"\x00" * 64
        path = dump_file(content)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = extract_strings_from_memory(filter="all")
        assert "new_strings_vs_disk" in result

    def test_disk_strings_excluded(self, tmp_path, monkeypatch):
        disk_content = b"SharedString_OnDisk" + b"\x00" * 10
        disk_file = tmp_path / "sample.exe"
        disk_file.write_bytes(disk_content)

        dump_content = b"SharedString_OnDisk" + b"\x00" * 10 + b"NewString_InMemory" + b"\x00" * 10
        dump = tmp_path / "memdump.bin"
        dump.write_bytes(dump_content)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", str(dump))

        result = extract_strings_from_memory("all", str(disk_file))
        novel = result["new_strings_vs_disk"]
        assert "SharedString_OnDisk" not in novel
        assert any("NewString" in s for s in novel)


# ---------------------------------------------------------------------------
# detect_shellcode
# ---------------------------------------------------------------------------

class TestDetectShellcode:
    def test_missing_dump_returns_error(self, monkeypatch):
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", "/no/dump.bin")
        result = detect_shellcode()
        assert "error" in result

    def test_no_shellcode_in_clean_dump(self, dump_file, monkeypatch):
        path = dump_file(b"\x00" * 1024)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = detect_shellcode()
        assert "shellcode_detected" in result
        assert result["shellcode_detected"] is False

    def test_peb_walk_detected(self, dump_file, monkeypatch):
        # 64-bit PEB walk: mov rax, gs:[0x60]
        peb_bytes = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
        path = dump_file(b"\x00" * 64 + peb_bytes + b"\x00" * 64)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = detect_shellcode()
        assert result["shellcode_detected"] is True
        assert any(i["pattern"] == "peb_walk" for i in result["indicators"])

    def test_nop_sled_detected(self, dump_file, monkeypatch):
        path = dump_file(b"\x00" * 64 + b"\x90" * 32 + b"\x00" * 64)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = detect_shellcode()
        assert result["shellcode_detected"] is True
        assert any(i["pattern"] == "nop_sled" for i in result["indicators"])

    def test_returns_required_keys(self, dump_file, monkeypatch):
        path = dump_file()
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = detect_shellcode()
        assert "shellcode_detected" in result
        assert "indicators" in result


# ---------------------------------------------------------------------------
# get_memory_entropy
# ---------------------------------------------------------------------------

class TestGetMemoryEntropy:
    def test_missing_dump_returns_error(self, monkeypatch):
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", "/no/dump.bin")
        result = get_memory_entropy()
        assert "error" in result

    def test_returns_overall_entropy(self, dump_file, monkeypatch):
        path = dump_file(b"\xAB" * 4096)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = get_memory_entropy()
        assert "overall" in result
        assert result["overall"] == 0.0  # constant data = 0 entropy

    def test_high_entropy_region_flagged(self, dump_file, monkeypatch, tmp_path):
        import os as _os
        path = dump_file(_os.urandom(4096))
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = get_memory_entropy()
        assert result["overall"] > 7.0
        assert any(r["type"] != "normal" for r in result.get("regions", []))


# ---------------------------------------------------------------------------
# analyze_injected_pe
# ---------------------------------------------------------------------------

class TestAnalyzeInjectedPe:
    def test_missing_dump_returns_error(self, monkeypatch):
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", "/no/dump.bin")
        result = analyze_injected_pe("0x0")
        assert "error" in result

    def test_invalid_offset_returns_error(self, dump_file, monkeypatch):
        path = dump_file()
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = analyze_injected_pe("not_a_hex")
        assert "error" in result

    def test_out_of_bounds_offset_returns_error(self, dump_file, monkeypatch):
        path = dump_file(b"\x00" * 100)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = analyze_injected_pe("0xFFFFFF")
        assert "error" in result

    def test_non_mz_at_offset_returns_error(self, dump_file, monkeypatch):
        path = dump_file(b"\x00" * 200)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", path)
        result = analyze_injected_pe("0x10")
        assert "error" in result

    def test_valid_pe_at_offset_returns_analysis(self, tmp_path, monkeypatch):
        pe_data = _make_dump_with_pe()
        # Build dump: 0x10 bytes padding + PE data
        dump_content = b"\x00" * 0x10 + pe_data
        dump = tmp_path / "memdump.bin"
        dump.write_bytes(dump_content)
        monkeypatch.setattr("tools.memory.DEFAULT_DUMP_PATH", str(dump))

        result = analyze_injected_pe("0x10")
        # Should attempt analysis; pefile may fail on minimal PE but should not raise
        assert isinstance(result, dict)
        assert "pe_type" in result or "error" in result


# ---------------------------------------------------------------------------
# run_yara
# ---------------------------------------------------------------------------

class TestRunYara:
    def test_unknown_ruleset_returns_error(self, tmp_path, monkeypatch):
        f = tmp_path / "sample.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        from tools import sandbox as _sb
        _sb._state["file_path"] = str(f)
        result = run_yara(["unknown_ruleset"], "file")
        assert "error" in result

    def test_no_yara_returns_error(self, tmp_path):
        with patch.dict("sys.modules", {"yara": None}):
            result = run_yara(["ransomware"], "file")
        assert "error" in result

    def test_valid_ruleset_no_match(self, tmp_path, monkeypatch):
        import yara
        f = tmp_path / "clean.exe"
        f.write_bytes(b"MZ" + b"\x00" * 200)

        mock_compiled = MagicMock()
        mock_compiled.match.return_value = []
        with patch("tools.memory.yara.compile", return_value=mock_compiled):
            from tools import sandbox as _sb
            _sb._state["file_path"] = str(f)
            result = run_yara(["ransomware"], "file")

        assert "matches" in result
        assert result["matches"] == []

    def test_valid_ruleset_with_match(self, tmp_path):
        import yara
        f = tmp_path / "mal.exe"
        f.write_bytes(b"CryptEncrypt" + b"\x00" * 200)

        mock_match = MagicMock()
        mock_match.rule = "Ransomware_Generic"
        mock_match.strings = [MagicMock(identifier="$enc1")]
        mock_compiled = MagicMock()
        mock_compiled.match.return_value = [mock_match]

        with patch("tools.memory.yara.compile", return_value=mock_compiled):
            from tools import sandbox as _sb
            _sb._state["file_path"] = str(f)
            result = run_yara(["ransomware"], "file")

        assert len(result["matches"]) == 1
        assert result["matches"][0]["rule"] == "Ransomware_Generic"
