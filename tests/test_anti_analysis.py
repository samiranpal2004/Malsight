# Phase 2 unit tests for tools/anti_analysis.py
import struct
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from tools.anti_analysis import (
    detect_anti_debug,
    detect_anti_vm,
    detect_anti_sandbox,
    ANTI_DEBUG_IMPORTS,
    ANTI_VM_REGISTRY_KEYS,
    ANTI_SANDBOX_PATTERNS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_file(tmp_path):
    def _write(content: bytes, suffix: str = ".exe") -> str:
        p = tmp_path / f"sample{suffix}"
        p.write_bytes(content)
        return str(p)
    return _write


@pytest.fixture
def clean_file(tmp_file):
    return tmp_file(b"\x00" * 512)


# ---------------------------------------------------------------------------
# detect_anti_debug
# ---------------------------------------------------------------------------

class TestDetectAntiDebug:
    def test_clean_binary_returns_no_techniques(self, clean_file):
        result = detect_anti_debug(clean_file)
        assert result["anti_debug_detected"] is False
        assert result["techniques"] == []

    def test_rdtsc_pattern_detected(self, tmp_file):
        # 0F 31 is RDTSC
        path = tmp_file(b"\x00" * 32 + b"\x0f\x31" + b"\x00" * 32)
        result = detect_anti_debug(path)
        assert result["anti_debug_detected"] is True
        assert any("RDTSC" in t for t in result["techniques"])

    def test_excessive_int3_detected(self, tmp_file):
        path = tmp_file(b"\xcc" * 15 + b"\x00" * 20)
        result = detect_anti_debug(path)
        assert result["anti_debug_detected"] is True
        assert any("INT3" in t for t in result["techniques"])

    def test_anti_debug_import_detected(self, tmp_file):
        mock_pe = MagicMock()
        mock_entry = MagicMock()
        mock_entry.dll = b"kernel32.dll"
        mock_func = MagicMock()
        mock_func.name = b"IsDebuggerPresent"
        mock_entry.imports = [mock_func]
        mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_entry]

        with patch("tools.anti_analysis._pefile.PE", return_value=mock_pe), \
             patch("tools.anti_analysis._PEFILE_AVAILABLE", True):
            path = tmp_file(b"\x00" * 64)
            result = detect_anti_debug(path)

        assert any("IsDebuggerPresent" in t for t in result["techniques"])

    def test_missing_file_returns_error(self, tmp_path):
        result = detect_anti_debug(str(tmp_path / "ghost.exe"))
        assert "error" in result

    def test_returns_required_keys(self, clean_file):
        result = detect_anti_debug(clean_file)
        assert "anti_debug_detected" in result
        assert "techniques" in result
        assert isinstance(result["techniques"], list)


# ---------------------------------------------------------------------------
# detect_anti_vm
# ---------------------------------------------------------------------------

class TestDetectAntiVm:
    def test_clean_binary_no_techniques(self, clean_file):
        result = detect_anti_vm(clean_file)
        assert result["anti_vm_detected"] is False
        assert result["techniques"] == []

    def test_vmware_string_detected(self, tmp_file):
        path = tmp_file(b"\x00" * 16 + b"VMware" + b"\x00" * 16)
        result = detect_anti_vm(path)
        assert result["anti_vm_detected"] is True
        assert any("VMware" in t for t in result["techniques"])

    def test_virtualbox_registry_detected(self, tmp_file):
        path = tmp_file(b"\x00" * 16 + b"VirtualBox" + b"\x00" * 16)
        result = detect_anti_vm(path)
        assert result["anti_vm_detected"] is True

    def test_cpuid_instruction_detected(self, tmp_file):
        # 0F A2 = CPUID
        path = tmp_file(b"\x00" * 16 + b"\x0f\xa2" + b"\x00" * 16)
        result = detect_anti_vm(path)
        assert result["anti_vm_detected"] is True
        assert any("CPUID" in t for t in result["techniques"])

    def test_vm_mac_prefix_detected(self, tmp_file):
        # VMware MAC prefix: 00 0C 29
        path = tmp_file(b"\x00" * 16 + b"\x00\x0c\x29" + b"\x00" * 16)
        result = detect_anti_vm(path)
        assert result["anti_vm_detected"] is True

    def test_missing_file_returns_error(self, tmp_path):
        result = detect_anti_vm(str(tmp_path / "ghost.exe"))
        assert "error" in result

    def test_returns_required_keys(self, clean_file):
        result = detect_anti_vm(clean_file)
        assert "anti_vm_detected" in result
        assert "techniques" in result


# ---------------------------------------------------------------------------
# detect_anti_sandbox
# ---------------------------------------------------------------------------

class TestDetectAntiSandbox:
    def test_clean_binary_no_techniques(self, clean_file):
        result = detect_anti_sandbox(clean_file)
        assert result["anti_sandbox_detected"] is False

    def test_getcursorpos_detected(self, tmp_file):
        path = tmp_file(b"\x00" * 16 + b"GetCursorPos" + b"\x00" * 16)
        result = detect_anti_sandbox(path)
        assert result["anti_sandbox_detected"] is True
        assert any("GetCursorPos" in t for t in result["techniques"])

    def test_long_sleep_value_detected(self, tmp_file):
        # Value > 600_000_000 (> 60s in 100ns units) packed as uint64 little-endian
        long_sleep = struct.pack("<Q", 700_000_000)  # 70 seconds
        path = tmp_file(b"\x00" * 8 + long_sleep + b"\x00" * 8)
        result = detect_anti_sandbox(path)
        assert result["anti_sandbox_detected"] is True
        assert any("sleep" in t.lower() for t in result["techniques"])

    def test_getsysteminfo_detected(self, tmp_file):
        path = tmp_file(b"\x00" * 8 + b"GetSystemInfo" + b"\x00" * 8)
        result = detect_anti_sandbox(path)
        assert result["anti_sandbox_detected"] is True

    def test_missing_file_returns_error(self, tmp_path):
        result = detect_anti_sandbox(str(tmp_path / "ghost.exe"))
        assert "error" in result

    def test_returns_required_keys(self, clean_file):
        result = detect_anti_sandbox(clean_file)
        assert "anti_sandbox_detected" in result
        assert "techniques" in result
        assert isinstance(result["techniques"], list)
