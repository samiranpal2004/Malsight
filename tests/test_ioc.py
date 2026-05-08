# Phase 2 unit tests for tools/ioc.py
import tempfile
import os

import pytest

from tools.ioc import extract_iocs, get_report


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_file(tmp_path):
    def _write(content: bytes, suffix: str = ".bin") -> str:
        p = tmp_path / f"sample{suffix}"
        p.write_bytes(content)
        return str(p)
    return _write


IOC_CONTENT = (
    b"Connecting to http://185.220.101.45/gate.php\n"
    b"Domain: update-svc-cdn.net\n"
    b"Email: victim@example.com\n"
    b"Wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n"
    b"Mutex: Global\\MicrosoftUpdateMutex_v2\n"
)


# ---------------------------------------------------------------------------
# extract_iocs
# ---------------------------------------------------------------------------

class TestExtractIocs:
    def test_extracts_ip_from_file(self, tmp_file):
        path = tmp_file(b"Connecting to 185.220.101.45 on port 443\n")
        result = extract_iocs(target="file", file_path=path)
        assert "185.220.101.45" in result["ips"]

    def test_extracts_url(self, tmp_file):
        path = tmp_file(b"GET http://evil.com/payload HTTP/1.1\n")
        result = extract_iocs(target="file", file_path=path)
        assert any("evil.com" in u for u in result["urls"])

    def test_extracts_email(self, tmp_file):
        path = tmp_file(IOC_CONTENT)
        result = extract_iocs(target="file", file_path=path)
        assert "victim@example.com" in result["emails"]

    def test_extracts_btc_wallet(self, tmp_file):
        path = tmp_file(IOC_CONTENT)
        result = extract_iocs(target="file", file_path=path)
        assert any("bc1q" in w for w in result["crypto_wallets"])

    def test_extracts_mutex(self, tmp_file):
        path = tmp_file(IOC_CONTENT)
        result = extract_iocs(target="file", file_path=path)
        assert any("MicrosoftUpdateMutex" in m for m in result["mutexes"])

    def test_private_ips_excluded(self, tmp_file):
        path = tmp_file(b"192.168.1.1 10.0.0.1 127.0.0.1 185.220.101.45")
        result = extract_iocs(target="file", file_path=path)
        ips = result["ips"]
        assert "192.168.1.1" not in ips
        assert "10.0.0.1" not in ips
        assert "127.0.0.1" not in ips
        assert "185.220.101.45" in ips

    def test_memdump_target(self, tmp_path, monkeypatch):
        dump = tmp_path / "memdump.bin"
        dump.write_bytes(b"http://c2.example.com/beacon\x00" * 5)
        monkeypatch.setattr("tools.ioc.DEFAULT_DUMP_PATH", str(dump))
        result = extract_iocs(target="memdump")
        assert "urls" in result

    def test_missing_file_returns_error(self, tmp_path):
        result = extract_iocs(target="file", file_path=str(tmp_path / "ghost.bin"))
        assert "error" in result

    def test_no_file_path_returns_error(self):
        result = extract_iocs(target="file", file_path=None)
        assert "error" in result

    def test_returns_required_keys(self, tmp_file):
        path = tmp_file(b"nothing special here")
        result = extract_iocs(target="file", file_path=path)
        for key in ("ips", "urls", "domains", "emails", "crypto_wallets", "mutexes"):
            assert key in result, f"Missing key: {key}"

    def test_exception_returns_error(self, monkeypatch):
        monkeypatch.setattr("tools.ioc.os.path.exists", lambda _: True)
        with pytest.raises(Exception):
            pass
        # Patch open to raise
        import builtins
        original_open = builtins.open

        def bad_open(*a, **kw):
            raise PermissionError("access denied")

        monkeypatch.setattr(builtins, "open", bad_open)
        result = extract_iocs(target="file", file_path="/some/file.bin")
        assert "error" in result


# ---------------------------------------------------------------------------
# get_report
# ---------------------------------------------------------------------------

class TestGetReport:
    def _valid_kwargs(self):
        return dict(
            verdict="malicious",
            confidence=97,
            threat_category="trojan",
            severity="critical",
            summary="This is a malicious trojan.",
            key_indicators=["High entropy", "Injected PE"],
            mitre_techniques=[{"id": "T1055.001", "name": "DLL Injection"}],
            recommended_action="Quarantine",
            iocs={"ips": ["185.220.101.45"], "urls": [], "domains": [], "mutexes": []},
        )

    def test_valid_report_returns_dict(self):
        result = get_report(**self._valid_kwargs())
        assert result["verdict"] == "malicious"
        assert result["confidence"] == 97
        assert result["severity"] == "critical"
        assert result["threat_category"] == "trojan"
        assert result["recommended_action"] == "Quarantine"

    def test_invalid_verdict_returns_error(self):
        kwargs = self._valid_kwargs()
        kwargs["verdict"] = "unknown_verdict"
        result = get_report(**kwargs)
        assert "error" in result

    def test_invalid_severity_returns_error(self):
        kwargs = self._valid_kwargs()
        kwargs["severity"] = "extreme"
        result = get_report(**kwargs)
        assert "error" in result

    def test_confidence_out_of_range_returns_error(self):
        kwargs = self._valid_kwargs()
        kwargs["confidence"] = 150
        result = get_report(**kwargs)
        assert "error" in result

    def test_benign_verdict_accepted(self):
        kwargs = self._valid_kwargs()
        kwargs.update(verdict="benign", confidence=92, severity="low",
                      threat_category="none", summary="Clean file.")
        result = get_report(**kwargs)
        assert result["verdict"] == "benign"
        assert "error" not in result

    def test_suspicious_verdict_accepted(self):
        kwargs = self._valid_kwargs()
        kwargs.update(verdict="suspicious", severity="medium")
        result = get_report(**kwargs)
        assert result["verdict"] == "suspicious"

    def test_missing_iocs_defaults_to_empty_dict(self):
        result = get_report(
            verdict="benign", confidence=90, threat_category="none",
            severity="low", summary="Clean.", key_indicators=[],
            mitre_techniques=[], recommended_action="Safe to execute",
        )
        assert result["iocs"] == {}

    def test_key_indicators_preserved(self):
        kwargs = self._valid_kwargs()
        result = get_report(**kwargs)
        assert "High entropy" in result["key_indicators"]
        assert "Injected PE" in result["key_indicators"]

    def test_mitre_techniques_preserved(self):
        kwargs = self._valid_kwargs()
        result = get_report(**kwargs)
        assert result["mitre_techniques"][0]["id"] == "T1055.001"

    def test_returns_all_required_schema_fields(self):
        result = get_report(**self._valid_kwargs())
        required = ("verdict", "confidence", "threat_category", "severity",
                    "summary", "key_indicators", "mitre_techniques",
                    "recommended_action", "iocs")
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_non_list_key_indicators_defaults(self):
        kwargs = self._valid_kwargs()
        kwargs["key_indicators"] = None
        result = get_report(**kwargs)
        assert result["key_indicators"] == []
