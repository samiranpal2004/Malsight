# Phase 2 unit tests for tools/threat_intel.py
import os
from unittest.mock import MagicMock, patch

import pytest

from tools.threat_intel import (
    check_domain_reputation,
    check_ip_reputation,
    check_malwarebazaar,
    check_virustotal,
)

KNOWN_HASH = "a3f9c12e84b14d2a91ccf0e123456789abcdef01234567890abcdef012345678"
UNKNOWN_HASH = "0" * 64


# ---------------------------------------------------------------------------
# check_malwarebazaar
# ---------------------------------------------------------------------------

class TestCheckMalwarebazaar:
    def test_known_hash_returns_found(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "query_status": "ok",
            "data": [{
                "signature": "Emotet",
                "tags": ["trojan", "banker"],
                "first_seen": "2024-01-15",
                "reporter": "abuse.ch",
            }],
        }
        with patch("tools.threat_intel.requests.post", return_value=mock_resp):
            result = check_malwarebazaar(KNOWN_HASH)

        assert result["found"] is True
        assert result["malware_family"] == "Emotet"
        assert "trojan" in result["tags"]
        assert result["first_seen"] == "2024-01-15"

    def test_unknown_hash_returns_not_found(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "hash_not_found"}
        with patch("tools.threat_intel.requests.post", return_value=mock_resp):
            result = check_malwarebazaar(UNKNOWN_HASH)

        assert result["found"] is False
        assert "error" not in result

    def test_network_error_returns_error_key(self):
        with patch("tools.threat_intel.requests.post", side_effect=Exception("timeout")):
            result = check_malwarebazaar(KNOWN_HASH)

        assert result["found"] is False
        assert "error" in result
        assert "timeout" in result["error"]

    def test_returns_dict(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "hash_not_found"}
        with patch("tools.threat_intel.requests.post", return_value=mock_resp):
            result = check_malwarebazaar(UNKNOWN_HASH)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# check_virustotal
# ---------------------------------------------------------------------------

class TestCheckVirusTotal:
    def test_missing_api_key_returns_error(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        result = check_virustotal(KNOWN_HASH)
        assert "error" in result
        assert "API key not configured" in result["error"]

    def test_known_hash_returns_detections(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 47, "undetected": 25},
                    "last_analysis_results": {
                        "Kaspersky": {"category": "malicious", "result": "Trojan.Agent"},
                        "CrowdStrike": {"category": "malicious", "result": "malicious_100"},
                    },
                }
            }
        }
        with patch("tools.threat_intel.requests.get", return_value=mock_resp):
            result = check_virustotal(KNOWN_HASH)

        assert result["found"] is True
        assert result["detections"] == 47
        assert result["total_engines"] == 72
        assert "Kaspersky" in result["notable_engines"]

    def test_not_found_returns_found_false(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("tools.threat_intel.requests.get", return_value=mock_resp):
            result = check_virustotal(UNKNOWN_HASH)

        assert result["found"] is False

    def test_network_error_returns_error(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")
        with patch("tools.threat_intel.requests.get", side_effect=Exception("connection refused")):
            result = check_virustotal(KNOWN_HASH)

        assert "error" in result


# ---------------------------------------------------------------------------
# check_ip_reputation
# ---------------------------------------------------------------------------

class TestCheckIpReputation:
    def test_missing_api_key_returns_error(self, monkeypatch):
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        result = check_ip_reputation("185.220.101.45")
        assert "error" in result
        assert "API key not configured" in result["error"]

    def test_known_c2_ip_returns_high_score(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "185.220.101.45",
                "abuseConfidenceScore": 97,
                "usageType": "Data Center/Web Hosting/Transit",
                "countryCode": "RO",
                "totalReports": 412,
            }
        }
        with patch("tools.threat_intel.requests.get", return_value=mock_resp):
            result = check_ip_reputation("185.220.101.45")

        assert result["ip"] == "185.220.101.45"
        assert result["abuse_confidence_score"] == 97
        assert result["country"] == "RO"
        assert result["total_reports"] == 412

    def test_network_error_returns_error(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
        with patch("tools.threat_intel.requests.get", side_effect=Exception("dns failure")):
            result = check_ip_reputation("1.2.3.4")

        assert "error" in result

    def test_result_contains_required_keys(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {}}
        with patch("tools.threat_intel.requests.get", return_value=mock_resp):
            result = check_ip_reputation("1.2.3.4")

        for key in ("ip", "abuse_confidence_score", "categories", "country", "total_reports"):
            assert key in result, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# check_domain_reputation
# ---------------------------------------------------------------------------

class TestCheckDomainReputation:
    def test_missing_api_key_returns_error(self, monkeypatch):
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        result = check_domain_reputation("evil-domain.net")
        assert "error" in result

    def test_malicious_domain_verdict(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"abuseConfidenceScore": 85, "usageType": "Malware", "isp": "Namecheap"}
        }
        with patch("tools.threat_intel.requests.get", return_value=mock_resp):
            result = check_domain_reputation("update-svc-cdn.net")

        assert result["domain"] == "update-svc-cdn.net"
        assert result["verdict"] == "malicious"

    def test_clean_domain_verdict(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"abuseConfidenceScore": 0}}
        with patch("tools.threat_intel.requests.get", return_value=mock_resp):
            result = check_domain_reputation("google.com")

        assert result["verdict"] == "clean"

    def test_network_error_returns_error(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
        with patch("tools.threat_intel.requests.get", side_effect=RuntimeError("timeout")):
            result = check_domain_reputation("example.com")

        assert "error" in result
