# Phase 2: check_malwarebazaar, check_virustotal, check_ip_reputation, check_domain_reputation
import os
import requests


def check_malwarebazaar(hash: str) -> dict:
    """Query MalwareBazaar for a SHA-256 hash. Returns malware family and tags on a hit."""
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash},
            timeout=5,
        )
        data = resp.json()
        if data.get("query_status") == "hash_not_found":
            return {"found": False}
        entry = data.get("data", [{}])[0]
        return {
            "found": True,
            "malware_family": entry.get("signature"),
            "tags": entry.get("tags", []),
            "first_seen": entry.get("first_seen"),
            "reporter": entry.get("reporter"),
        }
    except Exception as e:
        return {"found": False, "error": str(e)}


def check_virustotal(hash: str) -> dict:
    """Query VirusTotal for multi-engine detection results on a SHA-256 hash."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "API key not configured"}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if resp.status_code == 404:
            return {"found": False}
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        # Engines that flagged the file as malicious
        notable = {
            engine: res.get("result")
            for engine, res in results.items()
            if res.get("category") == "malicious"
        }
        verdicts = [
            res.get("result")
            for res in results.values()
            if res.get("category") == "malicious" and res.get("result")
        ]
        majority_verdict = max(set(verdicts), key=verdicts.count) if verdicts else "clean"
        return {
            "found": malicious > 0,
            "detections": malicious,
            "total_engines": total,
            "majority_verdict": majority_verdict,
            "notable_engines": dict(list(notable.items())[:10]),
        }
    except Exception as e:
        return {"error": str(e)}


def check_ip_reputation(ip: str) -> dict:
    """Query AbuseIPDB for abuse confidence score and categories for an IP address."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "API key not configured"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        data = resp.json().get("data", {})
        categories = (
            [c.strip() for c in data["usageType"].split(",")]
            if data.get("usageType")
            else []
        )
        return {
            "ip": data.get("ipAddress", ip),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "categories": categories,
            "country": data.get("countryCode", ""),
            "total_reports": data.get("totalReports", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def check_domain_reputation(domain: str) -> dict:
    """Query AbuseIPDB check endpoint with a domain name for threat verdict."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "API key not configured"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": domain, "maxAgeInDays": 90},
            timeout=10,
        )
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        categories = (
            [c.strip() for c in data["usageType"].split(",")]
            if data.get("usageType")
            else []
        )
        verdict = "malicious" if score > 50 else "suspicious" if score > 10 else "clean"
        return {
            "domain": domain,
            "verdict": verdict,
            "categories": categories,
            "age_days": None,
            "registrar": data.get("isp"),
        }
    except Exception as e:
        return {"error": str(e)}
