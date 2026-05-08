# Phase 2: extract_iocs, get_report
import os
import re

DEFAULT_DUMP_PATH = "/tmp/results/memdump.bin"

# ---------------------------------------------------------------------------
# IOC regex patterns
# ---------------------------------------------------------------------------

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
                   r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
                   r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b")
_URL = re.compile(r"https?://[^\s\"'<>]{4,}", re.I)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|info|biz|co|ru|cn|de|uk|fr|nl|pw|xyz|top|tk|cc|su)\b",
    re.I,
)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_BTC = re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-zA-HJ-NP-Z0-9]{25,34})\b")
_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_MUTEX = re.compile(r"\bGlobal\\[A-Za-z0-9_\-\.]{4,64}\b|"
                    r"\bLocal\\[A-Za-z0-9_\-\.]{4,64}\b")

# Private / loopback IPs to exclude from IOC results
_PRIVATE_RANGES = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.|255\.255\.255\.255)"
)


def _extract_from_bytes(data: bytes) -> dict:
    text = data.decode("utf-8", errors="ignore")

    ips = list(dict.fromkeys(
        ip for ip in _IPV4.findall(text) if not _PRIVATE_RANGES.match(ip)
    ))
    ipv6 = list(dict.fromkeys(_IPV6.findall(text)))
    urls = list(dict.fromkeys(_URL.findall(text)))
    # Domains: deduplicate and exclude those already in URLs
    url_hosts = {re.sub(r"https?://([^/:?#]+).*", r"\1", u) for u in urls}
    domains = list(dict.fromkeys(
        d for d in _DOMAIN.findall(text)
        if d not in url_hosts and d not in ips
    ))
    emails = list(dict.fromkeys(_EMAIL.findall(text)))
    btc = list(dict.fromkeys(_BTC.findall(text)))
    xmr = list(dict.fromkeys(_XMR.findall(text)))
    mutexes = list(dict.fromkeys(_MUTEX.findall(text)))

    return {
        "ips": ips[:100],
        "ipv6": ipv6[:20],
        "urls": urls[:100],
        "domains": domains[:100],
        "emails": emails[:50],
        "crypto_wallets": btc[:20] + xmr[:20],
        "mutexes": mutexes[:50],
    }


def extract_iocs(target: str = "file", file_path: str = None) -> dict:
    """Regex-extract IPs, URLs, domains, emails, crypto wallets, mutex names from file or dump."""
    try:
        if target == "memdump":
            path = DEFAULT_DUMP_PATH
        elif target == "file":
            path = file_path or ""
        else:
            path = target  # allow explicit path

        if not path or not os.path.exists(path):
            return {"error": f"target not found: {path!r}"}

        with open(path, "rb") as f:
            data = f.read()

        return _extract_from_bytes(data)
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Report packaging
# ---------------------------------------------------------------------------

_VALID_VERDICTS = {"benign", "suspicious", "malicious"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_ACTIONS = {
    "Quarantine",
    "Monitor",
    "Safe to execute",
    "Further analysis needed",
}


def get_report(
    verdict: str,
    confidence: int,
    threat_category: str,
    severity: str,
    summary: str,
    key_indicators: list,
    mitre_techniques: list,
    recommended_action: str,
    iocs: dict = None,
) -> dict:
    """Validate and package the final threat report verdict (does not persist to DB)."""
    try:
        errors: list = []

        if verdict not in _VALID_VERDICTS:
            errors.append(f"verdict must be one of {_VALID_VERDICTS}, got {verdict!r}")

        try:
            confidence = int(confidence)
        except (TypeError, ValueError):
            errors.append("confidence must be an integer")
            confidence = 0

        if not (0 <= confidence <= 100):
            errors.append(f"confidence must be 0–100, got {confidence}")

        if severity not in _VALID_SEVERITIES:
            errors.append(f"severity must be one of {_VALID_SEVERITIES}, got {severity!r}")

        if not isinstance(key_indicators, list):
            key_indicators = []

        if not isinstance(mitre_techniques, list):
            mitre_techniques = []

        if errors:
            return {"error": "; ".join(errors)}

        return {
            "verdict": verdict,
            "confidence": confidence,
            "threat_category": threat_category or "unknown",
            "severity": severity,
            "summary": summary or "",
            "key_indicators": key_indicators,
            "mitre_techniques": mitre_techniques,
            "recommended_action": recommended_action or "Further analysis needed",
            "iocs": iocs or {},
        }
    except Exception as e:
        return {"error": str(e)}
