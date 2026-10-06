"""
enrich.py

Takes normalized alerts from ingestion/ingest.py and attaches:
  1. MITRE ATT&CK technique context (via enrichment/mitre_lookup.py,
     local data, no network call)
  2. CTI reputation for the alert's source IP (via
     enrichment/abuseipdb_client.py, cached, real API when a key is set)

Per the locked mapping in the conversation (verified against real MITRE
data before use):
  - payload_delivery_detected  -> T1190, T1105, T1059
  - credential_stuffing_detected -> T1110.004

This module does not fabricate CTI or hash-reputation results. If
ABUSEIPDB_API_KEY / MALWAREBAZAAR_API_KEY are not set and no cache entry
exists, the relevant enrichment is explicitly marked unavailable --
never silently filled with a plausible-looking fake result.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mitre_lookup import get_techniques, MitreLookupError
from abuseipdb_client import check_ip, AbuseIPDBError
from malwarebazaar_client import check_hashes

TECHNIQUE_MAP = {
    "payload_delivery_detected": ["T1190", "T1105", "T1059"],
    "credential_stuffing_detected": ["T1110.004"],
}


def enrich_mitre(alert: dict) -> dict:
    """Attaches real MITRE technique data. Raises visibly (does not
    silently skip) if the alert_type has no mapping or a technique ID
    fails to resolve -- a silent skip here would mean the platform
    displays an alert with no technique context and no explanation why."""
    alert_type = alert.get("alert_type")
    technique_ids = TECHNIQUE_MAP.get(alert_type)
    if not technique_ids:
        alert["mitre"] = {
            "status": "no_mapping_defined",
            "note": f"No MITRE technique mapping configured for alert_type '{alert_type}'.",
        }
        return alert

    try:
        techniques = get_techniques(technique_ids)
        alert["mitre"] = {
            "status": "resolved",
            "techniques": techniques,
        }
    except MitreLookupError as e:
        # Fail visibly in the alert itself, not just as a raised exception
        # that would crash the whole enrichment batch.
        alert["mitre"] = {
            "status": "error",
            "note": str(e),
        }
    return alert


def enrich_cti(alert: dict) -> dict:
    """Attaches real AbuseIPDB reputation for the alert's source_ip.
    Explicitly marks unavailability rather than fabricating a score."""
    ip = alert.get("source_ip")
    if not ip:
        alert["cti"] = {"status": "no_ip_on_alert"}
        return alert

    try:
        result = check_ip(ip)
        alert["cti"] = {
            "status": "resolved",
            "source": result.get("_source"),  # "cache" or "api"
            "abuse_confidence_score": result.get("abuseConfidenceScore"),
            "total_reports": result.get("totalReports"),
            "country_code": result.get("countryCode"),
            "isp": result.get("isp"),
            "is_tor": result.get("isTor"),
            "last_reported_at": result.get("lastReportedAt"),
        }
    except AbuseIPDBError as e:
        alert["cti"] = {
            "status": "unavailable",
            "note": str(e),
        }
    return alert


def enrich_hash_reputation(alert: dict) -> dict:
    """Attaches real external hash-reputation results (MalwareBazaar) for
    every payload_sha256 found in the alert's raw_evidence.payloads_observed.
    Only applies to alerts that actually carry payload hashes -- an alert
    with no payloads gets an explicit 'no_payloads_on_alert' status, not
    silence. Never fabricates a malicious/clean verdict."""
    raw_evidence = alert.get("raw_evidence", {})
    payloads = raw_evidence.get("payloads_observed") or []
    hashes = sorted({
        p.get("payload_sha256") for p in payloads
        if isinstance(p, dict) and p.get("payload_sha256")
    })

    if not hashes:
        alert["hash_reputation"] = {"status": "no_payloads_on_alert"}
        return alert

    results = check_hashes(hashes)
    alert["hash_reputation"] = {
        "status": "checked",
        "results": results,
        "any_known_malicious": any(r.get("status") == "known_malicious" for r in results.values()),
    }
    return alert


def enrich_alert(alert: dict) -> dict:
    alert = enrich_mitre(alert)
    alert = enrich_cti(alert)
    alert = enrich_hash_reputation(alert)
    return alert


def enrich_batch(alerts: list) -> list:
    return [enrich_alert(a) for a in alerts]


if __name__ == "__main__":
    # Self-test using synthetic minimal alert shapes -- NOT real session
    # data (that's ingestion's job). This only proves the enrichment
    # wiring itself works end-to-end against real MITRE data and honestly
    # reports CTI/hash-reputation unavailability when no API key is set.
    import json

    test_alert_cred = {
        "alert_type": "credential_stuffing_detected",
        "source_ip": "203.0.113.237",
        "raw_evidence": {},
    }
    result = enrich_alert(test_alert_cred)
    print("--- credential_stuffing_detected ---")
    print(json.dumps(result, indent=2, default=str))

    test_alert_payload = {
        "alert_type": "payload_delivery_detected",
        "source_ip": "198.51.100.155",
        "raw_evidence": {
            "payloads_observed": [
                {"payload_sha256": "6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8"}
            ]
        },
    }
    result2 = enrich_alert(test_alert_payload)
    print("\n--- payload_delivery_detected ---")
    print(json.dumps(result2, indent=2, default=str))
