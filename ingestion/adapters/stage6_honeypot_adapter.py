"""
stage6_honeypot_adapter.py

Adapter for the UBI Stage 6 T-Pot honeypot replay data. Reads
sessions.parquet / clusters.json and derives alerts using the rules
verified and logged in docs/decision-log.md (D-001/D-004, D-002).

This is now ONE OF POTENTIALLY MANY adapters (see D-005) -- the detection
rules below are unchanged from before the refactor; what changed is that
this module's output is now run through canonicalize_alert() before being
returned, so enrichment/playbooks/UI depend only on the canonical shape
in ingestion/canonical_schema.py, never on this file's Stage-6-specific
field names directly.
"""

import json
from pathlib import Path
import sys
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from canonical_schema import validate_batch

SOURCE_DATASET_NAME = "ubi_stage6_honeypot"

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "stage6_source"
SESSIONS_PATH = DATA_DIR / "sessions.parquet"
CLUSTERS_PATH = DATA_DIR / "clusters.json"

# Locked demo anchors from docs/decision-log.md D-003. Kept as an explicit
# allowlist here (not re-derived by rank each run) so a re-run with a
# different/updated dataset can't silently swap the demo's headline
# alerts out from under a rehearsed narration.
DEMO_CREDENTIAL_STUFFING_IPS = ["203.0.113.237", "203.0.113.182"]
DEMO_PAYLOAD_SESSION_ID = "S-ed7d82-0000844#192"


class IngestError(Exception):
    pass


def _require_files():
    missing = [p for p in (SESSIONS_PATH, CLUSTERS_PATH) if not p.exists()]
    if missing:
        raise IngestError(
            "Required Stage 6 source file(s) missing: "
            + ", ".join(str(m) for m in missing)
            + ". These must be the real files copied from your Stage 6 "
            "submission -- this module will not proceed with synthetic "
            "substitutes."
        )


def _parse_json_field(raw):
    """Stage 6 stores nested fields as JSON-encoded strings (D-007). Parse
    safely; never silently treat a parse failure as an empty/False result
    without it being visible in the return value."""
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def load_sessions() -> pd.DataFrame:
    _require_files()
    df = pd.read_parquet(SESSIONS_PATH)
    expected_cols = {
        "session_id", "source_ip", "protocol", "destination_port",
        "start_utc", "end_utc", "event_count", "events",
        "credentials_observed", "commands_observed", "payloads_observed",
    }
    missing_cols = expected_cols - set(df.columns)
    if missing_cols:
        raise IngestError(
            f"sessions.parquet is missing expected column(s): {missing_cols}. "
            f"Schema may have changed since D-001/D-002 were verified -- "
            f"re-verify the alert rules against this file before trusting output."
        )
    return df


def load_infra1_ips() -> list:
    """Retained for reference/display purposes (e.g. showing 'this session's
    IP is part of a known infrastructure cluster' in the UI) -- no longer
    used as a detection trigger condition, see D-001 revision."""
    _require_files()
    with open(CLUSTERS_PATH, "r", encoding="utf-8") as f:
        clusters = json.load(f)
    clusters_list = clusters.get("clusters", [])
    infra1 = next((c for c in clusters_list if c.get("cluster_id") == "INFRA-1"), None)
    if infra1 is None:
        raise IngestError(
            "clusters.json does not contain a cluster with cluster_id "
            "'INFRA-1' -- re-verify clusters.json before proceeding."
        )
    return infra1.get("source_ips", [])


def load_known_bad_hashes() -> set:
    """Extracts the confirmed-malicious payload hashes from clusters.json,
    used as hash-reputation CONTEXT on alerts (D-001 revision) -- not as
    the trigger condition itself."""
    _require_files()
    with open(CLUSTERS_PATH, "r", encoding="utf-8") as f:
        clusters = json.load(f)
    clusters_list = clusters.get("clusters", [])
    infra1 = next((c for c in clusters_list if c.get("cluster_id") == "INFRA-1"), None)
    if infra1 is None:
        raise IngestError(
            "clusters.json does not contain a cluster with cluster_id "
            "'INFRA-1' -- re-verify clusters.json before proceeding."
        )
    # Real schema (verified against the actual file, not assumed):
    # infra1["payloads"] is a list of {"payload_sha256": ..., "session_ids": [...]}
    payload_entries = infra1.get("payloads")
    if not payload_entries:
        raise IngestError(
            "INFRA-1 cluster entry in clusters.json has no 'payloads' field "
            "with entries. Schema may have changed -- re-verify clusters.json "
            "before proceeding."
        )
    hashes = {p["payload_sha256"] for p in payload_entries if p.get("payload_sha256")}
    return hashes



# Generic recon-style command patterns. Written to generalize beyond this
# dataset's single observed command (D-004) -- these are common real-world
# reconnaissance commands, not reverse-engineered from the data. A session
# matching any of these is flagged even with zero payload activity.
RECON_COMMAND_PATTERNS = [
    "uname", "whoami", "id", "ifconfig", "ip a", "ip addr", "netstat",
    "ss -", "ps aux", "cat /etc/passwd", "cat /etc/shadow", "wget ", "curl ",
    "chmod +x", "nc -", "ncat ", "history", "crontab",
]


def _matches_recon_pattern(command: str) -> bool:
    if not command:
        return False
    cmd_lower = command.lower()
    return any(pattern in cmd_lower for pattern in RECON_COMMAND_PATTERNS)


def derive_payload_delivery_alerts(df: pd.DataFrame, known_bad_hashes: set) -> list:
    """
    D-001 (revised per conversation): a session is flagged if EITHER:
      (a) payloads_observed is non-empty (behavioral, IP-agnostic --
          catches any payload delivery regardless of source IP), OR
      (b) commands_observed contains a recon-pattern match (behavioral,
          IP-agnostic -- catches exploitation/recon activity even with
          no payload downloaded)

    The static INFRA-1 IP list is NOT a trigger condition (removed --
    it was redundant with (a) in this dataset and would not generalize
    to a new attacker IP). Instead, a payload hash match against
    known_bad_hashes is attached as CONTEXT on the alert (does this
    match previously-seen malicious infrastructure), not used to decide
    whether to alert at all.
    """
    alerts = []
    for _, row in df.iterrows():
        payloads = _parse_json_field(row["payloads_observed"]) or []
        commands = _parse_json_field(row["commands_observed"]) or []

        has_payload = len(payloads) > 0
        recon_commands = [
            c for c in commands
            if _matches_recon_pattern(c.get("command") if isinstance(c, dict) else c)
        ]
        has_recon_command = len(recon_commands) > 0

        if not (has_payload or has_recon_command):
            continue

        # Hash-reputation context: does any payload in this session match
        # a hash we've already confirmed malicious (from clusters.json)?
        # This is IP-agnostic and survives IP rotation -- a session from
        # a brand-new IP delivering a KNOWN hash would still be flagged
        # here as "known infrastructure", strengthening triage without
        # being required for detection itself.
        payload_hashes = {
            p.get("payload_sha256") for p in payloads
            if isinstance(p, dict) and p.get("payload_sha256")
        }
        matched_known_hashes = payload_hashes & known_bad_hashes

        canonical_alert = {
            "alert_type": "payload_delivery_detected",
            "entity_type": "session",
            "entity_id": row["session_id"],
            "source_ip": row["source_ip"],
            "source_dataset": SOURCE_DATASET_NAME,
            "first_seen_utc": row["start_utc"],
            "last_seen_utc": row["end_utc"],
            "raw_evidence": {
                "protocol": row["protocol"],
                "destination_port": int(row["destination_port"]) if pd.notna(row["destination_port"]) else None,
                "payloads_observed": payloads,
                "commands_observed": commands,
                "trigger_reason": {
                    "has_payload": has_payload,
                    "has_recon_command": has_recon_command,
                    "matched_recon_commands": recon_commands,
                },
                "known_infrastructure_match": bool(matched_known_hashes),
                "matched_known_hashes": list(matched_known_hashes),
            },
            "is_demo_anchor": row["session_id"] == DEMO_PAYLOAD_SESSION_ID,
        }
        alerts.append(canonical_alert)
    return alerts


def derive_credential_stuffing_alerts(df: pd.DataFrame) -> list:
    """Implements D-002: aggregate auth_fail count per source_ip. Returns
    one alert entity per source_ip that has any auth_fail activity, with
    the aggregate count and the list of contributing session_ids."""

    def count_auth_fail(events_raw):
        events = _parse_json_field(events_raw) or []
        return sum(1 for e in events if e.get("action") == "auth_fail")

    df = df.copy()
    df["_auth_fail_count"] = df["events"].apply(count_auth_fail)

    grouped = df[df["_auth_fail_count"] > 0].groupby("source_ip").agg(
        total_auth_fail=("_auth_fail_count", "sum"),
        session_count=("session_id", "count"),
        session_ids=("session_id", list),
        first_start=("start_utc", "min"),
        last_end=("end_utc", "max"),
    ).reset_index()

    alerts = []
    for _, row in grouped.iterrows():
        canonical_alert = {
            "alert_type": "credential_stuffing_detected",
            "entity_type": "source_ip",
            "entity_id": row["source_ip"],
            "source_ip": row["source_ip"],
            "source_dataset": SOURCE_DATASET_NAME,
            "first_seen_utc": row["first_start"],
            "last_seen_utc": row["last_end"],
            "raw_evidence": {
                "total_auth_fail": int(row["total_auth_fail"]),
                "session_count": int(row["session_count"]),
                "session_ids": row["session_ids"],
            },
            "is_demo_anchor": row["source_ip"] in DEMO_CREDENTIAL_STUFFING_IPS,
        }
        alerts.append(canonical_alert)
    # Highest volume first -- makes the demo-anchor IPs naturally surface
    # near the top without needing separate sorting logic downstream.
    alerts.sort(key=lambda a: a["raw_evidence"]["total_auth_fail"], reverse=True)
    return alerts


def run_adapter() -> dict:
    """Top-level entry point for this adapter. Returns a dict with both
    canonical-shaped alert lists plus a reconciliation block, matching
    the reconciliation.json pattern already used in Stage 6 -- so counts
    are always explicitly checkable, not just asserted. Every alert is
    validated against the canonical schema before being returned."""
    df = load_sessions()
    known_bad_hashes = load_known_bad_hashes()

    payload_alerts = derive_payload_delivery_alerts(df, known_bad_hashes)
    cred_alerts = derive_credential_stuffing_alerts(df)

    payload_alerts = validate_batch(payload_alerts, adapter_name=SOURCE_DATASET_NAME)
    cred_alerts = validate_batch(cred_alerts, adapter_name=SOURCE_DATASET_NAME)

    demo_payload_present = any(a["is_demo_anchor"] for a in payload_alerts)
    demo_cred_present = sum(1 for a in cred_alerts if a["is_demo_anchor"])

    return {
        "reconciliation": {
            "source_dataset": SOURCE_DATASET_NAME,
            "total_sessions_in_source": len(df),
            "payload_delivery_alerts": len(payload_alerts),
            "credential_stuffing_alert_ips": len(cred_alerts),
            "demo_payload_anchor_found": demo_payload_present,
            "demo_credential_anchors_found": demo_cred_present,
            "demo_credential_anchors_expected": len(DEMO_CREDENTIAL_STUFFING_IPS),
        },
        "payload_delivery_alerts": payload_alerts,
        "credential_stuffing_alerts": cred_alerts,
    }


if __name__ == "__main__":
    result = run_adapter()
    print(json.dumps(result["reconciliation"], indent=2))
    if not result["reconciliation"]["demo_payload_anchor_found"]:
        raise SystemExit("ERROR: demo payload anchor session not found in alerts -- investigate before demo.")
    if result["reconciliation"]["demo_credential_anchors_found"] != result["reconciliation"]["demo_credential_anchors_expected"]:
        raise SystemExit("ERROR: demo credential-stuffing anchor IP(s) missing from alerts -- investigate before demo.")
    print("\nAll reconciliation checks passed (Stage 6 adapter, canonical schema validated).")
