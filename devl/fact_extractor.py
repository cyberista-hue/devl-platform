"""
fact_extractor.py

Component 1 of the SOC Decision Evidence Validation
Layer (DEVL): Telemetry Ingestion & Fact Extractor.

Normalizes raw session telemetry into a canonical entity-attribute-
action schema (Fact Triples), per the DEVL architecture spec.

HONEST SCOPE NOTE: the real telemetry this project has access to (from
Stage 6, see docs/decision-log.md) is Linux/IoT honeypot session data
(SSH/Telnet/HTTP/MQTT), NOT Windows Sysmon/EDR telemetry. The DEVL
architecture spec was written with Windows Sysmon Event IDs as its
worked example (Office->PowerShell). This implementation is faithful to
the same architecture and verification LOGIC, applied honestly to the
telemetry actually available. The log-source taxonomy below
(NETWORK_SESSION_LOG, AUTH_LOG, COMMAND_EXEC_LOG, PAYLOAD_CAPTURE_LOG)
is this project's own, matched to what the T-Pot honeypot genuinely
captures -- adapting this to real Sysmon Event IDs / EDR telemetry for
a Windows enterprise environment is named explicitly as a
path-to-production step, not silently assumed to already work there.
"""

import json
from dataclasses import dataclass, field, asdict
from typing import Optional


# Honest log-source taxonomy matching what this project's real data
# actually contains (see honest scope note above). Extended (see
# docs/decision-log.md D-015) with real Windows Sysmon log sources once
# genuine Sysmon telemetry became available -- see
# devl/sysmon_fact_extractor.py and data/sysmon_source/DOWNLOAD_INFO.txt
# for provenance. These are kept in the SAME LogSource/Relation classes
# (not a parallel set) so evidence_matcher, claim_parser, and
# coverage_checker all work on Sysmon facts unchanged.
class LogSource:
    NETWORK_SESSION_LOG = "network_session_log"   # connect/disconnect events
    AUTH_LOG = "auth_log"                          # auth_success/auth_fail
    COMMAND_EXEC_LOG = "command_exec_log"          # command events
    PAYLOAD_CAPTURE_LOG = "payload_capture_log"    # payload_download events
    BANNER_LOG = "banner_log"                      # client_banner events
    PROCESS_CREATION_LOG = "process_creation_log"  # Sysmon Event ID 1
    PROCESS_ACCESS_LOG = "process_access_log"      # Sysmon Event ID 10
    FILE_CREATION_LOG = "file_creation_log"        # Sysmon Event ID 11


class Relation:
    CONNECTED_TO = "CONNECTED_TO"
    DISCONNECTED_FROM = "DISCONNECTED_FROM"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    AUTH_FAILED_AS = "AUTH_FAILED_AS"
    EXECUTED = "EXECUTED"
    DOWNLOADED_PAYLOAD = "DOWNLOADED_PAYLOAD"
    SENT_BANNER = "SENT_BANNER"
    SPAWNED = "SPAWNED"              # parent process -> child process (Sysmon EID 1)
    ACCESSED_PROCESS = "ACCESSED_PROCESS"    # source process -> target process (Sysmon EID 10)
    CREATED_FILE = "CREATED_FILE"    # process -> file path (Sysmon EID 11)


@dataclass
class Fact:
    """One canonical fact triple, with provenance so every fact can be
    traced back to exactly which raw event produced it."""
    subject: str
    relation: str
    obj: str
    timestamp: Optional[str]
    log_source: str
    session_id: str
    raw_event: dict = field(default_factory=dict)

    def key(self) -> tuple:
        """A fact's identity for graph/matching purposes -- excludes
        timestamp/raw_event so near-duplicate events don't create
        spurious distinct facts, but keeps subject/relation/object as
        the meaningful triple."""
        return (self.subject, self.relation, self.obj)

    def to_dict(self) -> dict:
        return asdict(self)


class FactExtractionError(Exception):
    pass


def extract_facts_from_session(session: dict) -> tuple:
    """
    Input: a real session dict as produced by the Stage 6 adapter (must
    contain session_id, source_ip, protocol, destination_port, and a
    parsed `events` list -- see ingestion/adapters/stage6_honeypot_adapter.py
    for the source schema). This function does NOT invent facts for
    event types it doesn't recognize -- an unrecognized action is
    skipped with the raw event preserved in a `skipped_events` field on
    the return, so nothing is silently lost or silently fabricated.

    Output: (facts: List[Fact], skipped_events: List[dict],
             incomplete_events: List[dict])

    `skipped_events` holds events whose action isn't recognized at all.
    `incomplete_events` holds events with a RECOGNIZED action but a
    missing required field (fixed per review: these used to silently
    become facts with a fabricated placeholder value, e.g.
    DOWNLOADED_PAYLOAD -> "unknown_hash" -- a fabricated fact is worse
    than a visibly missing one for an evidence-validation tool, so such
    events are now excluded from `facts` and reported separately
    instead, each with a specific reason).
    """
    required = {"session_id", "source_ip", "protocol", "events"}
    missing = required - set(session.keys())
    if missing:
        raise FactExtractionError(f"Session missing required field(s) for fact extraction: {missing}")

    session_id = session["session_id"]
    source_ip = session["source_ip"]
    protocol = session["protocol"]
    dest_port = session.get("destination_port")
    dest_label = f"{protocol}:{dest_port}" if dest_port else protocol

    facts = []
    skipped_events = []
    incomplete_events = []  # events with a recognized action but a
                             # missing required field -- these do NOT
                             # become facts with a fabricated placeholder
                             # value (see review fix below), but they are
                             # also not silently indistinguishable from
                             # genuinely unrecognized actions.

    for event in session["events"]:
        action = event.get("action")
        ts = event.get("utc") or event.get("event_time") or event.get("timestamp")

        if action == "connect":
            facts.append(Fact(
                subject=source_ip, relation=Relation.CONNECTED_TO, obj=dest_label,
                timestamp=ts, log_source=LogSource.NETWORK_SESSION_LOG,
                session_id=session_id, raw_event=event,
            ))
        elif action == "disconnect":
            facts.append(Fact(
                subject=source_ip, relation=Relation.DISCONNECTED_FROM, obj=dest_label,
                timestamp=ts, log_source=LogSource.NETWORK_SESSION_LOG,
                session_id=session_id, raw_event=event,
            ))
        elif action == "auth_success":
            username = event.get("username") or event.get("user")
            if not username:
                incomplete_events.append({"event": event, "reason": "auth_success missing username/user field"})
                continue
            facts.append(Fact(
                subject=source_ip, relation=Relation.AUTHENTICATED_AS, obj=username,
                timestamp=ts, log_source=LogSource.AUTH_LOG,
                session_id=session_id, raw_event=event,
            ))
        elif action == "auth_fail":
            username = event.get("username") or event.get("user")
            if not username:
                incomplete_events.append({"event": event, "reason": "auth_fail missing username/user field"})
                continue
            facts.append(Fact(
                subject=source_ip, relation=Relation.AUTH_FAILED_AS, obj=username,
                timestamp=ts, log_source=LogSource.AUTH_LOG,
                session_id=session_id, raw_event=event,
            ))
        elif action == "command":
            cmd = event.get("command")
            if not cmd:
                incomplete_events.append({"event": event, "reason": "command event missing command field"})
                continue
            facts.append(Fact(
                subject=source_ip, relation=Relation.EXECUTED, obj=cmd,
                timestamp=ts, log_source=LogSource.COMMAND_EXEC_LOG,
                session_id=session_id, raw_event=event,
            ))
        elif action == "payload_download":
            payload_hash = event.get("payload_sha256")
            if not payload_hash:
                incomplete_events.append({"event": event, "reason": "payload_download missing payload_sha256 field"})
                continue
            facts.append(Fact(
                subject=source_ip, relation=Relation.DOWNLOADED_PAYLOAD, obj=payload_hash,
                timestamp=ts, log_source=LogSource.PAYLOAD_CAPTURE_LOG,
                session_id=session_id, raw_event=event,
            ))
        elif action == "client_banner":
            banner = event.get("banner")
            if not banner:
                incomplete_events.append({"event": event, "reason": "client_banner missing banner field"})
                continue
            facts.append(Fact(
                subject=source_ip, relation=Relation.SENT_BANNER, obj=banner,
                timestamp=ts, log_source=LogSource.BANNER_LOG,
                session_id=session_id, raw_event=event,
            ))
        else:
            skipped_events.append(event)

    return facts, skipped_events, incomplete_events


if __name__ == "__main__":
    # Self-test against a real session pulled from actual Stage 6 data
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ingestion" / "adapters"))
    import pandas as pd

    sessions_path = Path(__file__).resolve().parent.parent / "data" / "stage6_source" / "sessions.parquet"
    df = pd.read_parquet(sessions_path)
    row = df[df["session_id"] == "S-ed7d82-0000844#192"].iloc[0]

    session = {
        "session_id": row["session_id"],
        "source_ip": row["source_ip"],
        "protocol": row["protocol"],
        "destination_port": int(row["destination_port"]) if pd.notna(row["destination_port"]) else None,
        "events": json.loads(row["events"]),
    }

    facts, skipped, incomplete = extract_facts_from_session(session)
    print(f"Extracted {len(facts)} facts from real session {session['session_id']}:")
    for f in facts:
        print(f"  ({f.subject}) --{f.relation}--> ({f.obj})  [{f.log_source}]")
    print(f"\nSkipped/unrecognized events: {len(skipped)}")
    print(f"Incomplete events (recognized action, missing required field -- excluded, not fabricated): {len(incomplete)}")
