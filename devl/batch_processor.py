"""
batch_processor.py

Extends DEVL to handle MULTIPLE alerts at once. Two distinct things
this does, kept conceptually separate:

1. BATCH VERIFICATION -- runs the existing per-alert pipeline (facts ->
   graph -> claims -> verify -> integrity -> reason slate) independently
   for each alert in the batch. Each alert's explanation is checked ONLY
   against that alert's own telemetry -- alerts never contaminate each
   other's verification. Results are then ranked so the most concerning
   ones (lowest integrity score / contradictions) surface first.

2. CORRELATION -- a SEPARATE pass, run only AFTER verification, that
   looks across all the batch's telemetry graphs for entities (IPs,
   payload hashes, usernames) that appear in more than one alert. This
   answers a different question than verification does: not "is this
   alert's explanation true" but "are these alerts connected to each
   other." Correlation never changes an individual alert's integrity
   score or verdict -- it's presented as separate, additional context.

HONEST SCOPE NOTE: this is deliberately simple, deterministic
entity-overlap detection (shared IP / hash / username across graphs),
not a statistical or ML-based campaign-clustering algorithm. It
directly generalizes the same manual finding from Stage 6 (the same
payload hash appearing across multiple source IPs = shared
infrastructure, see clusters.json's INFRA-1) into an automatic,
per-batch check -- it is not claimed to detect more sophisticated or
subtle correlation patterns (e.g. behavioral similarity without any
shared literal entity).
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fact_extractor import extract_facts_from_session, FactExtractionError
from graph_builder import build_graph
from claim_parser import parse_explanation
from evidence_matcher import verify_claims
from mismatch_engine import compute_integrity
from reason_slate import generate_reason_slate
from coverage_checker import find_unaccounted_evidence, detect_timestamp_gaps


class BatchProcessingError(Exception):
    pass


def load_manifest(path: str) -> list:
    """
    Manifest format: a JSON list of entries, each either
      {"alert_id": "...", "session": "path/to/session.json", "explanation": "text..."}
    or
      {"alert_id": "...", "session": "path/to/session.json", "explanation_file": "path/to/file.txt"}
    """
    with open(path, "r", encoding="utf-8") as f:
        entries = json.load(f)
    if not isinstance(entries, list):
        raise BatchProcessingError(f"Manifest {path} must be a JSON list of alert entries.")
    return entries


def _load_session(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def process_batch(manifest_entries: list) -> dict:
    """
    Runs verification independently per alert, then a separate
    correlation pass across all resulting graphs. Returns a full batch
    report. Any single alert's processing failure is recorded per-alert
    (not silently skipped, not aborting the whole batch) so one bad
    input doesn't hide results for the rest.
    """
    alert_results = []
    graphs_by_alert = {}   # alert_id -> TelemetryGraph, kept for the correlation pass
    facts_by_alert = {}    # alert_id -> list[Fact], for entity role lookups during correlation

    for entry in manifest_entries:
        alert_id = entry.get("alert_id") or entry.get("session", "unknown")
        try:
            session = _load_session(entry["session"])
            facts, _, _ = extract_facts_from_session(session)
            graph = build_graph(facts)

            if "explanation_file" in entry:
                with open(entry["explanation_file"], "r", encoding="utf-8") as f:
                    explanation_text = f.read()
            else:
                explanation_text = entry["explanation"]

            parsed = parse_explanation(explanation_text)
            verdicts = verify_claims(parsed.claims, graph)
            report = compute_integrity(verdicts)
            unaccounted = find_unaccounted_evidence(graph, parsed.claims)
            gaps = detect_timestamp_gaps(facts)
            slate = generate_reason_slate(
                alert_id=alert_id, explanation_text=explanation_text,
                graph=graph, report=report,
                analyst_decision=entry.get("decision"),
                unaccounted_evidence=unaccounted,
                timestamp_gaps=gaps,
                unparsed_fragments=parsed.unparsed_fragments,
            )

            alert_results.append({"alert_id": alert_id, "status": "processed", "slate": slate})
            graphs_by_alert[alert_id] = graph
            facts_by_alert[alert_id] = facts

        except (FactExtractionError, KeyError, FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            alert_results.append({
                "alert_id": alert_id, "status": "error",
                "error": f"{type(e).__name__}: {e}",
            })

    # Rank successfully processed alerts: contradictions/mismatches
    # first (most concerning), then by ascending integrity score.
    def sort_key(r):
        if r["status"] != "processed":
            return (2, 0)  # errors last
        slate = r["slate"]
        has_contradiction = "CONTRADICTORY_EVIDENCE_DETECTED" in slate["explanation_integrity"]["flags"]
        return (0 if has_contradiction else 1, slate["explanation_integrity"]["score"])

    ranked = sorted(alert_results, key=sort_key)

    correlation = correlate_entities(graphs_by_alert)

    batch_summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(manifest_entries),
        "processed": sum(1 for r in alert_results if r["status"] == "processed"),
        "errors": sum(1 for r in alert_results if r["status"] == "error"),
        "ranked_alerts": ranked,
        "correlation": correlation,
    }

    canonical = json.dumps(batch_summary, sort_keys=True, separators=(",", ":"), default=str)
    batch_summary["batch_audit_digest"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return batch_summary


import re


IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
HASH_RE = re.compile(r"^[a-f0-9]{64}$")


def _classify_confidence(entity: str, relations_seen: set) -> str:
    """
    Honest confidence tiering, matching the same reasoning already
    established in this project's own Stage 6 decision log (D-009-era
    finding: byte-identical payload hashes across IPs = high-confidence
    infrastructure link; shared commands/credentials = weaker, since
    generic tooling or shared wordlists can explain overlap without a
    shared actor). Applied here generically:
      - a payload hash or a raw IP entity shared across alerts ->
        STRONG_ENTITY_OVERLAP (a specific artifact/address is a
        meaningful coincidence)
      - an EXECUTED command shared across alerts -> WEAK_ENTITY_OVERLAP
        (this project's own dataset has exactly ONE distinct command
        across 62,515 sessions -- see D-004 -- so a shared command is
        NOT a meaningful signal here, and generically, commands are
        often generic/reused tooling, not proof of a shared actor)
      - anything else (username, banner, host:port) ->
        MEDIUM_ENTITY_OVERLAP

    NAMING NOTE (per review): labels use the explicit suffix
    "_ENTITY_OVERLAP" rather than a bare STRONG/MEDIUM/WEAK, so the
    output cannot be misread as "strong evidence of the same actor" --
    what is actually established is strong evidence that two alerts
    share this literal entity, which is a narrower, more defensible
    claim.
    """
    if HASH_RE.match(entity) or IP_RE.match(entity):
        return "STRONG_ENTITY_OVERLAP"
    if "EXECUTED" in relations_seen:
        return "WEAK_ENTITY_OVERLAP"
    return "MEDIUM_ENTITY_OVERLAP"


def correlate_entities(graphs_by_alert: dict) -> dict:
    """
    Builds a global index of every node (entity) across every alert's
    graph, then reports which entities appear in MORE THAN ONE alert's
    graph -- a real, deterministic shared-infrastructure signal (same
    IP, payload hash, or username seen across separate alerts). Each
    shared entity is tagged with an honest confidence tier (see
    _classify_confidence) rather than presented as uniformly meaningful.
    """
    entity_to_alerts = defaultdict(set)
    entity_to_relations = defaultdict(set)

    for alert_id, graph in graphs_by_alert.items():
        for u, v, data in graph.g.edges(data=True):
            relation = data.get("relation")
            for node in (u, v):
                if node:
                    entity_to_alerts[node].add(alert_id)
                    entity_to_relations[node].add(relation)

    shared = {
        entity: sorted(alerts)
        for entity, alerts in entity_to_alerts.items()
        if len(alerts) > 1
    }

    return {
        "shared_entity_count": len(shared),
        "shared_entities": [
            {
                "entity": entity,
                "appears_in_alerts": alerts,
                "confidence": _classify_confidence(entity, entity_to_relations[entity]),
            }
            for entity, alerts in sorted(shared.items())
        ],
    }


if __name__ == "__main__":
    # Self-test: 3 real alerts -- the original demo session, plus two
    # real sessions from DIFFERENT source IPs that genuinely share a
    # payload hash (confirmed against real data before this test was
    # written, not assumed) -- proving correlation surfaces a real,
    # non-fabricated shared-infrastructure link.
    manifest = [
        {
            "alert_id": "ALT-001",
            "session": "devl/samples/demo_session_payload_delivery.json",
            "explanation": (
                "198.51.100.155 connected to ssh:22. 198.51.100.155 authenticated as svc23. "
                "198.51.100.155 executed the command 'uname -a && id'. "
                "198.51.100.155 downloaded a malicious payload with hash "
                "6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8."
            ),
        },
        {
            "alert_id": "ALT-002",
            "session": "devl/samples/session_S-ed7d82-0000211_201.json",
            "explanation": "198.51.100.155 connected to mqtt:1883.",
        },
        {
            "alert_id": "ALT-003",
            "session": "devl/samples/session_S-ed7d82-0001055_883.json",
            "explanation": "198.51.100.160 connected to mqtt:1883.",
        },
    ]

    report = process_batch(manifest)
    print(f"Processed {report['processed']}/{report['total_alerts']} alerts, {report['errors']} error(s)\n")
    print("=== Ranked alerts (most concerning first) ===")
    for r in report["ranked_alerts"]:
        if r["status"] == "processed":
            s = r["slate"]["explanation_integrity"]
            print(f"  {r['alert_id']}: score={s['score']} status={s['status']} flags={s['flags']}")
        else:
            print(f"  {r['alert_id']}: ERROR - {r['error']}")

    print(f"\n=== Correlation: {report['correlation']['shared_entity_count']} shared entit(y/ies) across alerts ===")
    for item in report["correlation"]["shared_entities"]:
        print(f"  [{item['confidence']}] '{item['entity']}' appears in: {item['appears_in_alerts']}")
