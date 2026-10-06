"""
coverage_checker.py

Two SEPARATE checks, both deliberately scoped to what's honestly
buildable from real telemetry (see docs/decision-log.md D-012 for the
full reasoning, including what was explicitly NOT built and why):

1. UNACCOUNTED EVIDENCE -- compares every real fact in the telemetry
   graph against every claim the analyst's explanation actually made,
   and reports real facts that exist in evidence but were never
   referenced at all. This answers a different question than
   verification does: not "is what the analyst said true" but "did the
   analyst's explanation account for everything the evidence shows."
   This is fully buildable today because DEVL already builds a graph
   from ALL real session events, not just the ones an explanation
   happens to mention.

2. TIMESTAMP GAP DETECTION -- a simple, explicitly-labeled heuristic:
   flags unusually large gaps between consecutive events in a session
   as "evidence completeness may be degraded here." This is NOT log-
   tampering detection. It cannot see evidence that was deleted and
   left zero trace -- no system can. It only surfaces a STATISTICAL
   property of the timestamps that ARE present, as a prompt for a human
   to look closer, never as a claim that something was deleted.
"""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from claim_parser import Claim
from graph_builder import TelemetryGraph

# Default gap threshold for flagging: a stated, simple heuristic, not a
# sophisticated statistical anomaly detector. Honest about being
# arbitrary/configurable rather than presented as scientifically derived.
DEFAULT_GAP_THRESHOLD_SECONDS = 300


def find_unaccounted_evidence(graph: TelemetryGraph, claims: list, scope=None) -> list:
    """
    Returns a list of real graph edges (facts) that no claim in the
    explanation referenced at all -- evidence that exists but the
    analyst's stated reasoning never mentioned.

    `scope` (optional, an InvestigationScope from relevance_engine.py):
    when given, implements the two-question design explicitly:
      Question A: is this fact relevant to the investigation at all?
                  (relevance_engine.assess_relevance)
      Question B: did the explanation account for it?
    Only facts that pass Question A are checked for Question B and can
    appear as "unaccounted" -- a real but genuinely unrelated event
    (e.g. ordinary OS housekeeping noise alongside an attack) is never
    flagged as something the analyst "missed," because it was never in
    scope to begin with. Without `scope` (the default), every fact in
    the graph is treated as in-scope -- which is exactly correct for
    this project's single-session demo data, where one graph already
    equals one investigation boundary by construction, but would NOT
    generalize safely to a graph spanning multiple unrelated
    investigations without an explicit scope.
    """
    referenced = {(c.subject, c.relation, c.obj) for c in claims}

    if scope is not None:
        from relevance_engine import assess_relevance
        unaccounted = []
        for u, v, data in graph.g.edges(data=True):
            relation = data.get("relation")
            relevance = assess_relevance(u, relation, v, data.get("timestamp"), graph, scope)
            if not relevance["in_scope"]:
                continue  # Question A failed -- never reaches Question B
            key = (u, relation, v)
            if key not in referenced:
                unaccounted.append({
                    "subject": u, "relation": relation, "object": v,
                    "timestamp": data.get("timestamp"),
                    "log_source": data.get("log_source"),
                    "relevance": relevance,
                })
        return unaccounted

    unaccounted = []
    for u, v, data in graph.g.edges(data=True):
        relation = data.get("relation")
        key = (u, relation, v)
        if key not in referenced:
            unaccounted.append({
                "subject": u, "relation": relation, "object": v,
                "timestamp": data.get("timestamp"),
                "log_source": data.get("log_source"),
            })
    return unaccounted


def detect_timestamp_gaps(facts: list, threshold_seconds: int = DEFAULT_GAP_THRESHOLD_SECONDS, scope=None) -> list:
    """
    Sorts facts by real timestamp and flags any consecutive gap larger
    than `threshold_seconds`. Facts with no parseable timestamp are
    excluded from gap calculation entirely (never treated as a 0-second
    gap, which would be a fabricated data point).

    `scope` (optional, an InvestigationScope): when given, facts are
    first filtered to only those whose subject or object is one of the
    scope's declared affected_entities, before gap analysis. REAL BUG
    caught in testing: without this filter, combining facts from two
    genuinely unrelated real sources/timeframes (e.g. this project's
    2026 honeypot session and a 2020 real Sysmon sample) into one
    timeline produces a meaningless multi-year "gap" that has nothing
    to do with evidence completeness -- it's just two unrelated
    datasets with different dates. Scoping to the investigation's own
    entities avoids that. (Entity-only filtering is used here, not the
    full temporal+causal relevance tiering from relevance_engine.py,
    because gap analysis is inherently about a scoped entity's own
    timeline continuity, not general evidence relevance.)

    Timestamp parsing is delegated to relevance_engine._parse_ts -- the
    SAME function used to compare timestamps for scope filtering -- so
    there is exactly one timestamp-parsing implementation in this
    project, not two that could drift. A SECOND real bug was caught in
    testing here too: this function originally had its own inline
    `datetime.fromisoformat` call that didn't handle Sysmon's timezone-
    naive 'UtcTime' format, and raised TypeError the moment honeypot
    (timezone-aware) and Sysmon (naive) facts were sorted together --
    see docs/decision-log.md D-015.
    """
    from relevance_engine import _parse_ts

    if scope is not None:
        from relevance_engine import _parse_ts
        if scope.affected_entities:
            facts = [f for f in facts if f.subject in scope.affected_entities or f.obj in scope.affected_entities]
        window_start = _parse_ts(scope.window_start)
        window_end = _parse_ts(scope.window_end)
        if window_start is not None or window_end is not None:
            def _within_window(f):
                ts = _parse_ts(f.timestamp)
                if ts is None:
                    return True  # unparseable timestamps are excluded later anyway, not here
                if window_start is not None and ts < window_start:
                    return False
                if window_end is not None and ts > window_end:
                    return False
                return True
            facts = [f for f in facts if _within_window(f)]

    timestamped = []
    for f in facts:
        ts = _parse_ts(f.timestamp)
        if ts is not None:
            timestamped.append((ts, f))

    timestamped.sort(key=lambda pair: pair[0])

    gaps = []
    for i in range(1, len(timestamped)):
        prev_ts, prev_fact = timestamped[i - 1]
        curr_ts, curr_fact = timestamped[i]
        delta = (curr_ts - prev_ts).total_seconds()
        if delta > threshold_seconds:
            gaps.append({
                "gap_seconds": delta,
                "after_event": f"{prev_fact.subject} {prev_fact.relation} {prev_fact.obj}",
                "after_timestamp": prev_fact.timestamp,
                "before_event": f"{curr_fact.subject} {curr_fact.relation} {curr_fact.obj}",
                "before_timestamp": curr_fact.timestamp,
                "note": (
                    "Unusually large gap between consecutive recorded events. "
                    "This does NOT mean evidence was deleted -- it may be "
                    "completely normal session behavior. It is a prompt for "
                    "human review, not a tampering claim."
                ),
            })
    return gaps


if __name__ == "__main__":
    import json
    import pandas as pd
    from fact_extractor import extract_facts_from_session
    from graph_builder import build_graph
    from claim_parser import parse_explanation

    sessions_path = Path(__file__).resolve().parent.parent / "data" / "stage6_source" / "sessions.parquet"
    df = pd.read_parquet(sessions_path)
    row = df[df["session_id"] == "S-ed7d82-0000844#192"].iloc[0]
    session = {
        "session_id": row["session_id"], "source_ip": row["source_ip"],
        "protocol": row["protocol"],
        "destination_port": int(row["destination_port"]) if pd.notna(row["destination_port"]) else None,
        "events": json.loads(row["events"]),
    }
    facts, _, _ = extract_facts_from_session(session)
    graph = build_graph(facts)

    print("=== Unaccounted evidence test ===")
    print("Explanation mentions only 2 of the 6 real facts:")
    partial_explanation = "198.51.100.155 connected to ssh:22. 198.51.100.155 authenticated as svc23."
    parsed = parse_explanation(partial_explanation)
    unaccounted = find_unaccounted_evidence(graph, parsed.claims)
    print(f"Real facts in graph: {graph.edge_count()}  |  Claims made: {len(parsed.claims)}  |  Unaccounted: {len(unaccounted)}")
    for u in unaccounted:
        print(f"  MISSED: ({u['subject']}) --{u['relation']}--> ({u['object']})  [{u['timestamp']}]")

    print()
    print("=== Timestamp gap test (real session, should show NO large gaps -- events are 1-5s apart) ===")
    gaps = detect_timestamp_gaps(facts)
    print(f"Gaps found (threshold={DEFAULT_GAP_THRESHOLD_SECONDS}s): {len(gaps)}")

    print()
    print("=== Timestamp gap test with an artificially lowered threshold, to prove detection works at all ===")
    gaps_sensitive = detect_timestamp_gaps(facts, threshold_seconds=2)
    print(f"Gaps found (threshold=2s): {len(gaps_sensitive)}")
    for g in gaps_sensitive:
        print(f"  GAP: {g['gap_seconds']}s between '{g['after_event']}' and '{g['before_event']}'")

    print()
    print("=== Scoped unaccounted-evidence test (Question A then Question B) ===")
    from relevance_engine import InvestigationScope
    from sysmon_fact_extractor import extract_facts_from_sysmon_xml

    sysmon_facts, _, _ = extract_facts_from_sysmon_xml(
        str(Path(__file__).resolve().parent.parent / "data" / "sysmon_source" / "sample_process_lineage.xml")
    )
    combined_graph = build_graph(facts + sysmon_facts)
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    scope = InvestigationScope(
        incident_id="SELFTEST-INC-1",
        affected_entities={"198.51.100.155", ps},
        window_start="2026-07-01T00:42:00Z",
        window_end="2026-07-01T00:43:00Z",
    )
    # Explanation only covers the honeypot side -- never mentions the
    # Sysmon process chain at all.
    partial_explanation_2 = "198.51.100.155 connected to ssh:22. 198.51.100.155 authenticated as svc23."
    parsed_2 = parse_explanation(partial_explanation_2)
    scoped_unaccounted = find_unaccounted_evidence(combined_graph, parsed_2.claims, scope=scope)
    unscoped_unaccounted = find_unaccounted_evidence(combined_graph, parsed_2.claims)
    print(f"Combined real graph: {combined_graph.edge_count()} total facts (honeypot + Sysmon)")
    print(f"WITHOUT scope: {len(unscoped_unaccounted)} facts flagged unaccounted (includes unrelated OS noise)")
    print(f"WITH scope:    {len(scoped_unaccounted)} facts flagged unaccounted (OS noise correctly excluded)")
    for u in scoped_unaccounted:
        print(f"  MISSED (in-scope, [{u['relevance']['relevance_tier']}]): {u['subject']} {u['relation']} {u['object']}")
