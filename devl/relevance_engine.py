"""
relevance_engine.py

Answers the question: "How does DEVL know this evidence is related to
THIS incident, rather than an unrelated event, before using it as a
basis for an unaccounted-evidence or contradiction finding?"

Without this, find_unaccounted_evidence() would implicitly treat EVERY
fact in a graph as relevant to the investigation -- which works for
this project's single-session demo data (one session == one
investigation boundary, by construction), but does not generalize
honestly once facts from multiple sources/sessions/timeframes could be
merged into one graph. This module makes the scoping explicit and
inspectable instead of implicit.

Implements the layered relevance model:
  1. TEMPORAL  -- is the evidence inside the investigation's time window?
  2. ENTITY    -- does the evidence involve an entity (host/user/ip/
                  process) declared as part of the investigation?
  3. CAUSAL    -- is the evidence connected, via a real graph path
                  (e.g. a SPAWNED/ACCESSED_PROCESS process-lineage
                  chain), to another already-in-scope entity?

These combine into one disclosed, deterministic relevance_score (NOT a
trained ML weight -- see docs/decision-log.md D-015 for why a numeric
ML-style confidence score was deliberately NOT built). The two-question
design this was built to satisfy:
  Question A: Is this evidence relevant to the investigation?
  Question B: Does the analyst's reasoning account for this relevant
              evidence?
Only evidence that passes Question A is used for Question B (see
coverage_checker.find_unaccounted_evidence's `scope` parameter).
"""

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from graph_builder import TelemetryGraph

try:
    import networkx as nx
except ImportError:  # pragma: no cover
    nx = None


@dataclass
class InvestigationScope:
    """
    Explicit investigation boundary -- the analogue of the document's
    worked example ("Incident ID: INC-2026-014, Affected host: WS-023,
    Affected user: alice, Investigation window: 09:45-11:30"). Nothing
    here is inferred; the analyst/caller states it.
    """
    incident_id: str
    affected_entities: set = field(default_factory=set)  # hosts/users/IPs/processes central to the investigation
    window_start: Optional[str] = None   # ISO8601 string, inclusive; None = unbounded
    window_end: Optional[str] = None     # ISO8601 string, inclusive; None = unbounded

    def __post_init__(self):
        self.affected_entities = set(self.affected_entities)


def _parse_ts(ts: Optional[str]):
    """
    Parses a timestamp from either real format this project's two
    extractors produce: the honeypot's ISO8601 with 'Z' (timezone-
    aware) or Sysmon's 'YYYY-MM-DD HH:MM:SS.ffffff' (timezone-naive).
    A naive timestamp is assumed UTC (Sysmon's UtcTime field is, by
    its own name, already UTC) so the two sources can be compared --
    REAL BUG caught in testing: comparing an aware and a naive
    datetime raises TypeError, which surfaced the moment both real
    data sources were combined under one scope, not from either
    source alone.
    """
    if not ts:
        return None
    try:
        cleaned = ts.replace("Z", "+00:00")
        if " " in cleaned and "T" not in cleaned:
            cleaned = cleaned.replace(" ", "T")
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError):
        return None


def _temporal_match(timestamp, scope):
    if scope.window_start is None and scope.window_end is None:
        return None
    ts = _parse_ts(timestamp)
    if ts is None:
        return None
    start = _parse_ts(scope.window_start)
    end = _parse_ts(scope.window_end)
    if start is not None and ts < start:
        return False
    if end is not None and ts > end:
        return False
    return True


def _entity_match(subject, obj, scope):
    if not scope.affected_entities:
        return False
    return subject in scope.affected_entities or obj in scope.affected_entities


def _causal_match(subject, obj, graph, scope, causal_relations=("SPAWNED", "ACCESSED_PROCESS", "CREATED_FILE")):
    if nx is None or not scope.affected_entities:
        return False
    causal_edges = [
        (u, v) for u, v, d in graph.g.edges(data=True)
        if d.get("relation") in causal_relations
    ]
    if not causal_edges:
        return False
    sub = nx.Graph()
    sub.add_edges_from(causal_edges)

    for entity in scope.affected_entities:
        if entity not in sub:
            continue
        if subject in sub and nx.has_path(sub, entity, subject):
            return True
        if obj in sub and nx.has_path(sub, entity, obj):
            return True
    return False


RELEVANCE_WEIGHTS = {"temporal": 0.3, "entity": 0.4, "causal": 0.3}


def assess_relevance(subject, relation, obj, timestamp, graph, scope):
    temporal = _temporal_match(timestamp, scope)
    entity = _entity_match(subject, obj, scope)
    causal = _causal_match(subject, obj, graph, scope)

    score = (
        (RELEVANCE_WEIGHTS["temporal"] if temporal else 0.0)
        + (RELEVANCE_WEIGHTS["entity"] if entity else 0.0)
        + (RELEVANCE_WEIGHTS["causal"] if causal else 0.0)
    )

    # Deliberate design choice, stated explicitly: an entity or causal
    # match is sufficient for relevance EVEN IF the timestamp falls
    # outside the declared window (or is incomparable, e.g. real data
    # from two different real-world collection dates in this project's
    # own demo). The investigation's declared entities are relevant to
    # know about regardless of when their activity occurred -- that's
    # different from asking whether two timestamps are close enough to
    # compute a meaningful GAP between (see coverage_checker.
    # detect_timestamp_gaps, which DOES require both entity match and
    # being within the declared window, for exactly this reason: a
    # cross-era "gap" between two unrelated real datasets is not a
    # meaningful completeness signal, but knowing about a named
    # entity's full activity is still relevant evidence).
    if entity or causal:
        tier = "HIGH" if (entity and causal) else "MEDIUM"
    elif temporal:
        tier = "LOW"
    else:
        tier = "OUT_OF_SCOPE"

    return {
        "temporal_match": temporal,
        "entity_match": entity,
        "causal_match": causal,
        "relevance_score": round(score, 2),
        "relevance_tier": tier,
        "in_scope": tier != "OUT_OF_SCOPE",
    }


def filter_facts_by_relevance(graph, scope):
    in_scope, out_of_scope = [], []
    for u, v, data in graph.g.edges(data=True):
        relevance = assess_relevance(u, data.get("relation"), v, data.get("timestamp"), graph, scope)
        record = {
            "subject": u, "relation": data.get("relation"), "object": v,
            "timestamp": data.get("timestamp"), "log_source": data.get("log_source"),
            "relevance": relevance,
        }
        (in_scope if relevance["in_scope"] else out_of_scope).append(record)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope}


if __name__ == "__main__":
    import json
    from fact_extractor import extract_facts_from_session
    from sysmon_fact_extractor import extract_facts_from_sysmon_xml
    from graph_builder import build_graph

    with open("devl/samples/demo_session_payload_delivery.json", "r", encoding="utf-8") as f:
        session = json.load(f)
    honeypot_facts, _, _ = extract_facts_from_session(session)
    sysmon_facts, _, _ = extract_facts_from_sysmon_xml("data/sysmon_source/sample_process_lineage.xml")
    graph = build_graph(honeypot_facts + sysmon_facts)

    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    scope = InvestigationScope(
        incident_id="SELFTEST-INC-1",
        affected_entities={"198.51.100.155", ps},
        window_start="2026-07-01T00:42:00Z",
        window_end="2026-07-01T00:43:00Z",
    )

    result = filter_facts_by_relevance(graph, scope)
    print(f"In scope: {len(result['in_scope'])}  |  Out of scope: {len(result['out_of_scope'])}\n")
    print("IN SCOPE:")
    for r in result["in_scope"]:
        rel = r["relevance"]
        print(f"  [{rel['relevance_tier']}, score={rel['relevance_score']}] {r['subject']} {r['relation']} {r['object']}")
    print("\nOUT OF SCOPE (real data, but not relevant to THIS investigation):")
    for r in result["out_of_scope"]:
        print(f"  {r['subject']} {r['relation']} {r['object']}")
