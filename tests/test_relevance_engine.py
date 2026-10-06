import json
from pathlib import Path

import pytest

from fact_extractor import extract_facts_from_session
from sysmon_fact_extractor import extract_facts_from_sysmon_xml
from graph_builder import build_graph
from claim_parser import parse_explanation
from coverage_checker import find_unaccounted_evidence
from relevance_engine import InvestigationScope, assess_relevance, filter_facts_by_relevance

ROOT = Path(__file__).resolve().parent.parent
SYSMON_SAMPLE = ROOT / "data" / "sysmon_source" / "sample_process_lineage.xml"

IP = "198.51.100.155"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CHCP = r"C:\Windows\System32\chcp.com"
SVCHOST = r"C:\Windows\System32\svchost.exe"
UNSECAPP = r"C:\Windows\System32\wbem\unsecapp.exe"


@pytest.fixture
def combined_graph(session):
    honeypot_facts, _, _ = extract_facts_from_session(session)
    sysmon_facts, _, _ = extract_facts_from_sysmon_xml(str(SYSMON_SAMPLE))
    return build_graph(honeypot_facts + sysmon_facts), honeypot_facts + sysmon_facts


@pytest.fixture
def scope():
    return InvestigationScope(
        incident_id="INC-TEST-1",
        affected_entities={IP, PS},
        window_start="2026-07-01T00:42:00Z",
        window_end="2026-07-01T00:43:00Z",
    )


# ---------- entity relevance ----------

def test_fact_involving_a_scoped_entity_is_entity_relevant(combined_graph, scope):
    graph, _ = combined_graph
    result = assess_relevance(IP, "CONNECTED_TO", "ssh:22", "2026-07-01T00:42:13Z", graph, scope)
    assert result["entity_match"] is True
    assert result["in_scope"] is True


def test_fact_with_no_scoped_entity_is_not_entity_relevant(combined_graph, scope):
    graph, _ = combined_graph
    result = assess_relevance(SVCHOST, "SPAWNED", UNSECAPP, "2020-11-10 13:59:54.398", graph, scope)
    assert result["entity_match"] is False


# ---------- causal relevance (real process-lineage graph traversal) ----------

def test_process_directly_spawned_by_scoped_process_is_causally_relevant(combined_graph, scope):
    graph, _ = combined_graph
    # chcp.com itself is not in affected_entities, but IS reachable from
    # the scoped powershell.exe via a real SPAWNED edge.
    result = assess_relevance(PS, "SPAWNED", CHCP, "2020-11-10 13:59:56.687", graph, scope)
    assert result["causal_match"] is True
    assert result["entity_match"] is True  # PS itself is also a scoped entity here
    assert result["relevance_tier"] == "HIGH"


def test_unrelated_os_housekeeping_process_is_not_causally_relevant(combined_graph, scope):
    graph, _ = combined_graph
    result = assess_relevance(SVCHOST, "SPAWNED", UNSECAPP, "2020-11-10 13:59:54.398", graph, scope)
    assert result["causal_match"] is False
    assert result["in_scope"] is False
    assert result["relevance_tier"] == "OUT_OF_SCOPE"


# ---------- temporal relevance ----------

def test_timestamp_outside_the_window_is_not_temporally_relevant(combined_graph):
    graph, _ = combined_graph
    narrow_scope = InvestigationScope(
        incident_id="INC-NARROW", affected_entities=set(),
        window_start="2026-07-01T00:42:00Z", window_end="2026-07-01T00:42:05Z",
    )
    result = assess_relevance(IP, "DISCONNECTED_FROM", "ssh:22", "2026-07-01T00:42:18Z", graph, narrow_scope)
    assert result["temporal_match"] is False


def test_no_window_declared_gives_none_not_a_silent_pass_or_fail(combined_graph):
    graph, _ = combined_graph
    no_window_scope = InvestigationScope(incident_id="INC-NOWIN", affected_entities={IP})
    result = assess_relevance(IP, "CONNECTED_TO", "ssh:22", "2026-07-01T00:42:13Z", graph, no_window_scope)
    assert result["temporal_match"] is None


def test_mixed_timezone_aware_and_naive_timestamps_do_not_crash(combined_graph, scope):
    """Regression: honeypot timestamps are tz-aware ('...Z'), Sysmon's are
    naive -- comparing them used to raise TypeError the moment real data
    from both sources was combined under one scope."""
    graph, _ = combined_graph
    result = assess_relevance(PS, "SPAWNED", CHCP, "2020-11-10 13:59:56.687", graph, scope)
    assert result["relevance_score"] >= 0  # didn't raise


# ---------- the two-question integration with coverage_checker ----------

def test_scoped_unaccounted_evidence_excludes_real_but_unrelated_noise(combined_graph):
    graph, all_facts = combined_graph
    scope = InvestigationScope(
        incident_id="INC-TEST-2", affected_entities={IP, PS},
        window_start="2026-07-01T00:42:00Z", window_end="2026-07-01T00:43:00Z",
    )
    explanation = f"{IP} connected to ssh:22. {IP} authenticated as svc23."
    claims = parse_explanation(explanation).claims

    scoped = find_unaccounted_evidence(graph, claims, scope=scope)
    unscoped = find_unaccounted_evidence(graph, claims)

    scoped_triples = {(u["subject"], u["relation"], u["object"]) for u in scoped}
    assert (SVCHOST, "SPAWNED", UNSECAPP) not in scoped_triples  # real OS noise, correctly excluded
    assert len(scoped) < len(unscoped)  # scoping genuinely narrows the result


def test_scoped_unaccounted_evidence_still_catches_real_in_scope_misses(combined_graph):
    graph, _ = combined_graph
    scope = InvestigationScope(
        incident_id="INC-TEST-3", affected_entities={IP, PS},
        window_start="2026-07-01T00:42:00Z", window_end="2026-07-01T00:43:00Z",
    )
    explanation = f"{IP} connected to ssh:22. {IP} authenticated as svc23."
    claims = parse_explanation(explanation).claims
    scoped = find_unaccounted_evidence(graph, claims, scope=scope)
    scoped_triples = {(u["subject"], u["relation"], u["object"]) for u in scoped}
    assert (PS, "SPAWNED", CHCP) in scoped_triples  # real, in-scope, genuinely missed


def test_each_unaccounted_item_carries_its_own_relevance_explanation(combined_graph):
    graph, _ = combined_graph
    scope = InvestigationScope(incident_id="INC-TEST-4", affected_entities={IP, PS},
                                window_start="2026-07-01T00:42:00Z", window_end="2026-07-01T00:43:00Z")
    claims = parse_explanation(f"{IP} connected to ssh:22.").claims
    scoped = find_unaccounted_evidence(graph, claims, scope=scope)
    assert all("relevance" in u and "relevance_tier" in u["relevance"] for u in scoped)


# ---------- filter_facts_by_relevance ----------

def test_filter_facts_by_relevance_partitions_the_real_combined_graph(combined_graph, scope):
    graph, all_facts = combined_graph
    result = filter_facts_by_relevance(graph, scope)
    assert len(result["in_scope"]) + len(result["out_of_scope"]) == graph.edge_count()
    assert len(result["out_of_scope"]) > 0  # real OS noise exists and is excluded
    assert len(result["in_scope"]) > 0


def test_weights_are_disclosed_not_an_ml_score():
    from relevance_engine import RELEVANCE_WEIGHTS
    assert sum(RELEVANCE_WEIGHTS.values()) == pytest.approx(1.0)


# ---------- scoped timestamp-gap detection (coverage_checker integration) ----------

def test_scoped_gap_detection_excludes_cross_era_unrelated_datasets(combined_graph, scope):
    """Regression: combining this project's 2026 honeypot data and a real
    2020 Sysmon sample without scoping produced a ~177-million-second
    'gap' that reflected two unrelated real datasets, not evidence
    incompleteness. Scoping by both entity AND the declared time window
    must exclude the out-of-window facts before gap math runs."""
    from coverage_checker import detect_timestamp_gaps
    _, all_facts = combined_graph
    gaps = detect_timestamp_gaps(all_facts, scope=scope)
    assert all(g["gap_seconds"] < 100000 for g in gaps)  # no cross-era artifact


def test_unscoped_gap_detection_does_show_the_cross_era_artifact(combined_graph):
    """Confirms the bug was real (not assumed) -- without scope, the huge
    gap genuinely appears, which is exactly why scoping was needed."""
    from coverage_checker import detect_timestamp_gaps
    _, all_facts = combined_graph
    gaps = detect_timestamp_gaps(all_facts)
    assert any(g["gap_seconds"] > 100_000_000 for g in gaps)
