from conftest import IP
from fact_extractor import extract_facts_from_session
from graph_builder import build_graph
from claim_parser import parse_explanation
from coverage_checker import find_unaccounted_evidence, detect_timestamp_gaps


def test_a_true_but_partial_explanation_leaves_real_evidence_unaccounted(session):
    """The central distinction this project is built around: an explanation
    can be 100% true and still miss real evidence."""
    facts, _, _ = extract_facts_from_session(session)
    graph = build_graph(facts)
    claims = parse_explanation(f"{IP} connected to ssh:22. {IP} authenticated as svc23.").claims
    unaccounted = find_unaccounted_evidence(graph, claims)
    relations = {u["relation"] for u in unaccounted}
    assert relations == {"EXECUTED", "DOWNLOADED_PAYLOAD", "DISCONNECTED_FROM"}


def test_an_explanation_covering_everything_leaves_nothing_unaccounted(session):
    facts, _, _ = extract_facts_from_session(session)
    graph = build_graph(facts)
    text = (f"{IP} connected to ssh:22. {IP} authenticated as svc23. "
            f"{IP} executed the command 'uname -a && id'. "
            f"{IP} downloaded a malicious payload with hash 6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8. "
            f"{IP} disconnected from ssh:22.")
    claims = parse_explanation(text).claims
    assert find_unaccounted_evidence(graph, claims) == []


def test_no_gaps_at_the_realistic_default_threshold(session):
    """Real events in this session are 1-2 seconds apart -- genuinely no gap."""
    facts, _, _ = extract_facts_from_session(session)
    assert detect_timestamp_gaps(facts) == []


def test_gap_detector_actually_fires_at_a_sensitive_threshold(session):
    """Proves the zero-gaps result above reflects real data, not a broken detector."""
    facts, _, _ = extract_facts_from_session(session)
    gaps = detect_timestamp_gaps(facts, threshold_seconds=0.5)
    assert len(gaps) == 4
    assert all(g["gap_seconds"] >= 1.0 for g in gaps)


def test_gap_detector_never_treats_a_missing_timestamp_as_a_zero_second_gap(fresh):
    s = fresh()
    for e in s["events"]:
        if e["action"] == "command":
            del e["utc"]
    facts, _, _ = extract_facts_from_session(s)
    # should not crash, and the untimestamped fact must be excluded from gap math
    gaps = detect_timestamp_gaps(facts, threshold_seconds=0.1)
    for g in gaps:
        assert "uname" not in g["after_event"] and "uname" not in g["before_event"]
