import pytest

from conftest import IP, REAL_HASH, FAKE_HASH
from fact_extractor import extract_facts_from_session, Relation
from graph_builder import build_graph
from claim_parser import parse_explanation
from evidence_matcher import verify_claims, ClaimStatus
from mismatch_engine import compute_integrity


@pytest.fixture
def graph(session):
    facts, _, _ = extract_facts_from_session(session)
    return build_graph(facts)


def _verdicts(text, graph):
    return verify_claims(parse_explanation(text).claims, graph)


# ---------- evidence matcher ----------

def test_true_claim_is_verified_with_real_provenance(graph):
    (v,) = _verdicts(f"{IP} connected to ssh:22.", graph)
    assert v.status == ClaimStatus.VERIFIED
    assert v.matched_evidence[0]["timestamp"] == "2026-07-01T00:42:13Z"
    assert v.matched_evidence[0]["log_source"] == "network_session_log"


def test_fabricated_hash_is_unsupported(graph):
    (v,) = _verdicts(f"{IP} downloaded a malicious payload with hash {FAKE_HASH}.", graph)
    assert v.status == ClaimStatus.UNSUPPORTED


def test_claim_opposite_to_real_telemetry_is_contradicted(graph):
    """The telemetry shows a SUCCESSFUL auth as svc23; claiming it failed contradicts that."""
    (v,) = _verdicts(f"{IP} failed to authenticate as svc23.", graph)
    assert v.status == ClaimStatus.CONTRADICTED


def test_claim_needing_an_uncollected_log_source_is_missing_telemetry(session):
    facts, _, _ = extract_facts_from_session(session)
    partial = build_graph([f for f in facts if f.relation != Relation.DOWNLOADED_PAYLOAD])
    (v,) = _verdicts(f"{IP} downloaded a malicious payload with hash {REAL_HASH}.", partial)
    assert v.status == ClaimStatus.MISSING_TELEMETRY


def test_missing_telemetry_is_distinct_from_unsupported(session, graph):
    """Same claim: UNSUPPORTED when the log source WAS collected, MISSING when it wasn't."""
    text = f"{IP} downloaded a malicious payload with hash {FAKE_HASH}."
    (with_source,) = _verdicts(text, graph)
    facts, _, _ = extract_facts_from_session(session)
    without = build_graph([f for f in facts if f.relation != Relation.DOWNLOADED_PAYLOAD])
    (no_source,) = _verdicts(text, without)
    assert with_source.status == ClaimStatus.UNSUPPORTED
    assert no_source.status == ClaimStatus.MISSING_TELEMETRY


def test_every_atomic_claim_in_a_mixed_sentence_is_checked_independently(graph):
    """The review's 'mixed supported/unsupported' case: true, true, then fabricated."""
    text = (f"{IP} connected to ssh:22 and authenticated as svc23 "
            f"and downloaded a malicious payload with hash {FAKE_HASH}.")
    statuses = [v.status for v in _verdicts(text, graph)]
    assert statuses.count(ClaimStatus.VERIFIED) == 2
    assert statuses.count(ClaimStatus.UNSUPPORTED) == 1


def test_a_claim_about_a_different_ip_is_not_verified(graph):
    (v,) = _verdicts("203.0.113.9 connected to ssh:22.", graph)
    assert v.status != ClaimStatus.VERIFIED


# ---------- mismatch engine: the exact formula ----------

def test_all_verified_scores_one(graph):
    r = compute_integrity(_verdicts(f"{IP} connected to ssh:22. {IP} authenticated as svc23.", graph))
    assert r.integrity_score == 1.0
    assert r.status == "EXPLANATION_FULLY_SUPPORTED"
    assert r.flags == []


def test_one_unsupported_among_four_scores_point_eight(graph):
    text = (f"{IP} connected to ssh:22. {IP} authenticated as svc23. "
            f"{IP} executed the command 'uname -a && id'. "
            f"{IP} downloaded a malicious payload with hash {FAKE_HASH}.")
    r = compute_integrity(_verdicts(text, graph))
    # 3 verified / (3 verified + 1 unsupported) = 0.75
    assert r.integrity_score == 0.75
    assert "EXPLANATION_HALLUCINATION_WARNING" in r.flags


def test_contradiction_is_weighted_twice_as_heavily_as_an_unsupported_claim(graph):
    text = (f"{IP} connected to ssh:22. {IP} authenticated as svc23. "
            f"{IP} executed the command 'uname -a && id'. "
            f"{IP} downloaded a malicious payload with hash {REAL_HASH}. "
            f"{IP} failed to authenticate as svc23.")
    r = compute_integrity(_verdicts(text, graph))
    # 4 / (4 + 2*1) = 0.666...
    assert r.integrity_score == 0.67
    assert "CONTRADICTORY_EVIDENCE_DETECTED" in r.flags


def test_alpha_is_configurable(graph):
    text = f"{IP} connected to ssh:22. {IP} failed to authenticate as svc23."
    v = _verdicts(text, graph)
    assert compute_integrity(v, alpha=1.0).integrity_score == 0.5     # 1/(1+1)
    assert compute_integrity(v, alpha=3.0).integrity_score == 0.25    # 1/(1+3)


def test_missing_telemetry_alone_gives_partial_verification_not_a_mismatch(session):
    facts, _, _ = extract_facts_from_session(session)
    partial = build_graph([f for f in facts if f.relation != Relation.DOWNLOADED_PAYLOAD])
    r = compute_integrity(_verdicts(f"{IP} downloaded a malicious payload with hash {REAL_HASH}.", partial))
    assert r.status == "PARTIAL_VERIFICATION_ONLY"
    assert "TELEMETRY_GAP_DETECTED" in r.flags


def test_no_claims_at_all_does_not_divide_by_zero():
    assert compute_integrity([]).integrity_score == 0.0
