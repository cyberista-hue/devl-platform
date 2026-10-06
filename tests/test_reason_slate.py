import copy
import time

import pytest

from conftest import IP, FAKE_HASH
from reason_slate import verify_slate_digest


# ---------- parsing coverage reaching the actual output (review's most important fix) ----------

def test_unparsed_text_appears_in_the_reason_slate_itself(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22. The attacker appears to have compromised the server.")
    assert slate["parsing_coverage"]["complete_claim_coverage"] is False
    assert "attacker appears to have compromised" in slate["parsing_coverage"]["unparsed_fragments"][0]


def test_unparsed_text_forces_human_review(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22. Some unrecognisable interpretive claim here.")
    assert slate["decision_support"]["human_review_required"] is True


def test_fully_parsed_and_fully_accounted_explanation_needs_no_review(pipeline):
    text = (f"{IP} connected to ssh:22. {IP} authenticated as svc23. "
            f"{IP} executed the command 'uname -a && id'. "
            f"{IP} downloaded a malicious payload with hash 6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8. "
            f"{IP} disconnected from ssh:22.")
    slate = pipeline(text)
    assert slate["parsing_coverage"]["complete_claim_coverage"] is True
    assert slate["decision_support"]["human_review_required"] is False


# ---------- the core "truthful but incomplete" distinction ----------

def test_true_but_incomplete_explanation_is_fully_supported_yet_needs_review(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22. {IP} authenticated as svc23.")
    assert slate["verification_outcome"] == "FULLY_SUPPORTED"
    assert slate["evidence_coverage"]["unaccounted_count"] == 3
    assert slate["decision_support"]["human_review_required"] is True


# ---------- analyst decision ----------

def test_decision_block_states_its_own_boundary(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22.", decision="CLOSE")
    d = slate["analyst_decision"]
    assert d["stated_decision"] == "CLOSE"
    assert d["reasoning_evidence_basis"] == "FULLY_SUPPORTED"
    assert "does NOT evaluate whether the chosen decision" in d["note"]


def test_no_decision_given_yields_no_decision_block(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22.")
    assert slate["analyst_decision"] is None


def test_invalid_decision_value_is_rejected(pipeline):
    with pytest.raises(ValueError):
        pipeline(f"{IP} connected to ssh:22.", decision="MAYBE")


# ---------- digest reproducibility and tamper detection ----------

def test_evidence_digest_is_reproducible_across_runs(pipeline):
    text = f"{IP} connected to ssh:22."
    slate1 = pipeline(text, decision="ESCALATE")
    time.sleep(1.1)
    slate2 = pipeline(text, decision="ESCALATE")
    assert slate1["telemetry_graph_hash"] == slate2["telemetry_graph_hash"]
    assert slate1["evidence_digest"] == slate2["evidence_digest"]
    assert slate1["audit_digest"] != slate2["audit_digest"]  # correctly still differs (has a timestamp)
    assert slate1["generated_at_utc"] != slate2["generated_at_utc"]


def test_verify_slate_digest_passes_on_an_untouched_slate(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22.", decision="ESCALATE")
    result = verify_slate_digest(slate)
    assert result["valid"] is True
    assert result["claimed"] == result["recomputed"]


def test_verify_slate_digest_fails_when_evidence_is_edited_after_generation(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22.", decision="ESCALATE")
    tampered = copy.deepcopy(slate)
    tampered["explanation_integrity"]["sample_size"]["unsupported"] = 99
    result = verify_slate_digest(tampered)
    assert result["valid"] is False
    assert result["claimed"] != result["recomputed"]


def test_verify_slate_digest_fails_if_the_decision_itself_is_edited(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22.", decision="CLOSE")
    tampered = copy.deepcopy(slate)
    tampered["analyst_decision"]["stated_decision"] = "FALSE_POSITIVE"
    result = verify_slate_digest(tampered)
    assert result["valid"] is False


# ---------- three-way evidence integrity assessment ----------

def test_complete_and_accurate_explanation_appears_complete(pipeline):
    text = (f"{IP} connected to ssh:22. {IP} authenticated as svc23. "
            f"{IP} executed the command 'uname -a && id'. "
            f"{IP} downloaded a malicious payload with hash 6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8. "
            f"{IP} disconnected from ssh:22.")
    slate = pipeline(text)
    assessment = slate["evidence_integrity_assessment"]
    assert assessment["completeness_status"] == "APPEARS_COMPLETE"
    assert assessment["contradicted_evidence"]["count"] == 0
    assert assessment["unaccounted_evidence"]["count"] == 0


def test_true_but_partial_explanation_shows_gaps_detected_not_contradicted(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22. {IP} authenticated as svc23.")
    assessment = slate["evidence_integrity_assessment"]
    assert assessment["completeness_status"] == "GAPS_DETECTED"
    assert assessment["unaccounted_evidence"]["count"] == 3
    assert assessment["contradicted_evidence"]["count"] == 0  # nothing was CONTRADICTED, just unmentioned


def test_unparseable_text_present_shows_assessment_incomplete_even_with_gaps(pipeline):
    """ASSESSMENT_INCOMPLETE takes priority over GAPS_DETECTED -- when part
    of the explanation couldn't even be checked, that's reported distinctly
    from ordinary evidence gaps, per the requested three-way distinction."""
    slate = pipeline(f"{IP} connected to ssh:22. Some uncheckable interpretive claim.")
    assessment = slate["evidence_integrity_assessment"]
    assert assessment["completeness_status"] == "ASSESSMENT_INCOMPLETE"


def test_contradicted_evidence_is_counted_distinctly_from_missing_or_unaccounted(pipeline):
    text = (f"{IP} connected to ssh:22. {IP} authenticated as svc23. "
            f"{IP} failed to authenticate as svc23.")
    assessment = pipeline(text)["evidence_integrity_assessment"]
    assert assessment["contradicted_evidence"]["count"] == 1
    assert assessment["missing_telemetry"]["count"] == 0


def test_assessment_is_covered_by_the_reproducible_evidence_digest(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22.")
    tampered = copy.deepcopy(slate)
    tampered["evidence_integrity_assessment"]["completeness_status"] = "APPEARS_COMPLETE"
    result = verify_slate_digest(tampered)
    assert result["valid"] is False


# ---------- text rendering ----------

def test_text_renderer_shows_supporting_contradicting_unaccounted_and_missing(pipeline):
    from reason_slate import render_reason_slate_text
    text = f"{IP} connected to ssh:22. {IP} authenticated as svc23. {IP} failed to authenticate as svc23."
    slate = pipeline(text, decision="CLOSE")
    rendered = render_reason_slate_text(slate)
    assert "Analyst Decision:" in rendered and "CLOSE" in rendered
    assert "Supporting Evidence (2)" in rendered
    assert "Contradicting Evidence (1)" in rendered
    assert "Unaccounted Evidence" in rendered
    assert "Evidence Integrity: GAPS_DETECTED" in rendered
    assert "Human Review Required: YES" in rendered


# ---------- investigation scope ----------

def test_investigation_scope_appears_in_the_slate(pipeline):
    from relevance_engine import InvestigationScope
    scope = InvestigationScope(incident_id="INC-X", affected_entities={IP}, window_start=None, window_end=None)
    slate = pipeline(f"{IP} connected to ssh:22.", decision="CLOSE")
    # pipeline fixture doesn't pass scope by default; just confirm the field exists and is None when not used
    assert "investigation_scope" in slate
    assert slate["investigation_scope"] is None


def test_scope_is_covered_by_the_reproducible_evidence_digest(pipeline):
    slate = pipeline(f"{IP} connected to ssh:22.")
    tampered = copy.deepcopy(slate)
    tampered["investigation_scope"] = {"incident_id": "FORGED", "affected_entities": [], "window_start": None, "window_end": None}
    result = verify_slate_digest(tampered)
    assert result["valid"] is False
