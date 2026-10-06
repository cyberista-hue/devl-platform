"""
Shared fixtures for the DEVL test suite.

All tests build from the REAL demo session in devl/samples/ (a JSON file
extracted from the actual Stage 6 telemetry), not from the parquet
dataset -- so the suite runs on any machine with just networkx + pytest,
no pyarrow required.
"""

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "devl"))

SAMPLES = ROOT / "devl" / "samples"

# The real values in the demo session -- asserted against, never invented.
IP = "198.51.100.155"
REAL_HASH = "6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8"
FAKE_HASH = "deadbeef" + "0" * 56


@pytest.fixture
def session():
    with open(SAMPLES / "demo_session_payload_delivery.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def fresh(session):
    """Returns a function that deep-copies the session, so a test can
    corrupt its copy without affecting any other test."""
    return lambda: copy.deepcopy(session)


@pytest.fixture
def pipeline(session):
    """Runs the full DEVL pipeline the same way the CLI's `verify` does."""
    from fact_extractor import extract_facts_from_session
    from graph_builder import build_graph
    from claim_parser import parse_explanation
    from evidence_matcher import verify_claims
    from mismatch_engine import compute_integrity
    from coverage_checker import find_unaccounted_evidence, detect_timestamp_gaps
    from reason_slate import generate_reason_slate

    def run(explanation, decision=None, sess=None):
        sess = sess or session
        facts, _, _ = extract_facts_from_session(sess)
        graph = build_graph(facts)
        parsed = parse_explanation(explanation)
        verdicts = verify_claims(parsed.claims, graph)
        report = compute_integrity(verdicts)
        return generate_reason_slate(
            alert_id="TEST", explanation_text=explanation, graph=graph, report=report,
            analyst_decision=decision,
            unaccounted_evidence=find_unaccounted_evidence(graph, parsed.claims),
            timestamp_gaps=detect_timestamp_gaps(facts),
            unparsed_fragments=parsed.unparsed_fragments,
        )
    return run
