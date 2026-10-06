"""
custody_bridge.py

Connects DEVL's Reason Slates to the existing custody system
(custody/custody_cli.py), per the requested improvement: when an
analyst's decision + reasoning produces a Reason Slate, that complete
record -- decision, reasoning, evidence DEVL evaluated, DEVL's
findings, timestamp, and evidence/audit digests -- should be sealable
into the SAME tamper-evident hash chain the custody tool already
provides for response audit logs, rather than being a second, unrelated
artifact sitting beside it.

This module does NOT reimplement hashing/signing -- it imports and
reuses the real `seal_entries()` and `build_chain()` functions from
custody/custody_cli.py directly, so there is exactly one hash-chaining
implementation in this repository, not two that could drift apart.

Design: each Reason Slate becomes ONE entry in a running,
append-only "decision custody log" (JSONL, same shape the custody CLI
already reads). Sealing that log produces a sealed_case exactly like
sealing a response audit log does -- reusing one mental model across
both response-action custody (D-008) and decision-verification custody
(this module), rather than inventing a second one.
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

DEVL_DIR = Path(__file__).resolve().parent
ROOT = DEVL_DIR.parent
sys.path.insert(0, str(ROOT / "custody"))

from custody_cli import seal_entries, build_chain  # noqa: E402  (real, reused implementation)

DEFAULT_DECISION_LOG_PATH = ROOT / "custody" / "decision_custody_log.jsonl"


class CustodyBridgeError(Exception):
    pass


def _slate_to_custody_entry(slate: dict) -> dict:
    """
    Reduces a Reason Slate to the fields worth custody-sealing:
    decision, reasoning, evidence findings, and both digests. Excludes
    nothing required to reconstruct WHY the verification outcome was
    reached -- this is deliberately closer to "the whole slate" than a
    summary, since the point of sealing is to protect the complete
    record, not a lossy excerpt of it.
    """
    return {
        "record_type": "devl_decision_verification",
        "alert_id": slate["alert_id"],
        "generated_at_utc": slate["generated_at_utc"],
        "analyst_decision": slate.get("analyst_decision"),
        "explanation_text": slate["explanation_text"],
        "verification_outcome": slate["verification_outcome"],
        "decision_support": slate["decision_support"],
        "explanation_integrity": slate["explanation_integrity"],
        "evidence_coverage": slate["evidence_coverage"],
        "evidence_completeness": slate["evidence_completeness"],
        "parsing_coverage": slate["parsing_coverage"],
        "evidence_integrity_assessment": slate["evidence_integrity_assessment"],
        "telemetry_graph_hash": slate["telemetry_graph_hash"],
        "evidence_digest": slate["evidence_digest"],
        "audit_digest": slate["audit_digest"],
    }


def append_to_decision_log(slate: dict, log_path: Path = DEFAULT_DECISION_LOG_PATH) -> dict:
    """
    Appends one Reason Slate to the running decision custody log (JSONL,
    one entry per line -- same format the custody CLI's `seal` command
    reads). Returns the entry that was written.
    """
    entry = _slate_to_custody_entry(slate)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")
    return entry


def read_decision_log(log_path: Path = DEFAULT_DECISION_LOG_PATH) -> list:
    if not log_path.exists():
        return []
    entries = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def seal_decision_log(log_path: Path = DEFAULT_DECISION_LOG_PATH, sign: bool = False, keyfile: str = None) -> dict:
    """
    Seals the ENTIRE current decision custody log into one sealed_case,
    using the real custody hash-chain/signing logic (seal_entries, from
    custody/custody_cli.py -- not reimplemented here).
    """
    entries = read_decision_log(log_path)
    if not entries:
        raise CustodyBridgeError(f"Decision custody log at {log_path} is empty -- nothing to seal.")
    return seal_entries(entries, source_label=str(log_path.resolve()), sign=sign, keyfile=keyfile)


def append_and_reseal(slate: dict, log_path: Path = DEFAULT_DECISION_LOG_PATH,
                       sealed_output_path: Path = None, sign: bool = False, keyfile: str = None) -> dict:
    """
    Convenience wrapper: append this Reason Slate to the decision
    custody log, then immediately re-seal the whole (now-larger) log --
    so every `verify --seal` call leaves behind an up-to-date sealed
    case covering every decision verified so far in this log, not just
    the latest one. Optionally writes the sealed case to disk.
    """
    append_to_decision_log(slate, log_path)
    sealed_case = seal_decision_log(log_path, sign=sign, keyfile=keyfile)
    if sealed_output_path:
        with open(sealed_output_path, "w", encoding="utf-8") as f:
            json.dump(sealed_case, f, indent=2, default=str)
    return sealed_case


if __name__ == "__main__":
    # Self-test: build 2 real Reason Slates (one clean, one with a real
    # contradiction) from the real demo session, seal them into a decision
    # custody log, verify the chain, then prove tampering is still caught
    # -- using the SAME custody_cli functions the response-action custody
    # log already relies on (D-008), applied here to decision records.
    import tempfile
    import pandas as pd

    sys.path.insert(0, str(DEVL_DIR))
    from fact_extractor import extract_facts_from_session
    from graph_builder import build_graph
    from claim_parser import parse_explanation
    from evidence_matcher import verify_claims
    from mismatch_engine import compute_integrity
    from coverage_checker import find_unaccounted_evidence, detect_timestamp_gaps
    from reason_slate import generate_reason_slate

    with open(DEVL_DIR / "samples" / "demo_session_payload_delivery.json", "r", encoding="utf-8") as f:
        session = json.load(f)
    facts, _, _ = extract_facts_from_session(session)
    graph = build_graph(facts)

    def make_slate(explanation, decision, alert_id):
        parsed = parse_explanation(explanation)
        verdicts = verify_claims(parsed.claims, graph)
        report = compute_integrity(verdicts)
        return generate_reason_slate(
            alert_id=alert_id, explanation_text=explanation, graph=graph, report=report,
            analyst_decision=decision,
            unaccounted_evidence=find_unaccounted_evidence(graph, parsed.claims),
            timestamp_gaps=detect_timestamp_gaps(facts),
            unparsed_fragments=parsed.unparsed_fragments,
        )

    slate_a = make_slate("198.51.100.155 connected to ssh:22. 198.51.100.155 authenticated as svc23.",
                          "CLOSE", "SELFTEST-A")
    slate_b = make_slate("198.51.100.155 connected to ssh:22. 198.51.100.155 failed to authenticate as svc23.",
                          "FALSE_POSITIVE", "SELFTEST-B")

    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "decision_custody_log.jsonl"
        sealed_out = Path(tmp) / "sealed_decisions.json"

        sealed1 = append_and_reseal(slate_a, log_path=log_path, sealed_output_path=sealed_out)
        print(f"After 1 slate: {sealed1['entry_count']} entries sealed, root hash {sealed1['root_hash'][:16]}...")

        sealed2 = append_and_reseal(slate_b, log_path=log_path, sealed_output_path=sealed_out)
        print(f"After 2 slates: {sealed2['entry_count']} entries sealed, root hash {sealed2['root_hash'][:16]}...")
        assert sealed2["entry_count"] == 2

        # Verify chain integrity using the SAME build_chain function --
        # not a reimplementation.
        recomputed_chain = build_chain(read_decision_log(log_path))
        assert recomputed_chain[-1]["link_hash"] == sealed2["root_hash"]
        print("PASS: recomputed chain matches sealed root hash.")

        # Tamper test: alter one entry's stated decision after sealing.
        with open(sealed_out, "r", encoding="utf-8") as f:
            sealed_case = json.load(f)
        sealed_case["entries"][0]["analyst_decision"]["stated_decision"] = "ESCALATE"
        tampered_chain = build_chain(sealed_case["entries"])
        tamper_detected = tampered_chain[-1]["link_hash"] != sealed_case["root_hash"]
        print(f"Tamper detected after altering a sealed decision: {tamper_detected}")
        assert tamper_detected

    print("\nAll custody_bridge self-tests passed.")
