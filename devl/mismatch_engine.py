"""
mismatch_engine.py

Component 5 of DEVL: Mismatch & Contradiction Engine.

Aggregates per-claim verdicts (Component 4's output) into an overall
Explanation Integrity Score and a set of mismatch flags, exactly per
the DEVL architecture spec's formula:

    I = |C_VERIFIED| / (|C_VERIFIED| + |C_UNSUPPORTED| + alpha * |C_CONTRADICTED|)

Contradicted claims are weighted by `alpha` (default 2, matching the
spec's worked pseudocode) so a single contradiction hurts the score
more than a single unsupported claim -- a contradiction is a stronger
signal of a wrong explanation than a merely-unconfirmed one.
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence_matcher import ClaimVerdict, ClaimStatus


@dataclass
class MismatchReport:
    integrity_score: float
    status: str
    flags: list
    verified: list
    contradicted: list
    unsupported: list
    missing_telemetry: list


def compute_integrity(verdicts: list, alpha: float = 2.0) -> MismatchReport:
    verified = [v for v in verdicts if v.status == ClaimStatus.VERIFIED]
    contradicted = [v for v in verdicts if v.status == ClaimStatus.CONTRADICTED]
    unsupported = [v for v in verdicts if v.status == ClaimStatus.UNSUPPORTED]
    missing = [v for v in verdicts if v.status == ClaimStatus.MISSING_TELEMETRY]

    denominator = len(verified) + len(unsupported) + (alpha * len(contradicted))
    integrity_score = (len(verified) / denominator) if denominator > 0 else 0.0

    flags = []
    if unsupported:
        flags.append("EXPLANATION_HALLUCINATION_WARNING")
    if contradicted:
        flags.append("CONTRADICTORY_EVIDENCE_DETECTED")
    if missing:
        flags.append("TELEMETRY_GAP_DETECTED")

    if contradicted:
        status = "EXPLANATION_MISMATCH_DETECTED"
    elif unsupported:
        status = "EXPLANATION_MISMATCH_DETECTED"
    elif missing:
        status = "PARTIAL_VERIFICATION_ONLY"
    else:
        status = "EXPLANATION_FULLY_SUPPORTED"

    return MismatchReport(
        integrity_score=round(integrity_score, 2),
        status=status,
        flags=flags,
        verified=verified,
        contradicted=contradicted,
        unsupported=unsupported,
        missing_telemetry=missing,
    )


if __name__ == "__main__":
    # Self-test: reuse the exact real+fabricated claim mix from
    # evidence_matcher.py's self-test, and confirm the integrity score
    # and flags come out as the math dictates -- computed, not asserted.
    import json
    import pandas as pd
    from fact_extractor import extract_facts_from_session
    from graph_builder import build_graph
    from claim_parser import parse_explanation
    from evidence_matcher import verify_claims

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

    # Case A: an explanation that is 100% accurate
    accurate_explanation = (
        "198.51.100.155 connected to ssh:22. "
        "198.51.100.155 authenticated as svc23. "
        "198.51.100.155 executed the command 'uname -a && id'. "
        "198.51.100.155 downloaded a malicious payload with hash 6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8."
    )
    verdicts_a = verify_claims(parse_explanation(accurate_explanation).claims, graph)
    report_a = compute_integrity(verdicts_a)
    print("=== Case A: fully accurate explanation ===")
    print(f"Integrity score: {report_a.integrity_score}  Status: {report_a.status}  Flags: {report_a.flags}")
    print()

    # Case B: an explanation with one fabricated claim mixed in with real ones
    hallucinated_explanation = accurate_explanation + (
        " 198.51.100.155 downloaded a malicious payload with hash "
        "deadbeef00000000000000000000000000000000000000000000000000000000."
    )
    verdicts_b = verify_claims(parse_explanation(hallucinated_explanation).claims, graph)
    report_b = compute_integrity(verdicts_b)
    print("=== Case B: explanation with one fabricated claim ===")
    print(f"Integrity score: {report_b.integrity_score}  Status: {report_b.status}  Flags: {report_b.flags}")
    print(f"Unsupported claims: {[(v.claim.relation, v.claim.obj) for v in report_b.unsupported]}")
    print()

    # Case C: an explanation that directly contradicts real telemetry
    contradicted_explanation = accurate_explanation + " 198.51.100.155 failed to authenticate as svc23."
    verdicts_c = verify_claims(parse_explanation(contradicted_explanation).claims, graph)
    report_c = compute_integrity(verdicts_c)
    print("=== Case C: explanation contradicting real telemetry ===")
    print(f"Integrity score: {report_c.integrity_score}  Status: {report_c.status}  Flags: {report_c.flags}")
