"""
evidence_matcher.py

Component 4 of DEVL: Deterministic Evidence Matcher.

Queries the real TelemetryGraph (Component 2) for each parsed Claim
(Component 3), classifying it per the DEVL spec:
  VERIFIED         -- exact matching edge exists in the graph
  CONTRADICTED      -- an explicit contradiction rule fires (see below)
  UNSUPPORTED       -- required log source was active, but no matching
                       edge exists -- the claimed event did not happen
  MISSING_TELEMETRY -- the log source needed to check this claim was
                       never active for this graph at all

This is pure deterministic logic -- graph lookups and set membership
checks, no ML/LLM involved in the classification itself. This is
INTENTIONAL: this is the layer whose entire job is to be trustworthy
verification, so it must not itself be a system capable of "plausible
but wrong" output.
"""

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from claim_parser import Claim
from graph_builder import TelemetryGraph


class ClaimStatus:
    VERIFIED = "VERIFIED"
    CONTRADICTED = "CONTRADICTED"
    UNSUPPORTED = "UNSUPPORTED"
    MISSING_TELEMETRY = "MISSING_TELEMETRY"


# Contradiction rules: pairs of relations that are mutually exclusive
# for the SAME (subject, object) pair. If the graph contains the
# opposite relation for the exact same entities a claim references,
# that claim is CONTRADICTED rather than merely UNSUPPORTED -- a
# stronger, more specific signal (per the spec's worked example: an
# "unauthorized account" claim contradicted by an explicit
# "approved account" fact).
_CONTRADICTION_PAIRS = {
    "AUTHENTICATED_AS": "AUTH_FAILED_AS",
    "AUTH_FAILED_AS": "AUTHENTICATED_AS",
}


@dataclass
class ClaimVerdict:
    claim: Claim
    status: str
    note: str
    matched_evidence: list


def verify_claim(claim: Claim, graph: TelemetryGraph) -> ClaimVerdict:
    if claim.required_log not in graph.active_log_sources:
        return ClaimVerdict(
            claim=claim, status=ClaimStatus.MISSING_TELEMETRY,
            note=f"Log source '{claim.required_log}' was not active/collected for this graph -- "
                 f"cannot confirm or deny this claim.",
            matched_evidence=[],
        )

    matches = graph.get_matching_edges(claim.subject, claim.obj, claim.relation)
    if matches:
        return ClaimVerdict(
            claim=claim, status=ClaimStatus.VERIFIED,
            note=f"Matched {len(matches)} real telemetry event(s) supporting this exact claim.",
            matched_evidence=matches,
        )

    # Check for an explicit contradiction: same subject, DIFFERENT
    # object, but the opposite relation IS present -- e.g. claim says
    # "authenticated as admin" but graph shows "auth failed as admin"
    # for the same subject/object pair specifically.
    opposite_relation = _CONTRADICTION_PAIRS.get(claim.relation)
    if opposite_relation:
        contradicting = graph.get_matching_edges(claim.subject, claim.obj, opposite_relation)
        if contradicting:
            return ClaimVerdict(
                claim=claim, status=ClaimStatus.CONTRADICTED,
                note=f"Graph shows the OPPOSITE relation ({opposite_relation}) for this exact "
                     f"subject/object pair -- this claim directly conflicts with real telemetry.",
                matched_evidence=contradicting,
            )

    return ClaimVerdict(
        claim=claim, status=ClaimStatus.UNSUPPORTED,
        note=f"Log source '{claim.required_log}' WAS active, but no matching event exists. "
             f"This claim describes something that did not happen according to available telemetry.",
        matched_evidence=[],
    )


def verify_claims(claims: list, graph: TelemetryGraph) -> list:
    return [verify_claim(c, graph) for c in claims]


if __name__ == "__main__":
    # Self-test: real graph from the real demo session, real + fabricated
    # claims from claim_parser.py's own self-test text, run through the
    # matcher -- proves VERIFIED vs UNSUPPORTED discrimination actually
    # works end-to-end on real data.
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

    test_explanation = (
        "198.51.100.155 connected to ssh:22. "
        "198.51.100.155 authenticated as svc23. "
        "198.51.100.155 executed the command 'uname -a && id'. "
        "198.51.100.155 downloaded a malicious payload with hash 6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8. "
        "198.51.100.155 downloaded a malicious payload with hash deadbeef00000000000000000000000000000000000000000000000000000000. "
        "198.51.100.155 failed to authenticate as svc23."
    )
    parsed = parse_explanation(test_explanation)
    verdicts = verify_claims(parsed.claims, graph)

    print(f"Verified {len(verdicts)} claims against real graph ({graph.node_count()} nodes, {graph.edge_count()} edges):\n")
    for v in verdicts:
        print(f"[{v.status}] ({v.claim.subject}) --{v.claim.relation}--> ({v.claim.obj})")
        print(f"    {v.note}\n")
