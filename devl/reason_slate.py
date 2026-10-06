"""
reason_slate.py

Component 6 of DEVL: Reproducible Reason Slate Generator.

Assembles the final output structure per the DEVL spec's Sample Output
schema -- verified/contradictory/unsupported evidence breakdown, an
integrity score, and a SHA-256 audit digest binding the exact graph
state and claim set this Reason Slate was computed from, for
independent reproducibility (a third party can rebuild the same graph
from the same raw telemetry and confirm the digest matches).
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mismatch_engine import MismatchReport
from graph_builder import TelemetryGraph


def _claim_to_dict(claim) -> dict:
    return {
        "subject": claim.subject,
        "relation": claim.relation,
        "object": claim.obj,
        "required_log": claim.required_log,
        "raw_text": claim.raw_text,
    }


def _verdict_to_dict(verdict, include_evidence: bool = True) -> dict:
    d = {
        "claim": _claim_to_dict(verdict.claim),
        "status": verdict.status,
        "note": verdict.note,
    }
    if include_evidence and verdict.matched_evidence:
        d["matched_evidence"] = [
            {
                "relation": e.get("relation"),
                "timestamp": e.get("timestamp"),
                "log_source": e.get("log_source"),
                "session_id": e.get("session_id"),
            }
            for e in verdict.matched_evidence
        ]
    return d


DECISION_CHOICES = {"ESCALATE", "CLOSE", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"}


def assess_evidence_integrity(report, unaccounted_evidence: list, timestamp_gaps: list, unparsed_fragments: list) -> dict:
    """
    Distinguishes three genuinely different situations that are easy to
    blur together if only a single pass/fail verdict is shown:

      1. CONTRADICTED evidence -- evidence EXISTS and directly disagrees
         with a stated claim (report.contradicted).
      2. MISSING telemetry / gaps -- something about the evidence itself
         is incomplete: a log source was never collected for a specific
         claim (report.missing_telemetry), an unusually large gap
         between recorded events (timestamp_gaps), or real evidence
         that exists but the explanation never referenced at all
         (unaccounted_evidence).
      3. Assessment cannot be fully completed -- part of the
         EXPLANATION itself could not be decomposed into a checkable
         claim (unparsed_fragments), so DEVL cannot state that its
         picture of what the analyst claimed is complete, separate from
         whether the evidence itself has gaps.

    HONEST BOUNDARY, stated in the output every time: this function
    describes patterns in evidence DEVL actually received. It cannot
    detect evidence that was deleted, altered, or never collected
    before reaching this system -- that would require independent
    corroborating evidence of tampering (e.g. a log-clearing event
    actually present in telemetry), which this project's real data does
    not contain any examples of. See docs/decision-log.md for what was
    deliberately NOT built here and why.
    """
    contradicted_count = len(report.contradicted)
    missing_telemetry_count = len(report.missing_telemetry)
    unaccounted_count = len(unaccounted_evidence or [])
    gap_count = len(timestamp_gaps or [])
    unparsed_count = len(unparsed_fragments or [])

    if unparsed_count > 0:
        completeness_status = "ASSESSMENT_INCOMPLETE"
    elif missing_telemetry_count > 0 or gap_count > 0 or unaccounted_count > 0:
        completeness_status = "GAPS_DETECTED"
    else:
        completeness_status = "APPEARS_COMPLETE"

    return {
        "contradicted_evidence": {
            "count": contradicted_count,
            "meaning": "Evidence EXISTS and directly disagrees with a stated claim.",
        },
        "missing_telemetry": {
            "count": missing_telemetry_count,
            "meaning": "The log source needed to check a specific claim was never "
                       "collected -- genuinely unknown, not false.",
        },
        "unaccounted_evidence": {
            "count": unaccounted_count,
            "meaning": "Real evidence exists in the telemetry but the explanation "
                       "never referenced it at all.",
        },
        "timestamp_gaps": {
            "count": gap_count,
            "meaning": "Unusually large gaps between consecutive recorded events -- "
                       "a prompt for review, not a tampering claim.",
        },
        "completeness_status": completeness_status,
        "note": (
            "DEVL can only assess evidence it actually received. It cannot detect "
            "evidence that was deleted, altered, or never collected before reaching "
            "this system. GAPS_DETECTED means a specific, identifiable pattern was "
            "found in the evidence that IS present (missing telemetry, a timestamp "
            "gap, or unreferenced evidence). ASSESSMENT_INCOMPLETE means part of the "
            "explanation itself could not even be evaluated -- these are different "
            "situations and are reported separately, not collapsed into one flag."
        ),
    }


def generate_reason_slate(
    alert_id: str,
    explanation_text: str,
    graph: TelemetryGraph,
    report: MismatchReport,
    verification_outcome_override: str = None,
    analyst_decision: str = None,
    unaccounted_evidence: list = None,
    timestamp_gaps: list = None,
    unparsed_fragments: list = None,
    investigation_scope=None,
) -> dict:
    """
    Builds the final Reason Slate.

    `investigation_scope` (optional, an InvestigationScope from
    relevance_engine.py): when given, its declared boundary (incident
    ID, affected entities, time window) is recorded in the slate, and
    `unaccounted_evidence` is understood to already be the SCOPED
    result (see coverage_checker.find_unaccounted_evidence's `scope`
    parameter) -- i.e. real-but-unrelated facts were excluded before
    reaching this slate at all, per the Question A / Question B design.

    Produces TWO distinct digests, deliberately kept separate (fix for
    a real issue found in review: the original single "audit_digest"
    included generated_at_utc INSIDE the hashed content, which meant
    re-running verification on the exact same telemetry and explanation
    produced a DIFFERENT digest every time -- directly contradicting
    the claimed "independent reproducibility"):

      - evidence_digest: hashes ONLY evidence-identity content (the
        graph hash, the explanation text, and every claim verdict).
        Given the same telemetry + the same explanation + the same
        verification code, this digest is genuinely reproducible by a
        third party, at any time -- this is the one to cite for
        reproducibility claims.
      - audit_digest: hashes the evidence_digest together with
        record-creation metadata (generated_at_utc, alert_id). This
        one is EXPECTED to differ between runs/records -- it identifies
        a specific instance of the record, not the evidence itself.
    """
    if verification_outcome_override is None:
        # Renamed per review feedback: this component determines whether
        # an explanation's factual claims are supported by evidence --
        # it deliberately does NOT decide whether to escalate an alert,
        # since that decision needs inputs this layer doesn't have
        # (severity, asset criticality, policy, analyst workload, etc).
        # "ESCALATE" was too strong a claim for what's actually verified
        # here; verification_outcome states only what was checked.
        outcome_map = {
            "EXPLANATION_FULLY_SUPPORTED": "FULLY_SUPPORTED",
            "EXPLANATION_MISMATCH_DETECTED": "MISMATCH_DETECTED",
            "PARTIAL_VERIFICATION_ONLY": "PARTIAL_VERIFICATION_ONLY",
        }
        verification_outcome = outcome_map.get(report.status, "UNKNOWN")
    else:
        verification_outcome = verification_outcome_override

    if analyst_decision is not None and analyst_decision not in DECISION_CHOICES:
        raise ValueError(f"analyst_decision '{analyst_decision}' not in allowed set {DECISION_CHOICES}")

    graph_hash = graph.hash()

    evidence_breakdown = {
        "supporting": [_verdict_to_dict(v) for v in report.verified],
        "contradictory": [_verdict_to_dict(v) for v in report.contradicted],
        "unsupported_claims": [_verdict_to_dict(v) for v in report.unsupported],
        "telemetry_gaps": [_verdict_to_dict(v, include_evidence=False) for v in report.missing_telemetry],
    }

    # Evidence-identity content ONLY -- no timestamps, no alert_id.
    # Same telemetry + same explanation + same decision + same code =>
    # same digest, always, regardless of when or how many times this is
    # run. analyst_decision, unaccounted_evidence, timestamp_gaps, and
    # unparsed_fragments are all included here (not just as metadata)
    # because they are all themselves deterministic outputs of the same
    # evidence + input -- reproducibility should cover them too, not
    # just the claim verdicts.
    scope_summary = None
    if investigation_scope is not None:
        scope_summary = {
            "incident_id": investigation_scope.incident_id,
            "affected_entities": sorted(investigation_scope.affected_entities),
            "window_start": investigation_scope.window_start,
            "window_end": investigation_scope.window_end,
        }

    evidence_identity = {
        "explanation_text": explanation_text,
        "investigation_scope": scope_summary,
        "analyst_decision": (
            {"stated_decision": analyst_decision, "reasoning_evidence_basis": verification_outcome}
            if analyst_decision is not None else None
        ),
        "telemetry_graph_hash": graph_hash,
        "evidence_breakdown": evidence_breakdown,
        "explanation_integrity": {
            "score": report.integrity_score,
            "status": report.status,
            "flags": report.flags,
            "sample_size": {
                "verified": len(report.verified),
                "contradicted": len(report.contradicted),
                "unsupported": len(report.unsupported),
                "missing_telemetry": len(report.missing_telemetry),
            },
        },
        "evidence_coverage": {
            "unaccounted_evidence": unaccounted_evidence or [],
            "unaccounted_count": len(unaccounted_evidence) if unaccounted_evidence else 0,
            "note": (
                "Real facts present in the telemetry graph that the "
                "explanation never referenced -- not wrong, just not "
                "accounted for. An analyst's reasoning can be fully "
                "TRUE and still incomplete."
            ),
        },
        "evidence_completeness": {
            "timestamp_gaps": timestamp_gaps or [],
            "gap_count": len(timestamp_gaps) if timestamp_gaps else 0,
            "note": (
                "Unusually large gaps between consecutive recorded events, "
                "using a simple fixed-threshold heuristic. This does NOT "
                "detect or claim evidence tampering/deletion -- it cannot see "
                "evidence that left no trace at all. It only flags a "
                "statistical property of the timestamps that ARE present, "
                "as a prompt for human review."
            ),
        },
        "parsing_coverage": {
            "claims_parsed": len(report.verified) + len(report.contradicted) + len(report.unsupported) + len(report.missing_telemetry),
            "unparsed_fragments": unparsed_fragments or [],
            "unparsed_count": len(unparsed_fragments) if unparsed_fragments else 0,
            "complete_claim_coverage": not bool(unparsed_fragments),
            "note": (
                "Portions of the explanation text that the deterministic "
                "parser could not decompose into a verifiable claim -- e.g. "
                "phrasing outside its recognized grammar, or higher-level "
                "interpretive language ('appears to have compromised the "
                "server'). This text is NOT verified as true or false -- it "
                "is simply unrepresented in the claim-level results above. "
                "A Reason Slate with unparsed text should not be read as a "
                "complete account of everything the explanation claimed."
            ),
        },
        "evidence_integrity_assessment": assess_evidence_integrity(
            report, unaccounted_evidence, timestamp_gaps, unparsed_fragments
        ),
    }
    canonical_evidence = json.dumps(evidence_identity, sort_keys=True, separators=(",", ":"), default=str)
    evidence_digest = hashlib.sha256(canonical_evidence.encode("utf-8")).hexdigest()

    # analyst_decision's own evidence basis: reuses the SAME verification
    # outcome computed for the explanation, because the decision's
    # justification IS the explanation -- DEVL does not judge whether the
    # chosen decision (escalate/close/etc) was the objectively "correct"
    # business decision, only whether the STATED REASONING behind it is
    # evidence-supported. This boundary is stated explicitly, not implied.
    decision_block = None
    if evidence_identity["analyst_decision"] is not None:
        decision_block = {
            **evidence_identity["analyst_decision"],
            "note": (
                "This shows whether the analyst's STATED REASONING for this "
                "decision is evidence-supported. It does NOT evaluate whether "
                "the chosen decision itself was the objectively correct "
                "business call -- that requires severity, asset criticality, "
                "policy, and context this layer does not have."
            ),
        }

    slate_body = {
        "alert_id": alert_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        # NOTE: this field describes whether the EXPLANATION is
        # supported, not whether the alert should be escalated. See
        # decision_support below for that separate, explicit boundary.
        "verification_outcome": verification_outcome,
        "decision_support": {
            "human_review_required": (
                report.status != "EXPLANATION_FULLY_SUPPORTED"
                or bool(unaccounted_evidence)
                or bool(timestamp_gaps)
                or bool(unparsed_fragments)
            ),
            "note": (
                "This field reflects ONLY whether the explanation's claims "
                "are evidence-supported, whether real evidence exists that "
                "the explanation never accounted for, and whether any of the "
                "explanation text could not be parsed into a verifiable claim "
                "at all. It is NOT a disposition recommendation -- escalate/"
                "close decisions require severity, asset criticality, policy, "
                "and analyst context this layer does not have."
            ),
        },
        **evidence_identity,
        # Deliberately placed AFTER the **evidence_identity spread so it
        # overrides that key with the fuller block (same fields the digest
        # covers, plus the explanatory note). Placing it before the spread
        # was a real bug: the spread's key of the same name silently
        # overwrote it, and the note never reached the output.
        "analyst_decision": decision_block,
        "telemetry_graph_stats": {
            "node_count": graph.node_count(),
            "edge_count": graph.edge_count(),
            "active_log_sources": sorted(graph.active_log_sources),
        },
        "evidence_digest": evidence_digest,
    }

    # audit_digest covers the full record INCLUDING metadata -- this one
    # is expected to differ run-to-run / record-to-record, and is NOT
    # the digest to use for reproducibility verification.
    canonical_full_record = json.dumps(slate_body, sort_keys=True, separators=(",", ":"), default=str)
    audit_digest = hashlib.sha256((evidence_digest + canonical_full_record).encode("utf-8")).hexdigest()
    slate_body["audit_digest"] = audit_digest

    return slate_body


_IDENTITY_KEYS = [
    "explanation_text", "investigation_scope", "analyst_decision", "telemetry_graph_hash",
    "evidence_breakdown", "explanation_integrity", "evidence_coverage",
    "evidence_completeness", "parsing_coverage", "evidence_integrity_assessment",
]


def verify_slate_digest(slate: dict) -> dict:
    """
    Recomputes `evidence_digest` from a Reason Slate's own evidence
    fields and compares it to the digest the slate claims. Returns
    {"valid": bool, "claimed": str, "recomputed": str}.

    WHAT THIS PROVES, STATED HONESTLY: that the evidence content in this
    slate is internally consistent with the digest it carries -- i.e. it
    has not been edited since generation UNLESS the editor also
    recomputed and replaced the digest. A SHA-256 digest is not a
    signature: anyone who can edit the slate can also recompute the
    digest. For tamper-evidence against a capable adversary the digest
    must be stored somewhere they cannot reach, or the slate sealed and
    signed (see custody/custody_cli.py, which supports Ed25519 signing).
    """
    missing = [k for k in _IDENTITY_KEYS if k not in slate]
    if missing or "evidence_digest" not in slate:
        return {"valid": False, "claimed": slate.get("evidence_digest"), "recomputed": None,
                "error": f"slate is missing required field(s): {missing or ['evidence_digest']}"}

    identity = {k: slate[k] for k in _IDENTITY_KEYS}
    decision = identity["analyst_decision"]
    if decision is not None:
        # the explanatory note is display-only and is not part of the digest
        identity["analyst_decision"] = {
            "stated_decision": decision.get("stated_decision"),
            "reasoning_evidence_basis": decision.get("reasoning_evidence_basis"),
        }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
    recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {"valid": recomputed == slate["evidence_digest"],
            "claimed": slate["evidence_digest"], "recomputed": recomputed}


def _fmt_claim(item: dict) -> str:
    c = item["claim"]
    return f"{c['subject']} {c['relation']} {c['object']}"


def render_reason_slate_text(slate: dict) -> str:
    """
    Renders a Reason Slate as a short, explicit, human-readable block --
    showing supporting / contradicting / unaccounted / missing evidence
    side by side, so a reader sees WHY the verification outcome was
    reached rather than only a final pass/fail label. This does not
    replace the full JSON Reason Slate (which remains the source of
    truth and what evidence_digest/audit_digest are computed over) --
    it's a display-only rendering of the same data.
    """
    eb = slate["evidence_breakdown"]
    cov = slate["evidence_coverage"]
    gaps = slate["evidence_completeness"]
    pc = slate["parsing_coverage"]
    assessment = slate["evidence_integrity_assessment"]
    decision = slate.get("analyst_decision")

    lines = []
    lines.append(f"Alert: {slate['alert_id']}")
    lines.append("")
    if decision:
        lines.append(f"Analyst Decision:\n  {decision['stated_decision']}")
        lines.append("")
    lines.append(f"Analyst Reasoning:\n  \"{slate['explanation_text']}\"")
    lines.append("")

    lines.append(f"Supporting Evidence ({len(eb['supporting'])}):")
    lines += [f"  \u2713 {_fmt_claim(i)}" for i in eb["supporting"]] or ["  (none)"]
    lines.append("")

    lines.append(f"Contradicting Evidence ({len(eb['contradictory'])}):")
    lines += [f"  \u26a0 {_fmt_claim(i)} -- {i['note']}" for i in eb["contradictory"]] or ["  (none)"]
    lines.append("")

    lines.append(f"Unsupported / Fabricated Claims ({len(eb['unsupported_claims'])}):")
    lines += [f"  \u2717 {_fmt_claim(i)}" for i in eb["unsupported_claims"]] or ["  (none)"]
    lines.append("")

    lines.append(f"Unaccounted Evidence ({cov['unaccounted_count']}) -- real, but never mentioned:")
    lines += [f"  \u26a0 {u['subject']} {u['relation']} {u['object']}" for u in cov["unaccounted_evidence"]] or ["  (none)"]
    lines.append("")

    lines.append(f"Missing Telemetry ({len(eb['telemetry_gaps'])}):")
    lines += [f"  \u26a0 {_fmt_claim(i)}" for i in eb["telemetry_gaps"]] or ["  (none)"]
    lines.append("")

    if gaps["timestamp_gaps"]:
        lines.append(f"Timestamp Gaps ({gaps['gap_count']}):")
        lines += [f"  \u26a0 {g['gap_seconds']}s between '{g['after_event']}' and '{g['before_event']}'" for g in gaps["timestamp_gaps"]]
        lines.append("")

    if pc["unparsed_fragments"]:
        lines.append(f"Unparsed Explanation Text ({pc['unparsed_count']}) -- not verified true or false:")
        lines += [f"  \u26a0 \"{f}\"" for f in pc["unparsed_fragments"]]
        lines.append("")

    lines.append(f"Evidence Integrity: {assessment['completeness_status']}")
    lines.append(f"  Contradicted: {assessment['contradicted_evidence']['count']}  |  "
                  f"Missing telemetry: {assessment['missing_telemetry']['count']}  |  "
                  f"Unaccounted: {assessment['unaccounted_evidence']['count']}  |  "
                  f"Timestamp gaps: {assessment['timestamp_gaps']['count']}")
    lines.append("")

    lines.append(f"Verification Outcome: {slate['verification_outcome']}")
    lines.append(f"Human Review Required: {'YES' if slate['decision_support']['human_review_required'] else 'NO'}")
    if decision:
        lines.append(f"Decision's Reasoning Basis: {decision['reasoning_evidence_basis']}")

    return "\n".join(lines)


if __name__ == "__main__":
    import pandas as pd
    from fact_extractor import extract_facts_from_session
    from graph_builder import build_graph
    from claim_parser import parse_explanation
    from evidence_matcher import verify_claims
    from mismatch_engine import compute_integrity

    from coverage_checker import find_unaccounted_evidence, detect_timestamp_gaps

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

    # Deliberately partial AND partially-unparseable explanation -- true
    # as far as the parser can decompose it, but also includes
    # higher-level interpretive language outside the grammar, to
    # demonstrate parsing_coverage catching that gap too.
    explanation = (
        "198.51.100.155 connected to ssh:22. 198.51.100.155 authenticated as svc23. "
        "The attacker appears to have compromised the server after obtaining valid credentials."
    )
    parsed = parse_explanation(explanation)
    verdicts = verify_claims(parsed.claims, graph)
    report = compute_integrity(verdicts)

    unaccounted = find_unaccounted_evidence(graph, parsed.claims)
    gaps = detect_timestamp_gaps(facts)

    slate = generate_reason_slate(
        alert_id="ALT-DEMO-" + session["session_id"],
        explanation_text=explanation,
        graph=graph,
        report=report,
        analyst_decision="ESCALATE",
        unaccounted_evidence=unaccounted,
        timestamp_gaps=gaps,
        unparsed_fragments=parsed.unparsed_fragments,
    )
    print(json.dumps(slate, indent=2, default=str))
