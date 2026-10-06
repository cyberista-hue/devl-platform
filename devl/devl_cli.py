#!/usr/bin/env python3
"""
devl_cli.py

Command-line entry point for the SOC Decision Evidence Validation
Layer (DEVL). Ties together all 6 components:
  1. fact_extractor.py    -- telemetry -> Fact Triples
  2. graph_builder.py     -- Fact Triples -> TelemetryGraph
  3. claim_parser.py      -- explanation text -> Claims
  4. evidence_matcher.py  -- Claims x TelemetryGraph -> ClaimVerdicts
  5. mismatch_engine.py   -- ClaimVerdicts -> integrity score + flags
  6. reason_slate.py      -- everything -> final auditable JSON output

Commands:
  verify   Verify a given explanation against a session's real telemetry.
  explain  Generate a candidate explanation via the Anthropic API, then
           immediately verify it (requires OPENAI_API_KEY).
  facts    Just show the extracted Fact Triples for a session (debugging/
           inspection use).

Input sessions are read from a JSON file with the same shape as this
project's Stage 6 session records (session_id, source_ip, protocol,
destination_port, events).
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fact_extractor import extract_facts_from_session, FactExtractionError
from graph_builder import build_graph
from claim_parser import parse_explanation
from evidence_matcher import verify_claims
from mismatch_engine import compute_integrity
from reason_slate import generate_reason_slate, DECISION_CHOICES, render_reason_slate_text


def _load_session(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_facts(args):
    session = _load_session(args.session)
    try:
        facts, skipped, incomplete = extract_facts_from_session(session)
    except FactExtractionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Extracted {len(facts)} facts from session {session.get('session_id')}:\n")
    for f in facts:
        print(f"  ({f.subject}) --{f.relation}--> ({f.obj})  [{f.log_source}, {f.timestamp}]")
    if skipped:
        print(f"\n{len(skipped)} unrecognized event(s) skipped (not fabricated as facts):")
        for e in skipped:
            print(f"  {e}")
    if incomplete:
        print(f"\n{len(incomplete)} incomplete event(s) (recognized action, missing required "
              f"field -- excluded rather than fabricated with a placeholder value):")
        for item in incomplete:
            print(f"  {item['reason']}: {item['event']}")


def _load_scope(scope_file_path):
    """Loads an InvestigationScope from a JSON file:
    {"incident_id": "...", "affected_entities": [...], "window_start": "...", "window_end": "..."}
    window_start/window_end/affected_entities are all optional."""
    from relevance_engine import InvestigationScope
    with open(scope_file_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if "incident_id" not in raw:
        raise ValueError(f"Scope file {scope_file_path} is missing required field 'incident_id'.")
    return InvestigationScope(
        incident_id=raw["incident_id"],
        affected_entities=set(raw.get("affected_entities", [])),
        window_start=raw.get("window_start"),
        window_end=raw.get("window_end"),
    )


def cmd_verify(args):
    session = _load_session(args.session)
    try:
        facts, _, _ = extract_facts_from_session(session)
    except FactExtractionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if args.sysmon_xml:
        from sysmon_fact_extractor import extract_facts_from_sysmon_xml, SysmonExtractionError
        try:
            sysmon_facts, _, _ = extract_facts_from_sysmon_xml(args.sysmon_xml)
        except SysmonExtractionError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        facts = facts + sysmon_facts

    scope = None
    if args.scope_file:
        try:
            scope = _load_scope(args.scope_file)
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as e:
            print(f"ERROR loading --scope-file: {e}", file=sys.stderr)
            sys.exit(1)

    graph = build_graph(facts)

    if args.explanation_file:
        with open(args.explanation_file, "r", encoding="utf-8") as f:
            explanation_text = f.read()
    else:
        explanation_text = args.explanation

    parsed = parse_explanation(explanation_text)
    if parsed.unparsed_fragments:
        print(f"NOTE: {len(parsed.unparsed_fragments)} sentence(s) could not be parsed into "
              f"verifiable claims (unrecognized phrasing) -- these are not counted toward the "
              f"integrity score:", file=sys.stderr)
        for frag in parsed.unparsed_fragments:
            print(f"  - '{frag}'", file=sys.stderr)

    verdicts = verify_claims(parsed.claims, graph)
    report = compute_integrity(verdicts, alpha=args.alpha)

    from coverage_checker import find_unaccounted_evidence, detect_timestamp_gaps
    unaccounted = find_unaccounted_evidence(graph, parsed.claims, scope=scope)
    gaps = detect_timestamp_gaps(facts, scope=scope)

    slate = generate_reason_slate(
        alert_id=args.alert_id or f"ALT-{session.get('session_id', 'unknown')}",
        explanation_text=explanation_text,
        graph=graph,
        report=report,
        analyst_decision=args.decision,
        unaccounted_evidence=unaccounted,
        timestamp_gaps=gaps,
        unparsed_fragments=parsed.unparsed_fragments,
        investigation_scope=scope,
    )

    if scope:
        print(f"NOTE: investigation scope '{scope.incident_id}' applied -- unaccounted-evidence "
              f"findings below are limited to facts assessed as relevant to this investigation "
              f"(see evidence_coverage in the output for each fact's relevance tier).", file=sys.stderr)
    if unaccounted:
        print(f"NOTE: {len(unaccounted)} real telemetry event(s) exist that this explanation "
              f"never referenced:", file=sys.stderr)
        for u in unaccounted:
            print(f"  - ({u['subject']}) --{u['relation']}--> ({u['object']})  [{u['timestamp']}]", file=sys.stderr)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(slate, f, indent=2, default=str)
        print(f"Reason Slate written to {args.output}")
        print(f"Integrity score: {slate['explanation_integrity']['score']}  "
              f"Status: {slate['explanation_integrity']['status']}")
    elif args.format == "text":
        print(render_reason_slate_text(slate))
    else:
        print(json.dumps(slate, indent=2, default=str))

    if args.seal:
        from custody_bridge import append_and_reseal, CustodyBridgeError
        try:
            sealed = append_and_reseal(
                slate, sign=args.seal_sign, keyfile=args.seal_keyfile,
            )
            print(f"\nSealed into decision custody log: {sealed['entry_count']} total decision(s), "
                  f"root hash {sealed['root_hash'][:16]}...", file=sys.stderr)
        except (CustodyBridgeError, ValueError, ImportError) as e:
            print(f"WARNING: could not seal decision into custody log: {e}", file=sys.stderr)


def cmd_explain(args):
    from explanation_generator import generate_explanation, ExplanationGeneratorError

    session = _load_session(args.session)
    try:
        facts, _, _ = extract_facts_from_session(session)
    except FactExtractionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        explanation_text = generate_explanation(facts, alert_context=args.context or "")
    except ExplanationGeneratorError as e:
        print(f"ERROR generating explanation: {e}", file=sys.stderr)
        sys.exit(1)

    print("=== Generated explanation ===")
    print(explanation_text)
    print()
    print("=== Verifying it against the same real telemetry ===\n")

    graph = build_graph(facts)
    parsed = parse_explanation(explanation_text)
    verdicts = verify_claims(parsed.claims, graph)
    report = compute_integrity(verdicts)

    from coverage_checker import find_unaccounted_evidence, detect_timestamp_gaps
    unaccounted = find_unaccounted_evidence(graph, parsed.claims)
    gaps = detect_timestamp_gaps(facts)

    if parsed.unparsed_fragments:
        print(f"NOTE: {len(parsed.unparsed_fragments)} sentence(s) of the GENERATED explanation could not be "
              f"parsed into verifiable claims:", file=sys.stderr)
        for frag in parsed.unparsed_fragments:
            print(f"  - '{frag}'", file=sys.stderr)
    if unaccounted:
        print(f"NOTE: {len(unaccounted)} real telemetry event(s) exist that the generated explanation "
              f"never referenced:", file=sys.stderr)
        for u in unaccounted:
            print(f"  - ({u['subject']}) --{u['relation']}--> ({u['object']})  [{u['timestamp']}]", file=sys.stderr)

    slate = generate_reason_slate(
        alert_id=args.alert_id or f"ALT-{session.get('session_id', 'unknown')}",
        explanation_text=explanation_text,
        graph=graph,
        report=report,
        analyst_decision=args.decision,
        unaccounted_evidence=unaccounted,
        timestamp_gaps=gaps,
        unparsed_fragments=parsed.unparsed_fragments,
    )
    print(json.dumps(slate, indent=2, default=str))


def cmd_batch_verify(args):
    from batch_processor import load_manifest, process_batch, BatchProcessingError

    try:
        manifest = load_manifest(args.manifest)
    except BatchProcessingError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    report = process_batch(manifest)

    print(f"Processed {report['processed']}/{report['total_alerts']} alert(s), {report['errors']} error(s)\n")
    print("=== Ranked alerts (most concerning first) ===")
    for r in report["ranked_alerts"]:
        if r["status"] == "processed":
            s = r["slate"]["explanation_integrity"]
            print(f"  {r['alert_id']}: score={s['score']}  status={s['status']}  flags={s['flags']}")
        else:
            print(f"  {r['alert_id']}: ERROR - {r['error']}")

    print(f"\n=== Correlation: {report['correlation']['shared_entity_count']} shared entit(y/ies) across alerts ===")
    for item in report["correlation"]["shared_entities"]:
        print(f"  [{item['confidence']}] '{item['entity']}' appears in: {item['appears_in_alerts']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nFull batch report written to {args.output}")


def cmd_verify_slate(args):
    from reason_slate import verify_slate_digest

    with open(args.slate, "r", encoding="utf-8") as f:
        slate = json.load(f)
    result = verify_slate_digest(slate)
    if result["valid"]:
        print("PASS: the evidence content in this Reason Slate matches its evidence_digest.")
        print(f"evidence_digest: {result['claimed']}")
        print("NOTE: a SHA-256 digest is not a signature -- this detects edits to the evidence "
              "fields, but not an editor who also replaced the digest. Store the digest separately "
              "or seal the file with custody/custody_cli.py (Ed25519) for stronger assurance.")
    else:
        print("FAIL: this Reason Slate's evidence content does NOT match its evidence_digest.")
        print(f"  claimed:    {result['claimed']}")
        print(f"  recomputed: {result['recomputed']}")
        if result.get("error"):
            print(f"  {result['error']}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="devl_cli",
        description="SOC Decision Evidence Validation Layer -- verify whether an alert explanation is actually supported by real telemetry.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_facts = sub.add_parser("facts", help="Show extracted Fact Triples for a session (debugging).")
    p_facts.add_argument("session", help="Path to a session JSON file.")
    p_facts.set_defaults(func=cmd_facts)

    p_verify = sub.add_parser("verify", help="Verify a given explanation against a session's real telemetry.")
    p_verify.add_argument("session", help="Path to a session JSON file.")
    p_verify.add_argument("--explanation", help="The explanation text to verify (inline).")
    p_verify.add_argument("--explanation-file", help="Path to a file containing the explanation text.")
    p_verify.add_argument("--alert-id", help="Alert ID to embed in the Reason Slate (default: derived from session_id).")
    p_verify.add_argument("--alpha", type=float, default=2.0, help="Contradiction weight in the integrity score formula (default: 2.0).")
    p_verify.add_argument("--output", help="Write the Reason Slate JSON to this file instead of stdout.")
    p_verify.add_argument("--decision", choices=sorted(DECISION_CHOICES), default=None,
                           help="The analyst's stated decision. If given, DEVL reports whether the "
                                "stated reasoning (--explanation) supports it -- not whether the "
                                "decision itself was the correct business call.")
    p_verify.add_argument("--format", choices=["json", "text"], default="json",
                           help="Output format for stdout when --output is not given (default: json). "
                                "'text' renders a short, explicit summary showing supporting/contradicting/"
                                "unaccounted/missing evidence side by side.")
    p_verify.add_argument("--seal", action="store_true",
                           help="After generating the Reason Slate, append it to the decision custody log "
                                "and reseal the log (real hash-chaining, reused from custody/custody_cli.py).")
    p_verify.add_argument("--seal-sign", action="store_true", help="Digitally sign the resealed decision log (requires --seal and --seal-keyfile).")
    p_verify.add_argument("--seal-keyfile", help="Ed25519 private key PEM for --seal-sign.")
    p_verify.add_argument("--sysmon-xml", help="Path to a real Sysmon XML file whose process-lineage facts "
                                                "(SPAWNED/ACCESSED_PROCESS/CREATED_FILE) are merged into this "
                                                "session's telemetry graph before verification.")
    p_verify.add_argument("--scope-file", help="Path to a JSON investigation scope file "
                                                 "({incident_id, affected_entities, window_start, window_end}). "
                                                 "When given, unaccounted-evidence findings are limited to facts "
                                                 "assessed as relevant to this investigation (see relevance_engine.py).")
    p_verify.set_defaults(func=cmd_verify)

    p_explain = sub.add_parser("explain", help="Generate a candidate explanation via the OpenAI API, then verify it (requires OPENAI_API_KEY).")
    p_explain.add_argument("session", help="Path to a session JSON file.")
    p_explain.add_argument("--context", help="Optional alert context to include in the generation prompt.")
    p_explain.add_argument("--alert-id", help="Alert ID to embed in the Reason Slate.")
    p_explain.add_argument("--decision", choices=sorted(DECISION_CHOICES), default=None,
                            help="An analyst decision to check the generated explanation's reasoning basis against.")
    p_explain.set_defaults(func=cmd_explain)

    p_batch = sub.add_parser("batch-verify", help="Verify multiple alerts at once and correlate shared entities across them.")
    p_batch.add_argument("manifest", help="Path to a JSON manifest (list of {alert_id, session, explanation}).")
    p_batch.add_argument("--output", help="Write the full batch report JSON to this file.")
    p_batch.set_defaults(func=cmd_batch_verify)

    p_vs = sub.add_parser("verify-slate", help="Check that a saved Reason Slate's evidence content still matches its evidence_digest.")
    p_vs.add_argument("slate", help="Path to a Reason Slate JSON file (as written by `verify --output`).")
    p_vs.set_defaults(func=cmd_verify_slate)

    args = parser.parse_args()
    if args.command == "verify" and not args.explanation and not args.explanation_file:
        parser.error("verify requires either --explanation or --explanation-file")
    args.func(args)


if __name__ == "__main__":
    main()
