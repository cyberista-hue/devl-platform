#!/usr/bin/env python3
"""
custody_cli.py

A standalone CLI that turns a SOC response audit trail (any JSONL log of
timestamped actions -- not tied to this project's specific schema) into a
hash-chained, optionally digitally-signed, independently verifiable
custody record.

WHY THIS EXISTS (see docs/decision-log.md D-008 for full reasoning):
Existing open-source "chain of custody" tools hash raw forensic evidence
(disk images, files, captured web pages). This tool instead seals the
DECISION TRAIL of an automated response: which technique was matched,
what enrichment said, which steps ran automatically, which destructive
step was gated, and who approved or rejected it, and when. That is a
different artifact from raw evidence, and -- as far as could be verified
via web search on 2026-09-19 -- no existing published tool targets it
specifically.

Design principles:
  - Zero required dependencies for hashing/verification (stdlib only:
    hashlib, json, argparse). The `cryptography` library is used ONLY
    for the optional digital-signature features (keygen/sign/verify
    with --pubkey) -- sealing and chain verification work without it.
  - Works on ANY JSONL file of dict entries, not hardcoded to this
    project's audit_log.jsonl shape -- genuinely reusable.
  - Every command reports PASS/FAIL explicitly, with the exact entry
    index and reason on failure -- never a silent or ambiguous result.

Commands:
  seal    <input.jsonl> <output_sealed.json> [--sign --keyfile priv.pem]
  verify  <sealed.json> [--pubkey pub.pem]
  report  <sealed.json>
  keygen  <priv_out.pem> <pub_out.pem>
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

TOOL_NAME = "custody_cli"
TOOL_VERSION = "1.0.0"
GENESIS_HASH = "0" * 64


def _canonical_json(obj) -> str:
    """Deterministic JSON serialization -- sorted keys, fixed separators
    -- so the same entry always hashes to the same value regardless of
    dict ordering. This determinism is what makes the chain independently
    reproducible by a third party, not just re-checkable by this tool."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_jsonl(path: str) -> list:
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Malformed JSON on line {i+1} of {path}: {e}")
    return entries


def build_chain(entries: list) -> list:
    """
    Computes a hash chain over the entries: each link's hash covers the
    entry's own canonical content AND the previous link's hash, so
    altering, reordering, inserting, or deleting ANY entry breaks every
    subsequent hash -- not just the tampered one. This is the same
    structural property that makes blockchains tamper-evident, applied
    here to an audit log rather than a currency ledger.
    """
    chain = []
    prev_hash = GENESIS_HASH
    for i, entry in enumerate(entries):
        entry_content_hash = _sha256_hex(_canonical_json(entry))
        link_hash = _sha256_hex(prev_hash + entry_content_hash)
        chain.append({
            "index": i,
            "entry_content_hash": entry_content_hash,
            "prev_link_hash": prev_hash,
            "link_hash": link_hash,
        })
        prev_hash = link_hash
    return chain


def seal_entries(entries: list, source_label: str, sign: bool = False, keyfile: str = None) -> dict:
    """
    Core sealing logic, extracted so it can be called both by the CLI
    (`seal`) and programmatically by other tools in this repo (see
    devl/custody_bridge.py) without duplicating the hash-chain/signing
    logic in a second place. Returns the sealed_case dict; callers
    decide whether/where to write it to disk.
    """
    if not entries:
        raise ValueError("Refusing to seal an empty case (0 entries).")

    chain = build_chain(entries)
    root_hash = chain[-1]["link_hash"]
    sealed_at = datetime.now(timezone.utc).isoformat()

    sealed_case = {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "algorithm": "SHA256-chain",
        "sealed_at_utc": sealed_at,
        "source_file": source_label,
        "entry_count": len(entries),
        "root_hash": root_hash,
        "entries": entries,
        "chain": chain,
        "signature": None,
    }

    if sign:
        if not keyfile:
            raise ValueError("sign=True requires a keyfile.")
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
        except ImportError:
            raise ImportError("Signing requires the 'cryptography' package (pip install cryptography).")

        with open(keyfile, "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)
        signature = private_key.sign(root_hash.encode("utf-8"))
        sealed_case["signature"] = {
            "algorithm": "Ed25519",
            "value_hex": signature.hex(),
            "signed_root_hash": root_hash,
        }

    return sealed_case


def cmd_seal(args):
    entries = _read_jsonl(args.input)
    try:
        sealed_case = seal_entries(
            entries, source_label=str(Path(args.input).resolve()),
            sign=args.sign, keyfile=args.keyfile,
        )
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except ImportError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sealed_case, f, indent=2)

    print(f"Sealed {len(entries)} entries from {args.input}")
    print(f"Root hash: {sealed_case['root_hash']}")
    if sealed_case["signature"]:
        print("Digitally signed: yes (Ed25519)")
    print(f"Output: {args.output}")


def cmd_verify(args):
    with open(args.sealed, "r", encoding="utf-8") as f:
        sealed_case = json.load(f)

    entries = sealed_case["entries"]
    claimed_chain = sealed_case["chain"]
    claimed_root = sealed_case["root_hash"]

    recomputed_chain = build_chain(entries)

    if len(recomputed_chain) != len(claimed_chain):
        print(f"FAIL: entry count mismatch -- sealed case claims {len(claimed_chain)} links, "
              f"but {len(recomputed_chain)} entries are present.")
        sys.exit(1)

    first_break = None
    for i, (claimed, recomputed) in enumerate(zip(claimed_chain, recomputed_chain)):
        if claimed["link_hash"] != recomputed["link_hash"]:
            first_break = i
            break

    if first_break is not None:
        print(f"FAIL: hash chain broken at entry index {first_break}.")
        print(f"  Claimed link hash:    {claimed_chain[first_break]['link_hash']}")
        print(f"  Recomputed link hash: {recomputed_chain[first_break]['link_hash']}")
        print("  This means entry content, ordering, or a prior link was altered "
              "after sealing.")
        sys.exit(1)

    recomputed_root = recomputed_chain[-1]["link_hash"]
    if recomputed_root != claimed_root:
        print(f"FAIL: root hash mismatch. Claimed: {claimed_root}  Recomputed: {recomputed_root}")
        sys.exit(1)

    print(f"PASS: hash chain intact across all {len(entries)} entries.")
    print(f"Root hash verified: {recomputed_root}")

    if sealed_case.get("signature"):
        if not args.pubkey:
            print("NOTE: sealed case is signed, but no --pubkey was given -- signature NOT verified.")
        else:
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
                from cryptography.exceptions import InvalidSignature
            except ImportError:
                print("FAIL: signature present but 'cryptography' package not installed -- cannot verify.")
                sys.exit(1)

            with open(args.pubkey, "rb") as f:
                public_key = load_pem_public_key(f.read())
            sig_bytes = bytes.fromhex(sealed_case["signature"]["value_hex"])
            try:
                public_key.verify(sig_bytes, claimed_root.encode("utf-8"))
                print("PASS: digital signature verified (Ed25519) -- root hash was signed by the holder "
                      "of the corresponding private key.")
            except InvalidSignature:
                print("FAIL: digital signature does NOT verify against the provided public key.")
                sys.exit(1)
    else:
        print("NOTE: this sealed case was not digitally signed (hash-chain integrity only).")


def cmd_report(args):
    with open(args.sealed, "r", encoding="utf-8") as f:
        sealed_case = json.load(f)

    entries = sealed_case["entries"]
    print("=" * 60)
    print("CUSTODY REPORT")
    print("=" * 60)
    print(f"Sealed at:      {sealed_case['sealed_at_utc']}")
    print(f"Source file:    {sealed_case['source_file']}")
    print(f"Entry count:    {sealed_case['entry_count']}")
    print(f"Root hash:      {sealed_case['root_hash']}")
    print(f"Signed:         {'yes (Ed25519)' if sealed_case.get('signature') else 'no'}")
    print()

    # Two known entry shapes can appear in a sealed case: response-action
    # audit-log steps (record_type absent, has run_id/step_id/tag) and
    # DEVL decision-verification records (record_type ==
    # "devl_decision_verification", from devl/custody_bridge.py). Report
    # each type meaningfully rather than assuming one shape for both.
    decision_entries = [e for e in entries if e.get("record_type") == "devl_decision_verification"]
    response_entries = [e for e in entries if e.get("record_type") != "devl_decision_verification"]

    if decision_entries:
        print(f"Decision-verification records: {len(decision_entries)}")
        print("-" * 60)
        for e in decision_entries:
            d = e.get("analyst_decision") or {}
            print(f"\nAlert: {e.get('alert_id')}")
            print(f"  Decision: {d.get('stated_decision', '(none stated)')}")
            print(f"  Reasoning: \"{e.get('explanation_text')}\"")
            print(f"  Verification outcome: {e.get('verification_outcome')}")
            print(f"  Human review required: {e.get('decision_support', {}).get('human_review_required')}")
            print(f"  Evidence integrity: {e.get('evidence_integrity_assessment', {}).get('completeness_status')}")
            print(f"  Evidence digest: {e.get('evidence_digest')}")
        print()

    if response_entries:
        run_ids = {}
        for e in response_entries:
            rid = e.get("run_id", "unknown")
            run_ids.setdefault(rid, []).append(e)

        print(f"Distinct response runs: {len(run_ids)}")
        print("-" * 60)
        for rid, steps in run_ids.items():
            alert_id = steps[0].get("alert_entity_id", "?")
            alert_type = steps[0].get("alert_type", "?")
            print(f"\nRun: {rid}")
            print(f"  Alert: {alert_id} ({alert_type})")
            for s in steps:
                decision = s.get("decision")
                decision_note = f" [{decision}]" if decision and decision != "pending" else ""
                print(f"    - {s.get('step_id')}: {s.get('step_title')} ({s.get('tag')}){decision_note}")
    print()
    print("=" * 60)


def cmd_keygen(args):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("ERROR: keygen requires the 'cryptography' package (pip install cryptography).", file=sys.stderr)
        sys.exit(1)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(args.priv_out, "wb") as f:
        f.write(priv_bytes)
    with open(args.pub_out, "wb") as f:
        f.write(pub_bytes)

    print(f"Private key written to: {args.priv_out} (keep this secret -- used to sign)")
    print(f"Public key written to:  {args.pub_out} (share this -- used to verify)")


def main():
    parser = argparse.ArgumentParser(
        prog="custody_cli",
        description="Seal and independently verify a SOC response audit trail via SHA-256 hash-chaining and optional Ed25519 signing.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_seal = sub.add_parser("seal", help="Hash-chain (and optionally sign) a JSONL audit log into a sealed case file.")
    p_seal.add_argument("input", help="Path to the input JSONL audit log.")
    p_seal.add_argument("output", help="Path to write the sealed case JSON.")
    p_seal.add_argument("--sign", action="store_true", help="Digitally sign the root hash.")
    p_seal.add_argument("--keyfile", help="Path to an Ed25519 private key PEM (required with --sign).")
    p_seal.set_defaults(func=cmd_seal)

    p_verify = sub.add_parser("verify", help="Independently verify a sealed case's hash chain (and signature, if present).")
    p_verify.add_argument("sealed", help="Path to the sealed case JSON.")
    p_verify.add_argument("--pubkey", help="Path to an Ed25519 public key PEM to verify the signature.")
    p_verify.set_defaults(func=cmd_verify)

    p_report = sub.add_parser("report", help="Print a human-readable summary of a sealed case.")
    p_report.add_argument("sealed", help="Path to the sealed case JSON.")
    p_report.set_defaults(func=cmd_report)

    p_keygen = sub.add_parser("keygen", help="Generate an Ed25519 keypair for signing sealed cases.")
    p_keygen.add_argument("priv_out", help="Output path for the private key PEM.")
    p_keygen.add_argument("pub_out", help="Output path for the public key PEM.")
    p_keygen.set_defaults(func=cmd_keygen)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
