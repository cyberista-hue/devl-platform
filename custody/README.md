# Custody CLI

Seals and independently verifies the decision trail of an automated SOC
response (which MITRE technique matched, what enrichment returned,
which steps auto-ran, which required human approval, and what was
decided) using SHA-256 hash-chaining and optional Ed25519 digital
signatures.

See `docs/decision-log.md` (D-008) for why this exists and how it was
verified, including a real tamper-detection test.

## Quick start

```bash
# 1. Seal an audit log (hash-chain only, no signature)
python3 custody/custody_cli.py seal audit/audit_log.jsonl custody/sealed_case.json

# 2. Independently verify it
python3 custody/custody_cli.py verify custody/sealed_case.json

# 3. Human-readable summary
python3 custody/custody_cli.py report custody/sealed_case.json
```

## With digital signatures (optional, requires `pip install cryptography`)

```bash
# Generate a keypair (do this once; keep the private key secret)
python3 custody/custody_cli.py keygen custody/keys/private.pem custody/keys/public.pem

# Seal AND sign
python3 custody/custody_cli.py seal audit/audit_log.jsonl custody/sealed_case.json \
    --sign --keyfile custody/keys/private.pem

# Verify chain integrity AND signature
python3 custody/custody_cli.py verify custody/sealed_case.json --pubkey custody/keys/public.pem
```

Note: `custody/keys/` is intentionally empty in this package — private
keys are never shipped. Generate your own with `keygen` above.

## What "verified" actually means

- **Hash chain PASS** = the sealed entries have not been altered,
  reordered, inserted, or deleted since sealing.
- **Signature PASS** = the sealed case was signed by whoever holds the
  matching private key (non-repudiation), in addition to the above.
- This tool does **not** verify that the underlying playbook engine
  behaved correctly at the time of recording — that's a separate,
  already-tested trust boundary (see `playbooks/playbook_engine.py`'s
  own self-tests).

## Works on any JSONL audit log

This tool is not hardcoded to this project's specific audit log shape —
it will hash-chain any newline-delimited JSON file of dict entries.
