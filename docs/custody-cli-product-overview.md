# Custody CLI — Product Overview

*A reference document covering the idea, the problem it solves, how it
works, and how an organization would adopt it. Written for defense
prep — everything here is grounded in what was actually built and
tested (see docs/decision-log.md D-008 for the underlying verification
evidence).*

---

## 1. The Problem

When a SOC (Security Operations Center) responds to an alert — whether
by a human analyst or an automated system — that response generates a
**record**: what was detected, what technique it mapped to, what threat
intelligence said about it, which steps were taken automatically, and
which risky/destructive step required a human's explicit approval.

That record matters long after the incident is "handled," because it
gets used again later, by different people, under scrutiny:
- An **internal audit** asks "prove your SOC actually followed its own
  process for this incident."
- A **compliance audit** (SOC 2, ISO 27001) asks "show evidence your
  incident response controls were followed and the evidence itself
  wasn't altered afterward."
- A **legal or insurance situation** asks "produce a record of exactly
  what happened and when, that we can trust."
- An **internal dispute** — "did the analyst really approve that
  account lock, or did someone edit the log afterward to cover a
  mistake?"

The problem: **once that response log exists as a plain file (which is
how almost every tool produces it — JSON, JSONL, a database row), there
is nothing stopping anyone with write access from quietly editing it
afterward.** Change a timestamp. Flip a "rejected" to "approved."
Delete an embarrassing entry. Nothing about a plain log file detects
that this happened. That gap is a genuine, real weakness in almost
every SOC/IR workflow today — including in three real instances the
builder personally hit and was marked down for (documented in
docs/decision-log.md).

**Existing "chain of custody" tools do not fully solve this**, because
they focus on hashing *raw forensic evidence* (disk images, captured
web pages, files) — not on the *decision trail* of an automated
response (technique match → enrichment → automated steps → the human
approval moment itself). A search for existing tools targeting this
specific angle (the response decision trail, not raw evidence) did not
turn up a direct match — see D-008 for the exact tools checked.

---

## 2. The Solution — What This Tool Actually Does

The Custody CLI takes an existing response log (any JSONL file of
timestamped entries — not limited to this project's specific format)
and produces a **sealed, tamper-evident, independently verifiable
record** of it, using two layers of real cryptography:

1. **Hash-chaining (SHA-256)** — every entry gets its own content hash,
   and each entry's hash also incorporates the previous entry's hash.
   This means: if anyone alters, deletes, reorders, or inserts even one
   entry after sealing, the hash chain breaks from that point forward —
   and re-verifying pinpoints the *exact entry index* where it broke.

2. **Digital signing (Ed25519, optional)** — the final "root hash" of
   the whole sealed record can be cryptographically signed with a
   private key. Anyone with the matching public key can then verify
   that the seal was made by whoever holds that private key — proving
   *authenticity* (who sealed it), not just *integrity* (whether it was
   altered).

**Important, honest distinction:** this tool proves the record hasn't
been altered *since it was sealed* (and, with signing, who sealed it).
It does **not** independently verify that the underlying system that
produced the log behaved correctly at the time of recording — that's a
separate trust boundary, covered by testing the system that generates
the log (in this project, the playbook engine's own tests).

---

## 3. Core Features (all tested against real data — see D-008)

| Command | What it does |
|---|---|
| `seal` | Hash-chains a JSONL log into a sealed case file. Optionally signs the root hash with `--sign --keyfile`. |
| `verify` | Independently recomputes the hash chain and reports PASS/FAIL. On failure, names the exact entry index where tampering occurred. With `--pubkey`, also verifies the digital signature. |
| `report` | Prints a human-readable summary of a sealed case — grouped by response run, showing every step and every approval decision. |
| `keygen` | Generates a fresh Ed25519 keypair (private key for signing, public key for others to verify with). |

**Proven, not just claimed:**
- Sealed a real 18-entry log from actual playbook runs.
- Deliberately tampered with one field on one entry — `verify` caught
  it precisely, showing the claimed vs. recomputed hash at that exact
  index.
- Signed with one key, then attempted verification with a different
  (forged) key — signature check correctly failed, while the untouched
  hash chain correctly still passed, proving the two checks are
  genuinely independent, not decorative.

---

## 4. How to Run It

**Requirements:** Python 3 (no other install needed for hashing/sealing/
verifying — pure standard library). Digital signing additionally needs
one library:
```bash
pip install cryptography
```
(only required if you plan to use `--sign` / `--pubkey` / `keygen`)

**Basic usage (from inside the project folder):**
```bash
# Seal a response log
python3 custody/custody_cli.py seal audit/audit_log.jsonl custody/sealed_case.json

# Verify it hasn't been tampered with
python3 custody/custody_cli.py verify custody/sealed_case.json

# Read a human-readable summary
python3 custody/custody_cli.py report custody/sealed_case.json
```

**With digital signatures:**
```bash
# One-time: generate a keypair
python3 custody/custody_cli.py keygen custody/keys/private.pem custody/keys/public.pem

# Seal AND sign
python3 custody/custody_cli.py seal audit/audit_log.jsonl custody/sealed_case.json \
    --sign --keyfile custody/keys/private.pem

# Verify chain integrity AND signature
python3 custody/custody_cli.py verify custody/sealed_case.json --pubkey custody/keys/public.pem
```

---

## 5. How an Organization Would Use / Install This

**Who would use it:** SOC teams, MSSPs (managed security service
providers handling IR for multiple clients), internal audit/compliance
teams, and anyone who needs to hand off an incident response record to
someone else who wasn't there when it happened.

**How it fits into a real workflow:**
1. The organization's existing SOC/SOAR tooling produces a response log
   (JSONL or convertible to it) as it normally would — this tool
   doesn't replace that, it seals what already exists.
2. At the close of an incident (or on a schedule — e.g., nightly), the
   organization runs `seal` on that day's/incident's log.
3. The sealed case file (plus, ideally, the signature) gets stored
   somewhere separate from the live system — e.g., a write-once storage
   bucket, or handed to a compliance/legal team.
4. Whenever that record needs to be trusted again — an audit, a
   dispute, a legal request — anyone can independently run `verify`
   (they don't need the original tool's author involved at all; the
   verification math is self-contained and reproducible by a third
   party).

**Installation for an organization (realistic path):**
- Since it's a standalone Python script with minimal dependencies, the
  simplest path is: clone/copy the `custody/` folder onto any machine
  with Python 3, `pip install cryptography` if signing is wanted, and
  run it — no server, no database, no account setup required.
- For heavier organizational use, this could be wrapped as: a scheduled
  job (cron) that auto-seals each day's log; a small internal CLI
  package (`pip install` from an internal package index) for easier
  distribution across a team; or integrated as a step at the end of an
  existing SOAR/playbook pipeline, so sealing happens automatically
  right after each response completes.
- **Key management is the one real operational decision an
  organization would need to make**: who holds the private signing
  key, and how it's protected (e.g., a hardware security module or a
  secrets manager in a real deployment) — this project's `keygen`
  produces a working keypair for demonstration, but production key
  custody is explicitly named as a "path to production" item, not
  something this prototype solves.

---

## 6. What This Is NOT (say this proactively, don't wait to be asked)

- It does not verify that the response actions themselves were correct
  or appropriate — only that the record of them wasn't altered after
  the fact.
- It does not replace the underlying SOC/SOAR system's own testing —
  it seals whatever log that system produces, garbage in, garbage
  (but faithfully preserved) out.
- The `known_infrastructure_match` / destructive-action-simulation
  aspects belong to the broader platform this was built alongside, not
  to the custody tool itself — the custody tool is deliberately
  narrow and single-purpose.
- Private key custody/security in a real deployment is a real
  operational problem this prototype does not solve — it's named
  explicitly as a gap, not hidden.
