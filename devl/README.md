# DEVL — SOC Decision Evidence Validation Layer

Verifies whether an alert explanation (AI-generated or human-written)
is actually supported by real telemetry — distinguishing VERIFIED,
CONTRADICTED, UNSUPPORTED, and MISSING_TELEMETRY claims, and producing
an auditable, hash-digested Reason Slate.

See `docs/decision-log.md` (D-009 through D-015) for the full
architecture, design rationale, and real test evidence — including
every bug caught and fixed during development, stated honestly rather
than smoothed over.

## Requirements

Core verification (`facts`, `verify`): pure Python standard library +
`networkx` + `pandas` (already required elsewhere in this project).

```bash
pip install networkx pandas pyarrow
```

Explanation generation (`explain`) additionally requires a real
OpenAI API key (billed per token, not free -- see docs/decision-log.md):
```bash
export OPENAI_API_KEY="your-real-key-here"
```
Get one at https://platform.openai.com/api-keys/ — no key is bundled, and the
tool will not fabricate an explanation if the key is missing.

## Commands

```bash
# Show the raw Fact Triples extracted from a session's telemetry
python3 devl/devl_cli.py facts devl/samples/demo_session_payload_delivery.json

# Verify a given explanation against a session's real telemetry
python3 devl/devl_cli.py verify devl/samples/demo_session_payload_delivery.json \
    --explanation "198.51.100.155 connected to ssh:22. 198.51.100.155 authenticated as svc23." \
    --decision ESCALATE \
    --output reason_slate.json

# Same, but a short human-readable summary instead of JSON
python3 devl/devl_cli.py verify devl/samples/demo_session_payload_delivery.json \
    --explanation "..." --decision CLOSE --format text

# Same, and also seal this decision into the tamper-evident decision
# custody log (reuses the real hash-chaining from custody/custody_cli.py)
python3 devl/devl_cli.py verify devl/samples/demo_session_payload_delivery.json \
    --explanation "..." --decision CLOSE --seal

# Independently verify the sealed decision log with the SAME custody tool
# used for response-action audit logs
python3 custody/custody_cli.py seal custody/decision_custody_log.jsonl custody/sealed_decisions.json
python3 custody/custody_cli.py verify custody/sealed_decisions.json
python3 custody/custody_cli.py report custody/sealed_decisions.json

# Ask OpenAI to draft an explanation, then immediately verify it
python3 devl/devl_cli.py explain devl/samples/demo_session_payload_delivery.json \
    --context "Suspected payload delivery via exposed SSH service"

# Verify multiple alerts at once, with entity-overlap correlation
python3 devl/devl_cli.py batch-verify devl/samples/batch_manifest.json --output report.json

# Check that a saved Reason Slate hasn't been edited since generation
python3 devl/devl_cli.py verify-slate reason_slate.json

# Merge real Sysmon process-lineage evidence and scope the investigation
# -- unaccounted-evidence/gap findings are limited to what's actually
# relevant to this investigation (see "Process lineage and investigation
# scope" below)
python3 devl/devl_cli.py verify devl/samples/demo_session_payload_delivery.json \
    --explanation "198.51.100.155 connected to ssh:22. 198.51.100.155 authenticated as svc23." \
    --decision CLOSE \
    --sysmon-xml data/sysmon_source/sample_process_lineage.xml \
    --scope-file devl/samples/investigation_scope_example.json \
    --format text
```

The `--decision` flag is optional. When given, DEVL reports whether the
*stated reasoning* behind that decision is evidence-supported -- not
whether the decision itself was the objectively correct business call
(that needs severity/asset-criticality/policy context this layer
doesn't have). Every `verify` and `batch-verify` run also reports:
- **Unaccounted evidence** -- real telemetry events that exist but the
  explanation never mentioned. An explanation can be 100% true and
  still incomplete; this catches that case.
- **Timestamp gaps** -- unusually large gaps between consecutive real
  events (simple fixed-threshold heuristic). This is NOT tamper/log-
  deletion detection -- it cannot see evidence that left no trace at
  all, and only flags a statistical property of the timestamps that
  ARE present, as a prompt for human review.
- **Parsing coverage** -- explanation text the deterministic parser
  couldn't decompose into a claim at all. Surfaced explicitly, not
  silently dropped, and forces `human_review_required: true`.
- **Evidence integrity assessment** -- a three-way distinction, kept
  separate on purpose: evidence that CONTRADICTS a claim, evidence that
  is MISSING/never collected, and situations where the assessment
  itself is incomplete (unparsed text present) -- these are different
  problems and are never collapsed into one flag.

## Connecting to the custody system

`devl/custody_bridge.py` connects a Reason Slate to the same tamper-
evident hash-chaining the custody CLI already provides for response
audit logs (see `custody/custody_cli.py`, D-008). Every `verify --seal`
call appends that decision's full record (decision, reasoning, evidence
findings, both digests) as one entry in a running, append-only
`custody/decision_custody_log.jsonl`, then reseals the WHOLE log --
so the sealed case always covers every decision verified so far, not
just the latest one. This reuses the real `seal_entries()`/`build_chain()`
functions from `custody_cli.py` directly -- there is exactly one
hash-chaining implementation in this repository, not two that could
drift apart. The resulting sealed case is independently verifiable with
the SAME custody CLI commands used for response-action logs.

## What "verified" means here

- **VERIFIED** — the claim matches a real event in the telemetry graph.
- **CONTRADICTED** — the graph contains the opposite of what's claimed
  for the same entities (e.g. claiming an auth failure when the graph
  shows a real successful auth).
- **UNSUPPORTED** — the needed log source was active, but no matching
  event exists — the claimed event did not happen.
- **MISSING_TELEMETRY** — the log source needed to check this claim
  was never collected at all — genuinely unknown, not "false."

The `explanation_integrity` score follows the spec's formula:
`VERIFIED / (VERIFIED + UNSUPPORTED + 2×CONTRADICTED)`.

## Process lineage and investigation scope

Two more real, tested capabilities, directly answering "how does DEVL
know this evidence actually belongs to this investigation, rather than
being an unrelated event?":

- **`devl/sysmon_fact_extractor.py`** — parses real Windows Sysmon XML
  (Event IDs 1/10/11: process creation, process access, file creation)
  into the same Fact/Relation shape as the honeypot extractor, adding
  `SPAWNED`, `ACCESSED_PROCESS`, and `CREATED_FILE` relations. Built
  from a real, hand-selected, honestly-disclosed-as-partial sample of
  Sysmon telemetry from Splunk's public `attack_data` repo (see
  `data/sysmon_source/DOWNLOAD_INFO.txt` for exact provenance/hash) —
  not fabricated. Use `--sysmon-xml <file>` on `verify` to merge
  process-lineage facts into a session's graph.

- **`devl/relevance_engine.py`** — before a real fact can be used as an
  "unaccounted evidence" finding, DEVL asks (Question A) whether that
  fact is actually relevant to the declared investigation at all, via
  three real, disclosed (not ML-trained) signals: **temporal** (inside
  the investigation's time window), **entity** (involves a declared
  affected host/user/IP/process), and **causal** (connected via a real
  process-lineage path — `networkx` graph reachability over
  SPAWNED/ACCESSED_PROCESS/CREATED_FILE edges — to a declared entity).
  Only evidence that passes Question A is checked for Question B (did
  the explanation account for it). Define a scope with `--scope-file`
  (JSON: `incident_id`, `affected_entities`, `window_start`,
  `window_end` — see `devl/samples/investigation_scope_example.json`).
  Tested against real combined honeypot + Sysmon data: correctly
  separates attack-relevant process activity (causally connected to a
  scoped process) from genuinely unrelated real OS housekeeping noise
  (ordinary Windows service startup events) in the same graph.

## Honest scope notes

- This project's two real telemetry sources are Linux/IoT honeypot
  session data (SSH/Telnet/HTTP/MQTT) and a real, small, disclosed-as-
  partial Windows Sysmon sample (process creation/access/file
  creation). Both flow through the same Fact/Relation/graph pipeline
  unchanged. Full enterprise-scale Sysmon/EDR ingestion (not just a
  hand-selected sample) remains a path-to-production step.
- The relevance engine's weights (`RELEVANCE_WEIGHTS` in
  `relevance_engine.py`) are a disclosed, deterministic formula the
  project states openly — NOT a trained ML confidence score. A
  percentage like "88% process lineage match" would require a real
  trained model this project does not have; claiming one would be
  fabrication. The relevance tiers (HIGH/MEDIUM/LOW/OUT_OF_SCOPE) are
  the honest, defensible version of the same idea.
- Claim parsing uses a deterministic regex grammar, not a trained NER
  model (no labeled training data available). It only recognizes
  phrasing it has rules for — unmatched sentences are surfaced in
  `unparsed_fragments`, never silently dropped or force-matched.
- The verification layer (facts → graph → matcher → mismatch engine) is
  entirely deterministic — no ML/LLM involved in the classification
  itself. This is intentional: the layer whose job is to catch
  unsupported claims must not itself be capable of "plausible but
  wrong" output.
- The custody bridge's SHA-256 chain proves a sealed record wasn't
  edited *since sealing*, and (with `--seal-sign`) proves who sealed
  it. It cannot verify that the pipeline itself behaved correctly when
  the record was first written — that's covered separately by this
  project's own test suite (`tests/`), not by the seal itself.

## Running the test suite

```bash
pip install pytest
python3 -m pytest tests/ -v
```
86 tests, built on the JSON demo session and the real Sysmon XML sample
(not the parquet file), so they run without needing `pyarrow` installed.
