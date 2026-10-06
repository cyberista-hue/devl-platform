# DEVL — Decision Evidence Validation Layer
### Full Project Overview

*Brand note: logo/product colors — a mixture of blue and yellow.*

---

## 1. The Problem

When a security alert fires — from a SIEM, an EDR tool, or an AI copilot
— it usually comes with an **explanation**: a sentence or two saying
*why* it's suspicious. For example:

> "Suspicious PowerShell activity detected — likely malware download."

The analyst reading that explanation has to trust it, or spend their
own time manually digging through logs to check if it's actually true.
As AI copilots get more involved in writing these explanations
automatically, a new, serious problem appears: **AI systems can sound
completely confident while being wrong.** This is called
*hallucination* — the AI states something as fact that never actually
happened, and there is currently no automatic way to catch it before
an analyst acts on bad information.

**Real-world stakes:** if an analyst escalates (or worse, ignores) an
incident based on an explanation that turns out to be fabricated, that's
a wasted response, a missed real threat, or — in a regulated/defense
context — a decision nobody can defend later when asked "how did you
know that?"

**In one sentence:** *there is no standard way to automatically check
whether a SOC alert's explanation is actually backed by real evidence.*

---

## 2. How DEVL Solves It

DEVL sits between an alert's explanation (however it was generated —
AI, rules engine, or a human's own notes) and the analyst's final
decision. It does one job, very rigorously: **it checks every factual
claim in the explanation against the real telemetry, and tells you
exactly which parts are true, which parts are false, and which parts
can't be checked at all.**

Think of it like a fact-checker for a news article — except instead of
checking against other news sources, it checks against the actual
security logs (the "ground truth").

**The critical design decision:** the verification itself uses **no
AI** — it's plain, deterministic code (pattern matching + a graph
lookup). This is intentional. You cannot use an AI to reliably check
another AI's work, because both can be wrong in the same way. The
*checker* has to be something that always gives the same answer for the
same input — boring, predictable, and trustworthy.

---

## 3. The Solution, Broken Into Simple Pieces

Imagine a real event: *an attacker connects to a server over SSH, logs
in, runs a command, and downloads a malicious file.*

DEVL processes this in six steps:

### Step 1 — Turn raw logs into simple facts
**In plain words:** take messy log data and rewrite it as short,
simple sentences like "X did Y to Z."

**Real example:** a raw log entry might look like:
```json
{"action": "payload_download", "utc": "2026-07-01T00:42:17Z", "payload_sha256": "6cac3bae..."}
```
DEVL turns this into a simple fact:
> `198.51.100.155` → `DOWNLOADED_PAYLOAD` → `6cac3bae...`

### Step 2 — Build a map of what really happened
**In plain words:** connect all those simple facts into a picture — like
a diagram with arrows — showing who connected to what, who logged in as
who, what commands ran, what got downloaded.

**Real example:** for the session above, the map has 6 connected points
(nodes): the attacker's IP, the SSH port, the username, the command
text, the file hash, and the disconnect event — with arrows between
them showing exactly what happened and when.

### Step 3 — Break the explanation into checkable pieces
**In plain words:** take the explanation sentence and split it into
individual claims — one fact per piece — so each one can be checked
separately.

**Real example:** the explanation *"198.51.100.155 connected to ssh:22
and downloaded a malicious payload with hash 6cac3bae..."* gets split
into two separate claims:
1. `198.51.100.155 CONNECTED_TO ssh:22`
2. `198.51.100.155 DOWNLOADED_PAYLOAD 6cac3bae...`

### Step 4 — Check each claim against the real map
**In plain words:** for every claim, ask "does this actually show up in
the real picture from Step 2?"

**Real example:** claim 1 is checked against the map — yes, there's a
real `CONNECTED_TO` arrow between that IP and `ssh:22` → marked
**VERIFIED**. If someone claimed *"downloaded a payload with hash
deadbeef..."* (a hash that was never actually downloaded), the map has
no such arrow → marked **UNSUPPORTED**.

### Step 5 — Score the whole explanation
**In plain words:** count up how many claims were true, false, or
contradicted, and turn that into one overall trust score.

**Real example:** 4 claims checked, all 4 verified → score = **1.0**
(fully trustworthy). If 1 of those 5 claims turns out fabricated →
score drops to **0.8**, and the system raises a warning flag.

### Step 6 — Produce a final, tamper-evident report
**In plain words:** package everything — the score, which claims passed
and failed, and why — into one document, and stamp it with a unique
fingerprint (a hash) so if anyone changes it later, that change is
detectable.

---

## 4. Real Examples — Full Walkthrough

**Example A: A trustworthy AND complete explanation**
```
Explanation: "198.51.100.155 connected to ssh:22. 198.51.100.155
authenticated as svc23. 198.51.100.155 executed the command 'uname -a
&& id'. 198.51.100.155 downloaded a malicious payload with hash
6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8.
198.51.100.155 disconnected from ssh:22."
Decision: ESCALATE

Result: verification_outcome FULLY_SUPPORTED, score 1.0
human_review_required: False (every real event was both true AND accounted for)
```
Every claim matched a real event, AND every real event in the session
was referenced. Note DEVL never says "ESCALATE was correct" — only that
the stated reasoning behind it is fully evidence-supported.

**Example B: An explanation with one fabricated detail**
```
Same as above, PLUS: "198.51.100.155 downloaded a malicious payload
with hash deadbeef00000000000000000000000000000000000000000000000000000000."

Result: verification_outcome MISMATCH_DETECTED, score 0.8
Flag: EXPLANATION_HALLUCINATION_WARNING
human_review_required: True
```
DEVL correctly identifies that this specific hash was never actually
downloaded — the rest of the explanation is true, but this one claim is
made up, and the analyst is told exactly which one, not just "something
seems off."

**Example C: An explanation that is 100% true but INCOMPLETE**
```
Explanation: "198.51.100.155 connected to ssh:22. 198.51.100.155
authenticated as svc23."
Decision: CLOSE

Result: verification_outcome FULLY_SUPPORTED, score 1.0
human_review_required: True
evidence_coverage.unaccounted_count: 3
  MISSED: EXECUTED "uname -a && id"
  MISSED: DOWNLOADED_PAYLOAD "6cac3bae..."
  MISSED: DISCONNECTED_FROM ssh:22
```
This is the key distinction DEVL is built around: everything the
analyst said is TRUE, but real evidence exists that they never
mentioned at all — a command execution and a payload download. A
"CLOSE" decision based only on the stated reasoning would be missing
the most important part of the session. DEVL flags this even though
every individual claim checks out.

**Example D: An explanation with text outside the parser's grammar**
```
Explanation: "198.51.100.155 connected to ssh:22. 198.51.100.155
authenticated as svc23. The attacker appears to have compromised the
server after obtaining valid credentials."

Result: 2 claims parsed and verified (score 1.0 on what WAS parsed)
parsing_coverage.complete_claim_coverage: False
parsing_coverage.unparsed_fragments: ["The attacker appears to have
  compromised the server after obtaining valid credentials"]
human_review_required: True
```
The interpretive sentence ("appears to have compromised...") is
higher-level reasoning the deterministic parser doesn't attempt to
verify as true or false — it's surfaced explicitly as unparsed, rather
than silently ignored, so a Reason Slate is never mistaken for a
complete account of everything the explanation claimed.

**Example C: Multiple alerts at once, with correlation**

Three separate alerts come in. DEVL verifies each one independently,
then separately checks if they're connected:
```
ALT-001 (session A, IP .155): score 1.0
ALT-002 (session B, IP .155): score 1.0
ALT-003 (session C, IP .160): score 1.0

Correlation found:
[STRONG_ENTITY_OVERLAP]  Payload hash "e1c27bf7..." appears in ALT-002 AND ALT-003
          (two DIFFERENT attacker IPs used the exact same malicious file)
[WEAK_ENTITY_OVERLAP]    Command "uname -a && id" appears in all 3 alerts
          (this command is extremely common/generic — not a
           meaningful signal on its own)
```
This tells the analyst: *ALT-002 and ALT-003 are probably the same
attacker infrastructure, even though they used different IP addresses*
— a real, useful lead — while correctly NOT treating a common command
as if it proved a connection. Labels use the explicit
`_ENTITY_OVERLAP` suffix so the output can't be misread as "strong
evidence of the same actor" — what's actually established is strong
evidence these alerts share a specific literal entity.

---

## 4B. Establishing Evidence Relevance (Before Trusting It)

**The question this answers:** *"How does DEVL know a piece of evidence
actually belongs to THIS investigation, rather than being an unrelated
event elsewhere in the environment?"* Without an answer, a system like
this risks exactly the false-positive problem it's supposed to prevent
— flagging ordinary, unrelated activity as "evidence the analyst
missed."

**DEVL asks two separate questions, in order, never skipping the
first:**
- **Question A — Is this evidence relevant to the investigation?**
- **Question B — Did the analyst's reasoning account for it?**

Only evidence that passes Question A is used to answer Question B.
Relevance (Question A) is established through three real, disclosed
signals — never a black-box score:

1. **Temporal** — is the evidence inside the investigation's declared
   time window?
2. **Entity** — does the evidence involve a host, user, IP, or process
   explicitly declared as part of the investigation?
3. **Causal** — is the evidence connected, via a REAL graph path
   (an actual process-lineage chain — parent spawned child, process
   accessed process), to a declared entity? This uses `networkx`'s real
   graph-reachability algorithms over the process-lineage facts
   extracted from genuine Sysmon telemetry (see Section 5, Component 9)
   — not a guess.

**Real worked example (not hypothetical — this is the output of an
actual test run combining two real data sources):**

An investigation is scoped to IP `198.51.100.155` and a specific
`powershell.exe` process, within a declared time window. The combined
evidence graph (real honeypot session + real Sysmon process telemetry)
contains both attack-relevant activity AND ordinary Windows background
noise (a Windows service starting a routine helper process). DEVL
correctly separates them:

```
IN SCOPE (relevant to this investigation):
  [HIGH] powershell.exe SPAWNED chcp.com
    (causally connected: chcp.com is a direct child of the scoped process)
  [HIGH] lsass.exe ACCESSED_PROCESS powershell.exe
    (causally connected to the scoped process)

OUT OF SCOPE (real data, correctly excluded):
  svchost.exe SPAWNED unsecapp.exe
    (ordinary Windows service startup — no entity or causal connection
     to anything declared in this investigation)
```

The `svchost.exe` event is completely real (genuine Sysmon telemetry)
— it's excluded not because it's fake, but because it has no
established relationship to this specific investigation. That's the
mechanism that prevents the false-positive failure mode: suspicious-
looking activity is not treated as relevant just because it exists in
the same log stream.

**Honest limitation, stated directly:** the relevance score is a
disclosed, fixed-weight formula (`temporal: 0.3, entity: 0.4,
causal: 0.3` — see `RELEVANCE_WEIGHTS` in `relevance_engine.py`), not a
trained machine-learning confidence model. A claim like "88% process
lineage match" would require a real trained model this project does not
have, and asserting one would be fabrication. This is a real, working,
testable relevance mechanism — just an honestly-scoped one, not a
statistical/ML one.

---

## 5. Components (Technical Summary)

| # | Component | File | What it does |
|---|---|---|---|
| 1 | Fact Extractor | `devl/fact_extractor.py` | Raw telemetry → simple Fact Triples (skips, never fabricates, incomplete events) |
| 2 | Telemetry Graph Builder | `devl/graph_builder.py` | Facts → a real graph (using the `networkx` library) |
| 3 | Claim Parser | `devl/claim_parser.py` | Explanation text → individual checkable claims, including chained/implied-subject clauses |
| 4 | Evidence Matcher | `devl/evidence_matcher.py` | Claims × Graph → VERIFIED / CONTRADICTED / UNSUPPORTED / MISSING_TELEMETRY |
| 5 | Mismatch Engine | `devl/mismatch_engine.py` | Verdicts → integrity score + warning flags |
| 6 | Coverage Checker | `devl/coverage_checker.py` | Graph vs. claims → unaccounted evidence; timestamps → gap flags |
| 7 | Reason Slate Generator | `devl/reason_slate.py` | Everything → final cryptographically hashed report (SHA-256 digest, not a digital signature) |
| 8 | Relevance Engine | `devl/relevance_engine.py` | Is this evidence even relevant to THIS investigation? (temporal/entity/causal) — answered BEFORE Question B (did the explanation account for it) |
| 9 | Sysmon Fact Extractor | `devl/sysmon_fact_extractor.py` | Real Windows Sysmon XML (process creation/access/file creation) → the same Fact Triples, adding process-lineage relations |
| + | Batch Processor | `devl/batch_processor.py` | Handles many alerts at once + entity-overlap correlation |
| + | Explanation Generator | `devl/explanation_generator.py` | Optional: asks OpenAI to draft an explanation, which then gets verified like any other |
| + | Custody Bridge | `devl/custody_bridge.py` | Seals a decision's full Reason Slate into the same tamper-evident hash chain used for response-action audit logs |
| + | CLI | `devl/devl_cli.py` | The command-line tool tying everything together |

---

## 6. Data & Schema

**Input — a session file** (JSON), e.g. `devl/samples/demo_session_payload_delivery.json`:
```json
{
  "session_id": "S-ed7d82-0000844#192",
  "source_ip": "198.51.100.155",
  "protocol": "ssh",
  "destination_port": 22,
  "events": [
    {"action": "connect", "utc": "2026-07-01T00:42:13Z", ...},
    {"action": "auth_success", "utc": "...", "username": "svc23"},
    {"action": "command", "utc": "...", "command": "uname -a && id"},
    {"action": "payload_download", "utc": "...", "payload_sha256": "6cac3bae..."}
  ]
}
```

**A Fact Triple** (internal, Step 1's output):
```
subject: "198.51.100.155"
relation: "DOWNLOADED_PAYLOAD"
object: "6cac3bae..."
timestamp: "2026-07-01T00:42:17Z"
log_source: "payload_capture_log"
```

**Recognized relations:** `CONNECTED_TO`, `DISCONNECTED_FROM`,
`AUTHENTICATED_AS`, `AUTH_FAILED_AS`, `EXECUTED`, `DOWNLOADED_PAYLOAD`,
`SENT_BANNER`

**Claim statuses:** `VERIFIED`, `CONTRADICTED`, `UNSUPPORTED`,
`MISSING_TELEMETRY`

**Integrity score formula:**
```
score = VERIFIED / (VERIFIED + UNSUPPORTED + 2 × CONTRADICTED)
```
(a contradiction counts double against the score, since it's a
stronger, more specific problem than an unconfirmed claim)

**Output — a Reason Slate** (JSON), the final report — contains:
`alert_id`, `verification_outcome` (FULLY_SUPPORTED / MISMATCH_DETECTED
/ PARTIAL_VERIFICATION_ONLY — states only whether the explanation is
evidence-supported, never a disposition like "escalate"),
`analyst_decision` (the stated decision + whether its reasoning basis
holds up, if `--decision` was given), `decision_support`
(`human_review_required` boolean — trips on any mismatch, unaccounted
evidence, timestamp gap, OR unparsed text), `explanation_integrity`
(score/status/flags/sample_size), `evidence_breakdown`
(supporting/contradictory/unsupported/gaps), `evidence_coverage`
(real facts the explanation never mentioned), `evidence_completeness`
(timestamp gaps), `parsing_coverage` (any explanation text the parser
couldn't decompose into a claim), `telemetry_graph_stats`, and TWO
separate digests: `evidence_digest` (hashes only the evidence-identity
content — genuinely reproducible given the same telemetry+explanation+
decision) and `audit_digest` (hashes the full record including
timestamp/alert_id — expected to differ per record, identifies a
specific instance rather than the evidence itself).

---

## 7. Commands

```bash
# Show the facts extracted from one session
python3 devl/devl_cli.py facts devl/samples/demo_session_payload_delivery.json

# Verify one explanation against one session's real evidence
python3 devl/devl_cli.py verify devl/samples/demo_session_payload_delivery.json \
    --explanation "your explanation text here" \
    --decision ESCALATE \
    --output reason_slate.json

# Ask OpenAI to draft an explanation, then immediately verify it
export OPENAI_API_KEY="your-key"
python3 devl/devl_cli.py explain devl/samples/demo_session_payload_delivery.json

# Verify many alerts at once, with correlation
python3 devl/devl_cli.py batch-verify devl/samples/batch_manifest.json --output report.json

# Merge real Sysmon process-lineage evidence and scope the investigation
# -- see Section 4B for what this changes
python3 devl/devl_cli.py verify devl/samples/demo_session_payload_delivery.json \
    --explanation "your explanation text here" --decision CLOSE \
    --sysmon-xml data/sysmon_source/sample_process_lineage.xml \
    --scope-file devl/samples/investigation_scope_example.json

# Seal a verified decision into the tamper-evident custody log, then
# independently verify/report on it with the SAME custody tool used for
# response-action audit logs
python3 devl/devl_cli.py verify devl/samples/demo_session_payload_delivery.json \
    --explanation "..." --decision CLOSE --seal
python3 custody/custody_cli.py seal custody/decision_custody_log.jsonl custody/sealed_decisions.json
python3 custody/custody_cli.py verify custody/sealed_decisions.json
```

**Requirements:**
```bash
pip install networkx pandas pyarrow pyyaml python-dateutil
```
(`OPENAI_API_KEY` only needed for the `explain` command — everything
else works with zero API keys and zero cost)

**Valid `--decision` values:** `ESCALATE`, `CLOSE`, `FALSE_POSITIVE`,
`NEEDS_INVESTIGATION`. When given, DEVL checks whether the *stated
reasoning* behind that decision is evidence-supported — it never
judges whether the decision itself was the objectively correct
business call, since that needs severity/asset-criticality/policy
context this layer doesn't have.

---

## 8. What This Is NOT (state proactively)

- It does not use AI to make the verification decision — the checker
  itself is 100% deterministic code, by design.
- It does not detect correlation beyond literal shared entities (same
  IP, hash, username) — it will not catch two alerts that are similar
  in *behavior* but share no literal detail.
- The claim parser recognizes a defined set of sentence patterns — an
  explanation phrased very differently may not fully break down into
  claims (unmatched text is shown, never silently dropped).
- Real telemetry used so far is honeypot session data (SSH/Telnet/HTTP/
  MQTT) plus a real, small, hand-selected sample of Windows Sysmon
  telemetry (process creation/access/file creation) — not a full-scale
  enterprise Sysmon/EDR deployment. The same architecture applies at
  that scale; ingesting a live, full-volume enterprise feed is a
  path-to-production step, not a redesign.
- The relevance engine's temporal/entity/causal weights are a stated,
  disclosed formula, not a trained ML confidence model — see Section
  4B. It will not catch relevance signals outside these three
  categories (e.g. semantic similarity between unrelated-looking
  events that a trained model might learn).
- Investigation scope must be explicitly declared (`--scope-file`) —
  DEVL does not infer an investigation's boundary on its own; an
  analyst or calling system states it.
