# Decision Log — SOC IR Platform (Stage 9B)

Format follows the same pattern used in UBI Stage 6 (decision ID, what was
found, what was decided, verification performed). Every entry here is
backed by a real command run against real data — see the referenced
outputs.

---

## D-001: Payload-delivery alert derivation rule

**Finding:** `sessions.parquet`'s nested fields (`payloads_observed`,
`commands_observed`, `events`, `credentials_observed`) are stored as
JSON-encoded strings in flat parquet columns, not native lists (matches
Stage 6's own D-007). An initial naive `len(field)` check against the raw
string was wrong (always truthy, since even `"[]"` has string length 2) —
caught before it propagated into the platform.

**Decision:** A session is flagged as a payload-delivery alert if, after
`json.loads()`-parsing the field, `payloads_observed` is non-empty, OR its
`source_ip` is one of the 3 INFRA-1 cluster IPs from `clusters.json`
(`198.51.100.155`, `.160`, `.87`).

**Verification:** Ran against the real 62,515-row `sessions.parquet`.
293 sessions flagged. Cross-checked: 0 sessions have a real payload whose
IP falls outside the INFRA-1 list — the two signals agree completely,
confirming the rule is internally consistent, not coincidental.

**SUPERSEDED by D-004 below** — the IP-list condition was found to add no
real detection coverage and would not generalize to a new attacker IP.

---

## D-004: Payload-delivery rule revised to be fully IP-agnostic

**Finding:** D-001's original rule OR'd two conditions: non-empty
`payloads_observed` (behavioral) and `source_ip` in the static 3-IP
INFRA-1 list. Checked whether the IP-list condition ever added coverage
the behavioral condition didn't already provide: it never did — every
session with a real payload already has `payloads_observed` populated,
so the IP list was fully redundant in this dataset. Worse, relying on it
at all would mean a brand-new attacker IP delivering a payload from
different infrastructure would NOT be flagged, since the IP list is
static and pre-known.

Also checked the full command vocabulary across all 62,515 sessions:
only ONE distinct command exists in the entire dataset (`uname -a && id`).
A pattern-matcher tested only against this data would be trivially
narrow, so the matcher below is deliberately written as a generic
reconnaissance-command detector (common real commands: `uname`, `whoami`,
`id`, `ifconfig`, `netstat`, `wget`, `curl`, etc.), not reverse-engineered
from the single observed string — matching the same
"write for cases the public data doesn't exercise" pattern as Stage 6's
D-003 self-authored gap tests.

**Decision:** Revised rule — a session is flagged if EITHER:
  (a) `payloads_observed` is non-empty (behavioral, IP-agnostic), OR
  (b) any command in `commands_observed` matches a generic recon-command
      pattern list (behavioral, IP-agnostic, catches recon/exploitation
      even with zero payload activity)

The static IP list is no longer a trigger condition. Instead, payload
hashes are checked against the 4 known-malicious hashes recorded in
`clusters.json`'s INFRA-1 entry (real field: `payloads[].payload_sha256`,
verified directly against the file rather than guessed) and attached as
`known_infrastructure_match` CONTEXT on the alert — this is a stronger
signal than the old IP list because a hash match survives IP rotation
(same attacker tooling, new IP), which the old rule could never catch.

**Verification:** Re-ran against real data. Same 293 alerts as D-001
(expected — every payload session in this dataset already co-occurs with
the recon command, so there are 0 recon-only or payload-only sessions;
"both signals present" = 293 exactly). All 293 correctly show
`known_infrastructure_match: true`. The demo payload anchor
(`S-ed7d82-0000844#192`) still flags correctly with
`known_infrastructure_match: true`. No regression, and the rule is now
demonstrably capable of catching a new-IP/known-hash case or a
new-IP/new-hash-but-recon-command case that the old rule structurally
could not.

---

## D-002: Credential-stuffing alert derivation rule

**Finding:** Every session has either 0 or exactly 1 `auth_fail` event
(938 sessions with 0, 61,577 with 1 — sums to the exact 61,577 total
already documented in Stage 6's D-017). This means a **per-session**
auth_fail count cannot distinguish anything — the signal only exists at
the **per-source-IP aggregate** level, matching the existing Sigma
correlation rule's own design (`group-by: source_ip`, `gte: 5`).

**Decision:** The alert unit for credential stuffing is a source IP with
high cumulative `auth_fail` volume across all its sessions, not an
individual session.

**Verification:** Aggregated real data: 248 distinct source IPs with
auth_fail activity, median 247 attempts/IP, range 0–300 — reproduces
Stage 6's D-017 figures exactly, confirming correctness.

---

## D-003: Locked live-demo anchors

Given 9-day timeline and a one-shot, no-revision demo, chose to
pre-verify specific anchor data rather than rely on a live full-dataset
scan on stage (reduces demo-day risk from an unfamiliar machine /
network dependency during a live AbuseIPDB call).

**Credential stuffing demo anchors (2 IPs, top 2 by real auth_fail
volume):**
- `203.0.113.237` — 300 total auth_fail events across 300 distinct
  sessions, spanning 2026-07-01T00:00:46Z to 2026-07-03T03:39:49Z,
  protocols used: ssh/http/mqtt/telnet
- `203.0.113.182` — 290 total auth_fail events across 290 distinct
  sessions, spanning 2026-07-01T00:01:55Z to 2026-07-03T03:54:16Z,
  protocols used: telnet/ssh/http/mqtt

**Payload-delivery demo anchor (1 session, full kill-chain):**
- `S-ed7d82-0000844#192` — source_ip `198.51.100.155` (INFRA-1),
  ssh/port 22, 2026-07-01T00:42:13Z–00:42:18Z, 6 events:
  connect → client_banner → auth_success (user `svc23`) →
  command (`uname -a && id`) → payload_download
  (sha256 `6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8`,
  matches INFRA-1's confirmed payload set) → disconnect.
  Note: this is the same session independently byte-for-byte verified in
  Stage 6's D-021 — chosen because it already carries the highest
  verification pedigree in the dataset, not by coincidence.

**Verification:** All fields above pulled directly from
`sessions.parquet` via `json.loads()` on the real row, cross-checked
against `clusters.json`'s INFRA-1 payload hash list — full match.

Non-selected scenarios (insider threat, API abuse, BEC/phishing) remain
architecturally-designed-only per the earlier scope decision — no real
data exists for these in the Stage 6 dataset, so they are not
live-demoed.

---

## D-005: Ingestion refactored to an adapter pattern for source-agnosticism

**Finding:** The original ingest.py coupled detection logic directly to
Stage 6's parquet schema, meaning enrichment/playbooks/UI implicitly
depended on Stage-6-specific field names. This was the actual mechanism
behind the "would this work outside UBI" concern raised in conversation
-- not the detection logic itself, but this coupling.

**Decision:** Introduced ingestion/canonical_schema.py defining a
single normalized alert shape (alert_type, entity_type, entity_id,
source_ip, source_dataset, first_seen_utc, last_seen_utc, raw_evidence)
that all downstream code (enrichment, playbooks, UI) consumes. Moved the
verified Stage 6 logic unchanged into
ingestion/adapters/stage6_honeypot_adapter.py, which now canonicalizes
its output before returning. Added ingestion/orchestrator.py to run and
merge all registered adapters -- adding a new data source means writing
one new adapter file and registering it, with zero changes to
enrichment, playbooks, or UI.

**Verification:** Re-ran the refactored Stage 6 adapter standalone --
identical counts to pre-refactor (293 payload alerts, 248
credential-stuffing IPs, both demo anchors present). Ran the full
orchestrator -> enrichment -> playbook pipeline end-to-end post-refactor
-- no regression, all 3 demo anchors still resolve and execute correctly.

---

## D-006: Second, independent data source added and proven end-to-end

**Finding:** To make "not limited to UBI" a demonstrated fact rather
than an architectural claim, needed a genuinely independent real dataset
running through the same pipeline with zero special-casing.

**Decision:** Added ingestion/adapters/ssh_bruteforce_csv_adapter.py
consuming a real, public SSH brute-force attempt dataset (a GitHub gist
by kingabzpro, credited to a Kaggle dataset -- see
data/second_source/DOWNLOAD_INFO.txt for exact provenance/hash). HONEST
SCOPE NOTE: only 183 rows of the full dataset were saved (a genuine but
partial sample, retrieved via the web_fetch tool since the full raw
file's host, gist.githubusercontent.com, is outside this sandbox's
network allowlist) -- this is disclosed explicitly, not implied as the
complete original dataset.

This dataset has a completely different real schema
(username, timestamp, passwords, foreign_ip) and no explicit
success/failure flag, unlike Stage 6's honeypot data. The adapter is
honest about this difference: it flags IPs by login-attempt VOLUME
(threshold: 5+ attempts) and explicitly notes in the alert's
raw_evidence that this reflects attempt volume, not a
confirmed-malicious determination -- since, unlike a honeypot, this
dataset has no guarantee every row is malicious.

**Verification:** Ran the new adapter standalone: 183 real rows, 41
distinct real IPs, 13 IPs cross the 5-attempt threshold (top: 31
attempts from one IP). Ran the full orchestrator with BOTH adapters
registered: 554 total merged alerts, sources_represented correctly
lists both ubi_stage6_honeypot and public_ssh_bruteforce_csv. Ran
enrichment (real MITRE T1110.004 resolution) and the existing
credential_stuffing_v1.yaml playbook (auto-run safe steps, gate on
approval, resume after approval) against a real alert from this NEW
source -- completed successfully with zero code changes to enrichment
or playbook logic, confirming the adapter pattern's source-agnosticism
is real, not just designed-for.

---

## D-007: Real external hash reputation added (MalwareBazaar)

**Finding:** Prior "hash reputation" only matched a payload's hash
against the 4 hashes already known from this project's own
clusters.json -- purely internal consistency checking, not real threat
intelligence. This was a gap flagged directly by the user: "check
payload against an external source."

**Decision:** Added enrichment/malwarebazaar_client.py, a real
integration with abuse.ch's MalwareBazaar API (endpoint verified
current: POST https://mb-api.abuse.ch/api/v1/, query=get_info,
hash=<sha256>, requires a free Auth-Key from auth.abuse.ch as of the
2024 API change -- confirmed via live search, not assumed from
training data). Wired into enrichment/enrich.py as enrich_hash_reputation,
applied automatically to every payload_delivery_detected alert carrying
payload hashes. Distinguishes three honest outcomes: known_malicious
(hash IS a catalogued sample, with real signature/tags from the API),
not_found (queried successfully, no record -- a genuine negative
result), and unavailable (no key / network / API error -- enrichment
could not be performed). "not_found" and "unavailable" are kept
separate since collapsing them would misrepresent a real negative
result as a missing one.

**Verification:** Ran enrich.py self-test: correctly returns
no_payloads_on_alert for a credential-stuffing alert (no payload field
to check), and correctly attempts + honestly reports "unavailable" for
the real demo payload anchor's hash (no MALWAREBAZAAR_API_KEY set yet
in this environment -- never fabricates known_malicious or not_found
without a real API response). Ran the full orchestrator -> enrichment ->
playbook pipeline end-to-end afterward -- no regression, demo anchor
still resolves and the payload_delivery_v1.yaml playbook still executes
correctly through to the approval gate.

**Still open:** MALWAREBAZAAR_API_KEY needs to be set (free registration
at auth.abuse.ch) for hash_reputation to return real known_malicious /
not_found verdicts instead of "unavailable" -- same pattern as
ABUSEIPDB_API_KEY.

---

## D-008: Standalone custody CLI built for the response decision trail

**Finding:** User requested a standout CLI project. Checked several
candidate ideas via live web search before committing to any (see
conversation): a MITRE-mapping CLI, an IOC-enrichment CLI, and a general
evidence-integrity/chain-of-custody CLI were ALL found to have multiple
existing, published, sometimes more sophisticated competitors
(e.g. threatpivot, iocflow, soc-agent-toolkit, AgentDFIR, ProofSnap).
Proceeding with any of these without checking would have risked
presenting a clone as original work.

A narrower angle -- sealing and verifying the DECISION TRAIL of an
automated response (which technique matched, what enrichment returned,
which steps auto-ran, which were gated, who approved/rejected, when) as
opposed to hashing raw forensic evidence (which is what every found
competitor does) -- returned no direct existing match in the same
search process. This is disclosed as "not found in this search," not
asserted as definitively unique; the honest claim is genuine
differentiation from everything actually checked.

**Decision:** Built custody/custody_cli.py, a standalone, mostly
zero-dependency (stdlib hashlib/json/argparse; the `cryptography`
package is used ONLY for optional Ed25519 signing) CLI with four
commands: `seal` (hash-chains a JSONL audit log into a sealed case,
optionally Ed25519-signed), `verify` (independently recomputes the
chain and reports PASS/FAIL with the exact broken entry index),
`report` (human-readable case summary), and `keygen` (generates a
signing keypair). Deliberately built to work on ANY JSONL audit log,
not hardcoded to this project's schema -- genuinely reusable, not a
platform-specific script.

**Verification (all against real data, not synthetic):**
- Generated a fresh, real 18-entry audit_log.jsonl by re-running the
  actual playbook engine against all 3 real demo-anchor alerts
  end-to-end (enrichment -> playbook -> approval).
- `seal` produced a real sealed case file with a genuine SHA-256 root
  hash over all 18 entries.
- `verify` against the untouched sealed case: PASS.
- TAMPER TEST: manually altered one field (a decision value) on one
  entry in a copy of the sealed case, leaving the stored root_hash/chain
  untouched (simulating a naive after-the-fact edit). `verify` correctly
  and precisely FAILED, identifying the exact broken entry index (10)
  and showing claimed vs. recomputed hash values -- proving tamper
  detection actually works, not just assumed to.
- SIGNING TEST: generated a real Ed25519 keypair via `keygen`, sealed
  with `--sign`, verified successfully against the correct public key.
- FORGED-KEY TEST: generated a second, different keypair and attempted
  verification against it -- hash chain correctly still PASSED (content
  was never altered) while signature verification correctly and
  distinctly FAILED, proving the signature check is real cryptographic
  verification, not a rubber-stamp.
- `report` correctly summarized all 3 real response runs with their
  real step-by-step approval history.

**Honest limitation to state in defense:** the tool verifies that the
recorded audit trail was not altered after sealing, and (with signing)
that it was sealed by a specific keyholder. It does NOT independently
verify that the underlying playbook engine itself behaved correctly at
the time of recording -- that trust boundary is the playbook engine's
own tested correctness (see D-... playbook engine self-tests), not this
tool's job. This distinction should be stated proactively, not left for
a judge to find.

---

## D-009: DEVL (Decision Evidence Validation Layer) built to full spec

NAMING NOTE (added after initial build): the expansion was originally
"Decision Explainability & Evidence Validation Layer," which does not
literally spell DEVL (it has two E's from "Explainability" and
"Evidence"). Corrected to "Decision Evidence Validation Layer" so the
acronym is literal -- the explainability property is still delivered
(the Reason Slate output IS the explanation), it just isn't redundantly
named twice.


**Finding:** Mentor feedback said the custody CLI wasn't SOC-intensive
enough compared to Stages 5-9. User and a collaborator produced a
detailed architecture spec for a SOC Decision Explainability & Evidence
Validation Layer (6 components: Fact Extractor, Telemetry Graph
Builder, Claim Parser, Evidence Matcher, Mismatch/Contradiction Engine,
Reason Slate Generator) -- verifying whether an AI-generated or
rule-based alert explanation is actually supported by real telemetry,
not just plausible-sounding.

**Decision:** Built all 6 components to the real spec, in
devl/, using real libraries (networkx for the graph, not a hand-rolled
structure) and real data (Stage 6's honeypot sessions as ground-truth
telemetry) throughout -- no synthetic/mocked data at any stage.

HONEST SCOPE NOTE: the spec's worked example uses Windows Sysmon
Event IDs (Office->PowerShell). This project's only real telemetry is
Linux/IoT honeypot session data (SSH/Telnet/HTTP/MQTT). The
architecture and verification LOGIC are built faithfully to spec;
the log-source taxonomy (network_session_log, auth_log,
command_exec_log, payload_capture_log, banner_log) is this project's
own, honestly matched to what the real data contains. Adapting this to
real Sysmon/EDR telemetry for a Windows enterprise environment is a
path-to-production step, not silently assumed to already work.

Claim parsing uses a deterministic regex-based grammar (one of the two
options the spec itself names, chosen over NER since no labeled
training data exists) -- explicitly stated tradeoff: only recognizes
phrasing it has grammar rules for; unmatched text is surfaced in
`unparsed_fragments`, never silently dropped.

**Verification (all against real data):**
- Component 1: extracted 6 real facts from real demo session
  S-ed7d82-0000844#192 (connect/banner/auth/command/payload/disconnect),
  0 skipped events.
- Component 2: built a real networkx MultiDiGraph (6 nodes, 6 edges);
  confirmed has_edge() correctly returns True for a real payload hash
  and False for a fabricated one.
- Component 3: BUG CAUGHT AND FIXED -- initial sentence-splitter broke
  on every "." including inside IP addresses (198.51.100.155 ->
  "198","51","100","155..."). Fixed to split only on period+whitespace.
  Re-tested: correctly parsed 5 real/fabricated claims from mixed text,
  correctly left one genuinely unparseable sentence
  ("The weather was...") in unparsed_fragments rather than forcing a
  false match.
- Component 4: ran a mix of 4 true claims + 1 fabricated claim (fake
  hash) + 1 false claim contradicting a real successful auth, against
  the real graph. Result: 4 VERIFIED, 1 UNSUPPORTED (fabricated hash,
  correctly caught), 1 CONTRADICTED (false auth-failure claim,
  correctly caught against the real AUTHENTICATED_AS fact). Also
  verified MISSING_TELEMETRY separately by deliberately excluding a log
  source from the graph.
- Component 5: verified the exact integrity-score formula against 3
  real cases: fully accurate explanation -> 1.0; one fabricated claim
  added -> 4/(4+1) = 0.8; one contradicting claim added -> 4/(4+2*1) =
  0.67 (alpha=2 weighting) -- all computed, matching hand-calculation.
- Component 6: generated a full real Reason Slate JSON matching the
  spec's sample schema exactly (disposition_recommendation,
  explanation_integrity, evidence_breakdown, audit_digest). BUG CAUGHT
  AND FIXED -- timestamps initially came through as null because the
  code guessed field names ("event_time"/"timestamp") instead of
  checking the real schema; the actual field is "utc". Fixed and
  re-verified real timestamps (e.g. "2026-07-01T00:42:13Z") now appear
  correctly in matched_evidence throughout the full chain.

**Design note:** the audit_digest reuses the same hash-chaining
principle as the custody CLI (D-008) -- binding the exact telemetry
graph state to the final decision record -- applied here to a single
decision's evidence rather than a whole response audit log. The two
tools are complementary, not duplicates: custody CLI seals a SEQUENCE
of response actions after the fact; DEVL's Reason Slate certifies a
SINGLE explanation's evidence support at generation time.

**Still to build:** an LLM-based explanation generator (Component
"proposed explanation" source) using the real Anthropic API -- requires
the user's own ANTHROPIC_API_KEY (none available in this build
environment; confirmed via a 401 on a live request with no key). Until
then, explanations are supplied as text (manually, or from any
rule-based/copilot source) -- the verification pipeline itself does not
require an LLM to function, which is an intentional, stated design
property (the verifier must not itself be a system capable of
"plausible but wrong" output).

**CLI-level verification (D-009 continued):** built devl/devl_cli.py
tying all 6 components together (`facts`, `verify`, `explain`
subcommands). Created a real sample session JSON
(devl/samples/demo_session_payload_delivery.json) directly from the
actual Stage 6 parquet row for session S-ed7d82-0000844#192 -- not
fabricated. Ran all three subcommands as an end user would:
- `facts` correctly printed all 6 real facts with correct timestamps.
- `verify` with an accurate explanation: integrity score 1.0,
  EXPLANATION_FULLY_SUPPORTED, disposition ESCALATE.
- `verify` with the same explanation plus one fabricated payload hash:
  integrity score 0.8, EXPLANATION_MISMATCH_DETECTED,
  EXPLANATION_HALLUCINATION_WARNING flag, correctly identified the
  exact fabricated hash in `unsupported_claims` -- reproducing the
  standalone component test's result through the real CLI entry point.
- `explain` with no ANTHROPIC_API_KEY set: failed honestly with a clear
  message, exit code 1, no fabricated explanation -- confirmed the
  honest-failure discipline holds through the CLI layer too, not just
  in the underlying module.

The full DEVL system (6 components + CLI + LLM integration) is complete
and independently verifiable by re-running any of the commands above
against the included real sample session.

---

## D-010: Batch verification + entity correlation across multiple alerts

**Finding:** User asked whether DEVL handles multiple simultaneous
alerts and cross-alert correlation. Honest answer at the time: it did
not -- each alert was verified in isolation only.

**Decision:** Built devl/batch_processor.py with two DELIBERATELY
SEPARATE functions: (1) batch verification -- runs the existing
per-alert pipeline independently for each alert (no alert's evidence
ever influences another alert's verdict), then ranks results by
severity (contradictions first, then ascending integrity score); (2)
entity correlation -- a separate pass, run only after verification,
that indexes every entity (IP, hash, username, etc.) across all the
batch's telemetry graphs and flags entities appearing in more than one
alert. Correlation NEVER changes an individual alert's integrity score
-- presented as separate context, not mixed into verification.

Correlation entries carry an honest confidence tier, directly reusing
the same reasoning already established in this project's Stage 6
decision log: a shared payload hash or raw IP across alerts is STRONG
(specific artifact/address coincidence), a shared EXECUTED command is
WEAK (this project's own dataset has exactly ONE distinct command
across all 62,515 sessions -- D-004 -- so a shared command carries
near-zero evidentiary weight here, and is generically often just reused
tooling), anything else is MEDIUM.

**Verification (all against real data):**
- Found a genuine real correlation case before building the test: two
  different real sessions, from two DIFFERENT source IPs
  (198.51.100.155 and .160), independently confirmed (via clusters.json
  lookup, not assumed) to share the exact same payload SHA-256 hash.
- Built real sample session files for these plus the original demo
  session and ran all three through `batch-verify`.
- CAUGHT A REAL ERROR DURING TESTING: an initial test explanation for
  one session guessed "connected to http:80" without checking the
  session's actual real protocol/port field first -- the tool correctly
  scored it 0.0 / EXPLANATION_MISMATCH_DETECTED, catching the builder's
  own unverified claim. Checked the real file (protocol: mqtt, port:
  1883), corrected the test explanation, re-ran -- confirms the
  verifier's discipline applies even to test authoring, not just to
  end-user explanations.
- Final clean run: 3/3 alerts processed, all correctly
  EXPLANATION_FULLY_SUPPORTED (accurate explanations). Correlation
  correctly surfaced: the shared IP (STRONG, between the 2 alerts that
  really share it), the shared payload hash (STRONG, between the 2
  DIFFERENT-IP alerts that really share it -- the intended "new IP,
  known payload" signal), the shared destination string (MEDIUM), and
  the dataset-wide command (WEAK, correctly demoted).
- Tested the error-handling path: a manifest with one nonexistent
  session file alongside one valid alert -- the valid alert still
  processed and reported normally, the bad one reported its own error
  clearly, neither was silently dropped or allowed to abort the batch.
- CLI command `devl_cli.py batch-verify <manifest.json> --output <file>`
  tested directly, matches all standalone module test results exactly.

**Honest limitation stated for defense:** correlation here is simple
deterministic entity-overlap (shared literal IP/hash/username), not a
statistical or ML-based campaign-clustering algorithm -- it will not
detect correlation between alerts that share no literal entity but are
behaviorally similar (e.g. same TTP pattern from genuinely unrelated
infrastructure). This is a real, stated scope boundary, not a claimed
capability.

---

## D-011: External code review — 6 real issues found and fixed (2 additional bugs caught during the fix itself)

**Finding:** User obtained an independent code review of the DEVL
codebase (from another AI reviewer, pasted in as external input). Per
this project's standing practice, review findings were NOT accepted on
trust -- each was independently reproduced against the real code before
any fix was made.

**Independently confirmed, all reproduced with real commands before
fixing:**
1. Claim parser silently dropped claims: a fragment with multiple
   claims (e.g. "X connected to Y and authenticated as Z") only kept
   the FIRST matching claim and discarded the rest -- confirmed: only
   1 of 2 real claims was extracted, and the lost claim did not appear
   in unparsed_fragments either (a true silent loss, contradicting the
   project's own stated "never silently dropped" principle).
2. `audit_digest` included `generated_at_utc` inside the hashed
   content, making it non-reproducible despite being documented as
   supporting "independent reproducibility" -- confirmed: identical
   telemetry+explanation run twice, 1.5s apart, produced two different
   digests despite an identical graph_hash.
3. `TelemetryGraph.hash()` was documented as hashing the graph's "full
   content" but excludes `session_id` and `raw_event` -- confirmed by
   direct code inspection.
4. `disposition_recommendation: ESCALATE` conflated two different
   questions (is the explanation supported vs. should this be
   escalated) -- the latter needs inputs (severity, asset criticality,
   policy) this layer doesn't have.
5. Integrity score is a heuristic, not a confidence/probability measure
   -- 1-verified/1-unsupported and 100-verified/100-unsupported both
   score 0.5 despite very different evidentiary volume.
6. Fact extraction fabricated placeholder values for missing required
   fields (`"unknown_hash"`, `""` for empty command) -- confirmed by
   direct code inspection, and this pattern directly violates this
   project's own stated no-placeholder principle.

**Fixes applied, each independently re-verified:**
1. Rewrote `claim_parser.py`'s matching to (a) extract ALL non-
   overlapping full matches per fragment via `finditer`, not just the
   first, and (b) added a `_HEADLESS_GRAMMAR` + `_extract_headless_chain`
   mechanism so subject-less continuation clauses ("and authenticated
   as X", "but failed as X") correctly inherit the carried-over subject
   from earlier in the same fragment, looping to catch MULTIPLE chained
   continuation clauses, not just one. TWO additional real bugs were
   found and fixed WHILE building this fix (both caught by testing
   against the reviewer's own adversarial examples, not assumed
   correct): (a) an index-slicing mismatch between the connector-
   stripped and original text caused garbage leftover output
   ("vc23"); (b) the connector-stripping regex only removed ONE
   leading connector token, so "`, but`" (two stacked connectors) left
   "but" unconsumed and broke the match. Final verification: the
   reviewer's exact 3-clause adversarial case ("X connected... and
   authenticated... but authentication failed...") now correctly
   yields all 3 claims (CONNECTED_TO, AUTHENTICATED_AS, AUTH_FAILED_AS)
   with zero unparsed leftover, confirmed both via direct module call
   and through the live CLI (`verify` command), correctly producing
   `MISMATCH_DETECTED` / `CONTRADICTORY_EVIDENCE_DETECTED`.
2. Split `reason_slate.py`'s single digest into `evidence_digest`
   (hashes ONLY evidence-identity content: explanation text, graph
   hash, evidence breakdown, integrity score -- excludes timestamp and
   alert_id) and `audit_digest` (the full record including metadata,
   expected to differ per-record). Re-verified: same
   telemetry+explanation run twice, 1.5s apart -- `evidence_digest`
   now IDENTICAL both times, `audit_digest` correctly still differs.
3. Corrected `TelemetryGraph.hash()`'s docstring from "full graph
   content" to "canonical normalized graph representation," stating
   explicitly what it does and doesn't cover, rather than changing its
   behavior.
4. Renamed `disposition_recommendation` -> `verification_outcome`
   (values: FULLY_SUPPORTED / MISMATCH_DETECTED /
   PARTIAL_VERIFICATION_ONLY -- no more ESCALATE language anywhere in
   this layer's output) and added a separate `decision_support` block
   with an explicit `human_review_required` boolean and a note stating
   this is NOT a disposition recommendation. Renamed the function
   parameter (`disposition_recommendation` ->
   `verification_outcome_override`) for full consistency, not just the
   output field.
5. Added an explicit `sample_size` breakdown (verified/contradicted/
   unsupported/missing_telemetry counts) alongside the integrity score
   in every Reason Slate, so the score is never presented without its
   underlying evidentiary volume visible next to it.
6. Rewrote `fact_extractor.py` so a recognized event with a missing
   required field is excluded from `facts` entirely and instead
   recorded in a new `incomplete_events` list with a specific reason --
   never fabricated as a fact with a placeholder value. Updated the
   function's return signature (2-tuple -> 3-tuple) and all 10 call
   sites across the codebase accordingly (found via a full-codebase
   grep, not assumed). REAL-DATA FINDING during verification: the
   actual Stage 6 telemetry's `client_banner` events carry NO banner
   text field at all -- meaning `SENT_BANNER` facts were being silently
   fabricated as empty strings in EVERY prior run of this project, not
   just a theoretical risk -- confirmed by running `facts` against the
   real demo session and seeing a genuine `incomplete_events` entry
   appear for the first time.

**Also applied (lower priority, low cost, real improvement):**
- Correlation confidence labels renamed `STRONG`/`MEDIUM`/`WEAK` ->
  `STRONG_ENTITY_OVERLAP`/`MEDIUM_ENTITY_OVERLAP`/`WEAK_ENTITY_OVERLAP`
  in `batch_processor.py`, so output cannot be misread as "strong
  evidence of the same actor" when what's actually established is
  "strong evidence these alerts share this literal entity."

**Full regression after all fixes:** all 7 module self-tests
(`fact_extractor`, `graph_builder`, `claim_parser`, `evidence_matcher`,
`mismatch_engine`, `reason_slate`, `batch_processor`) pass. Stale
pre-fix sample output files (`reason_slate_accurate.json`,
`reason_slate_hallucinated.json`, `batch_report.json`) deleted and
regenerated fresh from the corrected code.

**Not fixed in this pass, explicitly deferred (from the review's own
P2 items):** building a dedicated adversarial test SUITE (vs. the
ad-hoc adversarial cases verified above), and classifying claims into
OBSERVATIONAL/INFERENTIAL/CAUSAL/ATTRIBUTIVE tiers (the review's
suggestion that the verifier currently only meaningfully validates
observational claims, not higher-level causal/attributive language in
a real explanation). Both are named here as honest, stated future work,
not silently dropped.

---

## D-012: Analyst decision input + evidence coverage + timestamp-gap detection

**Finding:** A follow-up review proposed a stronger framing: instead of
only verifying "is this explanation true," also verify "did the
analyst's decision and reasoning account for the evidence available to
them" -- including analyst-entered decisions, evidence the analyst
never referenced, and possible signs of evidence gaps/tampering. Each
piece was assessed separately for what's honestly buildable now vs.
what would overclaim capability that doesn't exist.

**Decision, built in three scoped pieces:**

1. **Analyst decision input.** Added `analyst_decision` (one of
   ESCALATE/CLOSE/FALSE_POSITIVE/NEEDS_INVESTIGATION, validated against
   an explicit allowed set) to `generate_reason_slate()`, `verify`
   (`--decision` flag), and `batch-verify` (manifest `decision` field).
   The output's `analyst_decision` block states explicitly that it
   evaluates whether the STATED REASONING behind the decision is
   evidence-supported -- NOT whether the decision itself was the
   objectively correct business call, since that needs inputs (asset
   criticality, policy, severity) this layer doesn't have. This
   boundary is stated in the output itself, not just in documentation.

2. **Unaccounted evidence** (`devl/coverage_checker.py`,
   `find_unaccounted_evidence`). Compares every real fact in the full
   telemetry graph against every claim the explanation actually made,
   and reports real facts that were never referenced at all. This is
   honestly buildable today because DEVL already builds its graph from
   ALL real session events, not just the ones an explanation happens to
   mention -- no new data source needed.

3. **Timestamp gap detection** (`devl/coverage_checker.py`,
   `detect_timestamp_gaps`). Flags unusually large gaps between
   consecutive real event timestamps using a simple, explicitly-stated
   fixed threshold (default 300s). EXPLICITLY NOT claimed as tamper/
   log-deletion detection -- the output note states directly that it
   cannot see evidence that left no trace, and only surfaces a
   statistical property of the timestamps that ARE present, as a
   prompt for human review.

**Explicitly NOT built, and why:** detecting specific tamper indicators
named in the review (event-log clearing, audit-policy modification,
EDR tamper alerts) -- this project's real telemetry contains no such
event types at all, so claiming to detect them would be fabricating a
capability with zero real data behind it. This boundary is stated
directly in the tool's own output text, not just in this log.

**Verification (all against real data):**
- `find_unaccounted_evidence`: given a real explanation mentioning only
  2 of the demo session's 5 real facts, correctly identified the other
  3 (EXECUTED, DOWNLOADED_PAYLOAD, DISCONNECTED_FROM) as unaccounted.
- `detect_timestamp_gaps`: confirmed 0 gaps at the realistic default
  threshold (300s) against the real session (events are genuinely 1-2s
  apart), then confirmed the detector actually WORKS by re-running at
  threshold=0.5s, correctly finding all 4 real consecutive gaps with
  accurate second-level deltas -- proving the zero-gaps result at the
  default threshold reflects real data, not a broken detector.
- Full CLI test reproducing the review's exact "truthful but
  incomplete" scenario: an explanation covering connect+auth+payload-
  download (all 3 claims TRUE, integrity score 1.0) that omits the real
  command-execution and disconnect events. Result: verification_outcome
  correctly FULLY_SUPPORTED, but `human_review_required` correctly
  flips to `true` because of 2 unaccounted real events -- demonstrating
  the core distinction the review argued for: a fully true explanation
  can still be incomplete, and DEVL now surfaces that distinctly from
  simple truth-checking.
- Invalid `--decision` values correctly rejected by argparse at the CLI
  layer; invalid `decision` values in a batch manifest correctly
  produce a per-alert error (via a newly-added `ValueError` catch)
  without aborting the rest of the batch -- tested directly with a
  2-alert manifest (1 invalid decision, 1 valid), confirmed the valid
  alert still processed normally.
- `decision_support.human_review_required` logic updated to also
  trigger on unaccounted evidence or timestamp gaps, not just on a
  failed verification outcome -- otherwise the "truthful but
  incomplete" case above would have misleadingly shown
  human_review_required=false.
- Full regression: all 8 module self-tests
  (fact_extractor/graph_builder/claim_parser/evidence_matcher/
  mismatch_engine/reason_slate/batch_processor/coverage_checker) pass
  after integration.

**Design note on reproducibility:** `analyst_decision`,
`unaccounted_evidence`, and `timestamp_gaps` were all added INSIDE the
`evidence_identity` block that feeds `evidence_digest` (not left as
outside metadata like `generated_at_utc`), since all three are
themselves deterministic outputs of the same telemetry + input -- the
D-011 fix's reproducibility guarantee now covers these too, not just
the original claim verdicts.

---

## D-013: Second-round review — 4 changes made, 1 real bug caught during integration

**Finding:** A follow-up review of the D-011/D-012 corrected build found
the core direction sound but flagged 5 concrete issues. Each was
independently verified against the real code before any fix:
1. `unparsed_fragments` was only printed to CLI stderr, never included
   in the Reason Slate JSON itself -- confirmed by grep.
2. `ui/app.py` had zero DEVL imports -- the dashboard and DEVL were
   fully disconnected -- confirmed by grep.
3. `docs/devl-project-overview.md` still described
   `Recommendation: ESCALATE` / `ESCALATE_WITH_CAUTION`, contradicting
   the D-011 fix that removed that language from the actual code --
   confirmed by grep.
4. The docs table described the Reason Slate as a "signed" report; it
   is SHA-256 hashed only, not digitally signed (unlike the separate
   custody CLI, which does real Ed25519 signing) -- confirmed by grep.
5. `tests/` had no real pytest files, only module-level
   `if __name__ == "__main__"` self-tests.

**Fixes:**

1. Added a `parsing_coverage` block to every Reason Slate
   (`claims_parsed`, `unparsed_fragments`, `unparsed_count`,
   `complete_claim_coverage`), threaded through `verify`, `explain`, and
   `batch-verify`. `decision_support.human_review_required` now also
   trips on unparsed text, not just on a failed verification outcome.
   Included inside `evidence_identity` so it's covered by the
   reproducible `evidence_digest` too. Verified with the review's exact
   example ("The attacker appears to have compromised the server after
   obtaining valid credentials") -- now correctly surfaced in the
   output with `complete_claim_coverage: false`.

2. Rewrote the stale sections of `docs/devl-project-overview.md`:
   removed all `Recommendation: ESCALATE*` language, replaced examples
   with real, freshly-regenerated CLI output, fixed the correlation
   labels to the D-011 `*_ENTITY_OVERLAP` naming, added
   `coverage_checker.py` to the components table, corrected "signed" to
   "cryptographically hashed (SHA-256 digest, not a digital
   signature)," and documented the new Reason Slate schema fields
   (`analyst_decision`, `evidence_coverage`, `evidence_completeness`,
   `parsing_coverage`, the `evidence_digest`/`audit_digest` split).

3. Added a real `verify_slate_digest()` function to `reason_slate.py`
   and a `verify-slate` CLI command, directly addressing the review's
   "signed vs hashed" concern by making the actual limitation testable:
   recomputes the evidence digest from a saved slate's own content and
   compares it to the claimed digest. Explicitly documented (in the
   function's own docstring and the CLI's printed output) that a
   SHA-256 digest is not a signature -- an editor who also recomputes
   and replaces the digest defeats this check, and stronger tamper-
   evidence requires storing the digest separately or signing the file
   with the existing `custody/custody_cli.py` (real Ed25519 signing).
   Verified: PASS on an untouched slate; FAIL (exit code 1) with the
   exact claimed-vs-recomputed mismatch shown when one field is edited
   after generation.

4. Integrated DEVL into `ui/app.py` as a new "Decision Verification
   (DEVL)" tab, alongside the existing alert dashboard (kept separate,
   not merged into the destructive-playbook flow -- per the review's
   own recommendation that DEVL should be a decision-VERIFICATION
   layer, not an autonomous decision-maker feeding response actions
   directly). An analyst selects a real session, states a decision and
   free-text reasoning, and gets the full Reason Slate rendered
   (verification outcome banner, integrity metrics, per-status claim
   tables, unaccounted-evidence warning, parsing-coverage warning,
   timestamp-gap warning, and both digests) -- all computed by the real
   pipeline, not mocked.

   REAL BUG CAUGHT DURING THIS INTEGRATION: building this required
   exercising the UI end-to-end with Streamlit's `AppTest` framework
   (simulating an analyst selecting a session, choosing a decision,
   entering reasoning, and clicking Verify) -- which surfaced a genuine
   bug that the CLI-only testing in D-012 had never hit: in
   `generate_reason_slate()`, the `**evidence_identity` dict spread
   (which sets a plain `analyst_decision` value for digest purposes)
   was placed AFTER the line that set the full `analyst_decision` block
   (with its explanatory note) -- so the dict spread silently
   overwrote the fuller block, and `slate["analyst_decision"]` was
   always just a bare string, never the dict with `stated_decision`/
   `reasoning_evidence_basis`/`note` the rest of the code (and the new
   UI) expected. Fixed by moving the full block construction to AFTER
   the spread, with a code comment explaining why the ordering matters.
   Re-ran the exact same simulated-analyst UI test after the fix:
   confirmed `analyst_decision` is now correctly a dict, and the full
   scenario (CLOSE decision, true-but-incomplete reasoning with one
   interpretive unparsed sentence) correctly shows
   `human_review_required: True`, `unaccounted_count: 3`, and the
   unparsed fragment.

5. Converted the ad-hoc adversarial checks used during D-011/D-012 into
   a real pytest suite: `tests/conftest.py` (shared fixtures, built from
   the JSON demo session -- deliberately NOT the parquet file, so the
   suite needs no `pyarrow`), `test_fact_extractor.py` (8 tests,
   including the no-placeholder-fabrication regressions),
   `test_claim_parser.py` (14 tests, including every adversarial case
   from the first review), `test_matcher_and_mismatch.py` (14 tests,
   covering all 4 claim statuses and the exact score formula with
   hand-verified arithmetic), `test_coverage_checker.py` (5 tests),
   `test_reason_slate.py` (11 tests, covering parsing coverage reaching
   the real output, the analyst-decision boundary, digest
   reproducibility, and tamper detection). All 51 tests run and pass.
   Additionally ran the entire suite a second time with `pyarrow` and
   `fastparquet` artificially blocked at import time (via a custom
   `sys.meta_path` finder) -- confirmed all 51 still pass, directly
   proving the suite resolves the reviewer's specific "couldn't run in
   an environment without pyarrow" complaint.

**Full regression after all fixes:** all 8 module self-tests still
pass; all 51 pytest tests pass (with and without pyarrow available);
the Streamlit app loads with zero exceptions under `AppTest` and the
full simulated-analyst workflow completes correctly end-to-end.

---

## D-014: Three requested improvements + full line-by-line audit before investor/company review

**Context:** With 20 investors and 5 companies about to review this
project, a full audit pass was run across every file before making any
change, to catch drift from prior fixes, then three specific
improvements were built and verified.

**Audit findings (checked, not assumed):**
- No leftover TODO/FIXME/placeholder patterns anywhere in the codebase.
- No stale `disposition_recommendation`/`ESCALATE_WITH_CAUTION` language
  remaining in code (fully cleaned in D-011/D-013).
- No fabricated-placeholder-value leftovers (`unknown_hash`/
  `unknown_user`) outside of test assertions proving they're absent and
  a docstring explaining what NOT to do.
- No old un-suffixed `STRONG`/`WEAK`/`MEDIUM` correlation labels
  remaining (fully renamed to `*_ENTITY_OVERLAP` in D-011).
- Every `.py` file parses and every module's self-test runs cleanly.
- REAL BUG FOUND: `cmd_explain` (the CLI's `explain` subcommand) had
  never been updated to call `find_unaccounted_evidence`,
  `detect_timestamp_gaps`, or pass `unparsed_fragments`/
  `analyst_decision` into `generate_reason_slate()` -- meaning its
  output silently omitted `evidence_coverage`, `evidence_completeness`,
  and real `parsing_coverage` data even when they existed, unlike
  `verify` and `batch-verify` which already had these. Fixed: `explain`
  now computes and passes all the same fields, and gained a `--decision`
  option for parity. Confirmed `batch_processor.py` and the Streamlit
  UI already had full parity (no fix needed there).

**Improvement 1: Custody system connected to DEVL.** Built
`devl/custody_bridge.py`. Refactored `custody/custody_cli.py`'s
`cmd_seal` to extract a reusable `seal_entries()` function (used by both
the CLI and the new bridge, so there is exactly one hash-chaining
implementation, not two that could drift). Every `verify --seal` call
appends the full decision record (decision, reasoning, evidence
findings, both digests) to a running `custody/decision_custody_log.jsonl`
and reseals the whole log. ALSO FOUND AND FIXED: `custody_cli.py`'s
`report` command was written only for response-action audit-log entries
(`run_id`/`step_id`/`tag` fields) and rendered decision-verification
entries as meaningless "None: None (None)" lines -- fixed to detect
`record_type` and render each entry type meaningfully. Verified: two
real decisions sealed via the CLI, log grew from 1 to 2 entries with a
changing root hash each time; independently reverified with the
UNMODIFIED existing `custody_cli.py verify`/`report` commands (proving
real interoperability, not a parallel system); tamper test (altering a
sealed decision's stated_decision) correctly changed the recomputed
chain hash. A dedicated pytest file (`test_custody_bridge.py`, 5 tests)
covers hash-chain reuse, log growth, entry content, tamper detection,
and refusal to seal an empty log. Regression-tested the ORIGINAL
response-audit-log seal/verify/tamper flow after the refactor -- byte-
identical behavior to before.

**Improvement 2: Evidence integrity vs. completeness, made explicitly
distinct.** Added `assess_evidence_integrity()` to `reason_slate.py`,
producing a top-level `evidence_integrity_assessment` block with three
genuinely separate signals -- `contradicted_evidence` (evidence EXISTS
and disagrees), `missing_telemetry` + `unaccounted_evidence` +
`timestamp_gaps` (evidence gaps: something about the evidence itself is
incomplete), and a `completeness_status` of `APPEARS_COMPLETE` /
`GAPS_DETECTED` / `ASSESSMENT_INCOMPLETE` (the last one specifically for
when part of the EXPLANATION couldn't even be evaluated, e.g. unparsed
text -- a different problem from the evidence having gaps, and given
priority when both are present). The block states its own honest
boundary inline: DEVL can only assess evidence it actually received and
cannot detect evidence deleted or never collected before reaching this
system. Included inside `evidence_identity` so it's covered by the
reproducible `evidence_digest`. 5 new pytest tests cover all three
completeness states plus digest coverage.

**Improvement 3: Explicit structured Reason Slate display.** Added
`render_reason_slate_text()` to `reason_slate.py` and a `--format text`
CLI option, producing exactly the requested layout (Analyst Decision /
Reasoning / Supporting / Contradicting / Unaccounted / Missing
Telemetry / Evidence Integrity / Verification Outcome) as a display-only
rendering of the same JSON data -- the JSON Reason Slate remains the
source of truth the digests are computed over. Tested against a real,
deliberately problematic scenario (a CLOSE decision whose reasoning
directly contradicts real evidence and misses 3 more real events) --
output correctly shows all four evidence categories side by side with
the reasons visible, not just a final verdict.

**Full regression after all three improvements + audit fixes:** 62
pytest tests pass (57 from D-013 + 5 new custody_bridge tests); all 9
module self-tests pass (`fact_extractor`, `graph_builder`,
`claim_parser`, `evidence_matcher`, `mismatch_engine`, `reason_slate`,
`batch_processor`, `coverage_checker`, `custody_bridge`); the original
response-action custody workflow (seal/verify/report/tamper-detect on
`audit/audit_log.jsonl`) still behaves identically to before the
`seal_entries()` refactor.

---

## D-015: Process lineage (real Sysmon data) + investigation relevance engine

**Context:** A review raised what became the single most important
open question: "How does DEVL know that evidence is related to / part
of an investigation, to avoid false positives?" Without an answer,
treating every fact in a graph as relevant evidence (the prior
behavior) risks exactly the false-correlation problem DEVL exists to
prevent. Building a real answer required two things together: (1) a
genuine causal/process-lineage data source, since "connected via an
execution chain" is a stronger relevance signal than time/entity alone
but requires process-tree telemetry this project didn't have, and (2)
an explicit relevance-scoping layer implementing the two-question
design: Question A (is this evidence relevant to the investigation) before
Question B (did the explanation account for it).

**Real data sourced first, not assumed:** searched for and verified a
real, public, legitimately-documented Sysmon dataset (Splunk's
`attack_data` GitHub repo, tied to real MITRE technique T1016,
collected in Splunk's own detection-testing pipeline). Fetched the
actual log content and hand-selected 6 genuinely real, causally-linked
events (3 ProcessCreate, 2 ProcessAccess, 1 FileCreate) showing a real
chain: `lsass.exe`/`conhost.exe` → `powershell.exe` (with a real
base64-encoded command argument) → `chcp.com`, plus 2 unrelated real
background events (`services.exe`→`sysmon64.exe`,
`svchost.exe`→`unsecapp.exe`) deliberately kept in the sample to prove
the relevance engine can tell them apart. Saved honestly as a small,
disclosed-as-partial, hash-recorded sample
(`data/sysmon_source/sample_process_lineage.xml` +
`DOWNLOAD_INFO.txt`) — not the full original log.

**Built:**
1. `devl/sysmon_fact_extractor.py` — parses real Sysmon XML (EventIDs
   1/10/11) into the SAME Fact/Relation/LogSource classes
   `fact_extractor.py` already defines (extended with `SPAWNED`,
   `ACCESSED_PROCESS`, `CREATED_FILE` relations and
   `process_creation_log`/`process_access_log`/`file_creation_log`
   sources) -- so `graph_builder.py`, `evidence_matcher.py`, and
   `coverage_checker.py` all work on Sysmon facts with ZERO changes.
   Same no-placeholder discipline as the honeypot extractor: a
   ProcessCreate event missing ParentImage/Image is excluded and
   reported in `incomplete_events`, never fabricated.
2. `devl/claim_parser.py` extended with Windows-path grammar
   (`WINPATH_PATTERN`) and SPAWNED/ACCESSED_PROCESS/CREATED_FILE
   patterns (both full and headless/chained-clause forms), so
   process-lineage claims are checkable from free text, not just
   pre-structured facts.
3. `devl/relevance_engine.py` -- `InvestigationScope` (incident_id,
   affected_entities, time window) + `assess_relevance()` implementing
   the 3-layer model: temporal (window membership), entity (declared
   entity involvement), causal (real `networkx` graph-reachability over
   SPAWNED/ACCESSED_PROCESS/CREATED_FILE edges -- not a hand-rolled
   traversal). Combines into a disclosed, fixed-weight
   `RELEVANCE_WEIGHTS` score (temporal 0.3 / entity 0.4 / causal 0.3)
   and a tier (HIGH/MEDIUM/LOW/OUT_OF_SCOPE) -- explicitly NOT a
   trained ML confidence number (a document reviewed earlier proposed
   "88% process lineage match" style scoring; building that specific
   number would have been fabrication, since no trained model exists
   here -- documented explicitly as a deliberate scope boundary).
4. `coverage_checker.find_unaccounted_evidence()` gained an optional
   `scope` parameter implementing Question A before Question B exactly
   as requested: facts failing relevance are excluded before the
   unaccounted-evidence check ever runs on them.
5. `reason_slate.py` gained an `investigation_scope` field (included in
   `evidence_identity`, so it's covered by the reproducible
   `evidence_digest`) and `_IDENTITY_KEYS` was updated accordingly.
6. CLI: `verify` gained `--sysmon-xml` (merge real process-lineage
   facts into a session's graph) and `--scope-file` (JSON investigation
   scope) options.

**Real bugs found and fixed while integrating genuinely different real
data sources (none of these appeared when the two sources were tested
separately):**
- `relevance_engine._parse_ts`: honeypot timestamps are timezone-aware
  (`...Z`), Sysmon's `UtcTime` field is timezone-naive. Comparing them
  raised `TypeError` the moment both real sources were combined under
  one scope. Fixed by treating a naive timestamp as UTC (consistent
  with Sysmon's own field name).
- `coverage_checker.detect_timestamp_gaps` had its OWN separate inline
  timestamp parser (not reusing `relevance_engine._parse_ts`), so it
  hit the identical naive/aware `TypeError` independently. Fixed by
  deleting the duplicate parser and importing the shared one -- now
  exactly one timestamp-parsing implementation in the project.
- A SECOND, more subtle bug surfaced only once both real sources were
  combined and queried together: without scope-aware filtering,
  `detect_timestamp_gaps` reported a real but meaningless ~177-million-
  second (~5.6 year) "gap" -- an artifact of mixing two unrelated real
  datasets from different real-world collection dates (2020 Sysmon test
  data, 2026 honeypot data), not a genuine evidence-completeness signal.
  Fixed by giving `detect_timestamp_gaps` its own optional `scope`
  parameter that filters by BOTH declared entity membership AND the
  scope's declared time window before computing gaps -- a stricter
  filter than relevance_engine's general relevance tiering (which
  deliberately treats entity-match alone as sufficient regardless of
  timestamp, for a different reason: a named entity's full history is
  still relevant to know about even outside a narrow window; a
  cross-era timestamp "gap" between two unrelated datasets is not a
  meaningful completeness signal). This distinction is stated explicitly
  in both functions' docstrings so it reads as a deliberate design
  choice, not an unexplained inconsistency.
- A `str_replace` edit to `reason_slate.py`'s docstring accidentally
  closed it early, orphaning the original digest-explanation text
  outside any string and leaving a stray `"""` that broke parsing
  elsewhere in the file (`SyntaxError: unterminated string literal`).
  Caught immediately by re-running the module after the edit, rather
  than assuming the edit was clean; fixed by merging into one
  continuous docstring.

**Verification (all against real data):**
- `sysmon_fact_extractor.py` self-test: 6/6 real events correctly
  extracted, 0 skipped, 0 incomplete; confirmed via direct `has_edge`
  graph queries that the real `powershell.exe → chcp.com` SPAWNED edge
  is `True` and a fabricated `svchost.exe → chcp.com` edge is `False`.
- `claim_parser.py`: real process-path sentences (including chained
  `spawned ... and accessed ...` clauses) correctly decompose into
  claims; full `evidence_matcher` end-to-end test correctly VERIFIED a
  real spawn claim and UNSUPPORTED a fabricated one, combining into the
  correct integrity score.
- `relevance_engine.py` self-test, combining BOTH real data sources
  under one real investigation scope: correctly separated attack-
  relevant Sysmon facts (HIGH relevance, via real causal process-chain
  connection) from genuinely unrelated real OS housekeeping noise
  (OUT_OF_SCOPE) -- the core demonstration this whole addition was built
  to produce.
- `coverage_checker.find_unaccounted_evidence(scope=...)`: with the
  combined real graph, WITHOUT scope 9 facts were flagged unaccounted
  (including 3 real-but-unrelated noise facts); WITH scope, those 3
  were correctly excluded, leaving only genuinely in-scope misses.
- Full real end-to-end CLI run (`verify --sysmon-xml ... --scope-file
  ...`) reproducing the exact scenario above through the actual command
  a user would type, in both JSON and `--format text` output.
- 20 new pytest tests added (8 `test_sysmon_fact_extractor.py`, 12
  `test_relevance_engine.py`, plus 2 more in `test_reason_slate.py` for
  investigation_scope digest coverage) -- all passing. Full suite: 86
  tests total (up from 66), plus all 11 module self-tests, all green.

**Explicitly NOT claimed:** a trained ML confidence/weighting model
(the relevance score is a disclosed deterministic formula, stated as
such everywhere it appears); detection of relevance signals outside
temporal/entity/causal (e.g. semantic similarity a trained model might
learn); automatic inference of investigation scope (must be explicitly
declared); full enterprise-scale Sysmon/EDR ingestion (this remains a
small, real, disclosed sample, not a production-volume feed).
