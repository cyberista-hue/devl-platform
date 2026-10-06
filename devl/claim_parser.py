"""
claim_parser.py

Component 3 of DEVL: Proposed Explanation Claim Parser.

Decomposes a free-text explanation (from an AI copilot, an analyst's
own notes, or a rule engine's description) into discrete, verifiable
claims -- deterministic regex-based extraction, per the DEVL spec
("deterministic regex/NER model").

DESIGN CHOICE, stated honestly: a full statistical NER model needs
labeled training data this project does not have. A deterministic
pattern-grammar is the other option the spec itself names, and it has a
real advantage for THIS use case: every match is explainable and
reproducible (the same input always parses the same way), which matters
for an audit-grade tool more than raw NLP coverage would. The tradeoff,
stated honestly: this parser only recognizes the relation patterns it
has grammar rules for. An explanation using very different phrasing may
not decompose fully -- unmatched text is preserved and surfaced, never
silently dropped, so the gap is visible rather than hidden.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


IP_PATTERN = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
HASH_PATTERN = r"[a-f0-9]{64}"  # sha256 hex
HOSTPORT_PATTERN = r"[\w\-\.]+:\d+"
WINPATH_PATTERN = r"[A-Za-z]:\\\S+\.\w+"  # a Windows file/process path ending in an extension


class Relation:
    CONNECTED_TO = "CONNECTED_TO"
    DISCONNECTED_FROM = "DISCONNECTED_FROM"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    AUTH_FAILED_AS = "AUTH_FAILED_AS"
    EXECUTED = "EXECUTED"
    DOWNLOADED_PAYLOAD = "DOWNLOADED_PAYLOAD"
    SENT_BANNER = "SENT_BANNER"
    SPAWNED = "SPAWNED"
    ACCESSED_PROCESS = "ACCESSED_PROCESS"
    CREATED_FILE = "CREATED_FILE"


# Maps each relation to the log source that would be needed to verify a
# claim using it -- mirrors Component 4's `required_log` field in the
# spec's pseudocode, so a claim can be flagged MISSING_TELEMETRY when
# the needed log source wasn't collected, distinct from UNSUPPORTED.
RELATION_REQUIRED_LOG = {
    Relation.CONNECTED_TO: "network_session_log",
    Relation.DISCONNECTED_FROM: "network_session_log",
    Relation.AUTHENTICATED_AS: "auth_log",
    Relation.AUTH_FAILED_AS: "auth_log",
    Relation.EXECUTED: "command_exec_log",
    Relation.DOWNLOADED_PAYLOAD: "payload_capture_log",
    Relation.SENT_BANNER: "banner_log",
    Relation.SPAWNED: "process_creation_log",
    Relation.ACCESSED_PROCESS: "process_access_log",
    Relation.CREATED_FILE: "file_creation_log",
}


@dataclass
class Claim:
    subject: str
    relation: str
    obj: str
    required_log: str
    raw_text: str  # the exact sentence fragment this claim was parsed from


@dataclass
class ParseResult:
    claims: list = field(default_factory=list)
    unparsed_fragments: list = field(default_factory=list)


# Each grammar rule: (compiled regex, relation, group index for subject, group index for object)
# Patterns are intentionally permissive about phrasing ("connected to" /
# "made a connection to") but strict about requiring a real-looking
# entity (IP regex, hash regex, host:port regex) as the object -- this
# is what keeps false-positive parses low.
_GRAMMAR = [
    (re.compile(rf"({IP_PATTERN})\s+(?:connected to|made a connection to|reached out to)\s+({HOSTPORT_PATTERN}|{IP_PATTERN}(?::\d+)?)", re.I),
     Relation.CONNECTED_TO),
    (re.compile(rf"({IP_PATTERN})\s+(?:disconnected from)\s+({HOSTPORT_PATTERN}|{IP_PATTERN}(?::\d+)?)", re.I),
     Relation.DISCONNECTED_FROM),
    (re.compile(rf"({IP_PATTERN})\s+(?:authenticated as|logged in as|successfully authenticated as)\s+([\w\-\.]+)", re.I),
     Relation.AUTHENTICATED_AS),
    (re.compile(rf"({IP_PATTERN})\s+(?:failed to authenticate as|attempted to log in as)\s+([\w\-\.]+)", re.I),
     Relation.AUTH_FAILED_AS),
    (re.compile(rf"({IP_PATTERN})\s+(?:executed|ran)\s+(?:the command\s+)?['\"]?([^'\".;]+)['\"]?", re.I),
     Relation.EXECUTED),
    (re.compile(rf"({IP_PATTERN})\s+(?:downloaded(?:\s+a)?(?:\s+malicious)?\s+payload(?:\s+with hash)?)\s*[:\-]?\s*({HASH_PATTERN})", re.I),
     Relation.DOWNLOADED_PAYLOAD),
    (re.compile(rf"({IP_PATTERN})\s+(?:downloaded(?:\s+a)?(?:\s+malicious)?\s+payload\s+from)\s+({IP_PATTERN})", re.I),
     Relation.DOWNLOADED_PAYLOAD),  # variant: object is a source IP, not a hash -- still parseable, checked against graph as-is
    (re.compile(rf"({IP_PATTERN})\s+(?:sent(?:\s+a)?\s+banner)\s*[:\-]?\s*(.+)", re.I),
     Relation.SENT_BANNER),
    # Process-lineage patterns (Windows Sysmon-style paths, e.g.
    # "C:\Windows\System32\powershell.exe") -- a genuinely different
    # entity format from the IP-anchored patterns above, added for real
    # Sysmon process-creation/access/file-creation facts (see
    # sysmon_fact_extractor.py, docs/decision-log.md D-015).
    (re.compile(rf"({WINPATH_PATTERN})\s+(?:spawned|launched|created process)\s+({WINPATH_PATTERN})", re.I),
     Relation.SPAWNED),
    (re.compile(rf"({WINPATH_PATTERN})\s+(?:accessed|accessed process)\s+({WINPATH_PATTERN})", re.I),
     Relation.ACCESSED_PROCESS),
    (re.compile(rf"({WINPATH_PATTERN})\s+(?:created file|created the file|wrote file|wrote the file)\s+({WINPATH_PATTERN})", re.I),
     Relation.CREATED_FILE),
]


# "Headless" variants of the same relation phrases -- no leading IP
# capture group -- used for continuation clauses that share an implied
# subject with an earlier clause in the same fragment (e.g. "X
# connected to Y AND authenticated as Z" -- the second clause has no
# explicit subject of its own). Group 1 here is the object, not the
# subject -- the real subject is supplied separately via carryover.
_HEADLESS_GRAMMAR = [
    (re.compile(rf"^(?:connected to|made a connection to|reached out to)\s+({HOSTPORT_PATTERN}|{IP_PATTERN}(?::\d+)?)", re.I),
     Relation.CONNECTED_TO),
    (re.compile(rf"^(?:disconnected from)\s+({HOSTPORT_PATTERN}|{IP_PATTERN}(?::\d+)?)", re.I),
     Relation.DISCONNECTED_FROM),
    (re.compile(rf"^(?:authenticated as|logged in as|successfully authenticated as)\s+([\w\-\.]+)", re.I),
     Relation.AUTHENTICATED_AS),
    (re.compile(rf"^(?:failed to authenticate as|authentication failed as|attempted to log in as)\s+([\w\-\.]+)", re.I),
     Relation.AUTH_FAILED_AS),
    (re.compile(rf"^(?:executed|ran)\s+(?:the command\s+)?['\"]?([^'\".;]+)['\"]?", re.I),
     Relation.EXECUTED),
    (re.compile(rf"^(?:downloaded(?:\s+a)?(?:\s+malicious)?\s+payload(?:\s+with hash)?)\s*[:\-]?\s*({HASH_PATTERN})", re.I),
     Relation.DOWNLOADED_PAYLOAD),
    (re.compile(rf"^(?:spawned|launched|created process)\s+({WINPATH_PATTERN})", re.I),
     Relation.SPAWNED),
    (re.compile(rf"^(?:accessed|accessed process)\s+({WINPATH_PATTERN})", re.I),
     Relation.ACCESSED_PROCESS),
    (re.compile(rf"^(?:created file|created the file|wrote file|wrote the file)\s+({WINPATH_PATTERN})", re.I),
     Relation.CREATED_FILE),
]


def _try_headless_match(text: str, subject: str):
    """Attempts to match a subject-less continuation clause, using a
    carried-over subject from earlier in the same fragment. Strips
    leading connector words (and/but/,) before attempting the match.
    Returns (relation, obj, cleaned_text, consumed_end_index) so the
    caller can correctly compute the remainder from the SAME cleaned
    string the match was found against -- slicing against the original
    unstripped text here would misalign indices."""
    cleaned = re.sub(r"^(?:(?:and|but|,|;)\s*)+", "", text.strip(), flags=re.I).strip()
    for pattern, relation in _HEADLESS_GRAMMAR:
        m = pattern.match(cleaned)
        if m:
            obj = m.group(1).strip()
            return relation, obj, cleaned, m.end()
    return None


def _extract_headless_chain(text: str, subject: str) -> tuple:
    """
    Repeatedly applies _try_headless_match to `text`, extracting EVERY
    chained subject-less clause it can (e.g. "and authenticated as X,
    but authentication failed as X" has TWO headless clauses, not one --
    a real bug found in review: the original code only attempted a
    single headless match and left any further chained clauses as an
    opaque unparsed string, even when they were individually
    recognizable). Returns (claims_found: list[Claim], final_leftover: str).
    """
    claims_found = []
    remaining = text
    while True:
        if not remaining.strip(" ,.;-") or subject is None:
            break
        headless = _try_headless_match(remaining, subject)
        if not headless:
            break
        h_relation, h_obj, h_cleaned, h_end = headless
        claims_found.append(Claim(
            subject=subject, relation=h_relation, obj=h_obj,
            required_log=RELATION_REQUIRED_LOG[h_relation],
            raw_text=f"(implied subject: {subject}) {h_cleaned[:h_end]}",
        ))
        remaining = h_cleaned[h_end:]
    return claims_found, remaining.strip(" ,.;-")


def parse_explanation(text: str) -> ParseResult:
    """
    Splits the explanation into sentence-like fragments (period+whitespace,
    ';', or newline boundaries -- not bare periods, which would split IP
    addresses). Within EACH fragment, repeatedly scans for EVERY grammar
    match, not just the first -- a single fragment can and often does
    contain multiple distinct claims. Two passes are made:
      1. Full IP-anchored matches (subject explicitly stated).
      2. For any leftover span, a "headless" match using the SUBJECT
         CARRIED OVER from the most recent full match in the same
         fragment -- this is what lets "X connected to Y and
         authenticated as Z" correctly yield TWO claims (both
         attributed to X) instead of silently losing the second one.
         This was a real bug found in review: the original version
         stopped at the first matching rule per fragment and discarded
         everything after it, including cases where the discarded text
         was a second, CONTRADICTING claim (e.g. "authenticated as X,
         but authentication failed as X" used to silently keep only
         the first half).

    Any text still not covered by either pass is preserved in
    `unparsed_fragments` -- genuinely unrecognized phrasing stays
    visible, never silently dropped or forced into a false match.
    """
    raw_fragments = [f.strip() for f in re.split(r"\.\s+|[;\n]", text) if f.strip()]
    raw_fragments = [f[:-1].strip() if f.endswith(".") else f for f in raw_fragments]
    result = ParseResult()

    for fragment in raw_fragments:
        all_matches = []
        for pattern, relation in _GRAMMAR:
            for m in pattern.finditer(fragment):
                all_matches.append((m.start(), m.end(), m, relation))

        if not all_matches:
            result.unparsed_fragments.append(fragment)
            continue

        all_matches.sort(key=lambda t: (t[0], -(t[1] - t[0])))
        selected = []
        last_end = -1
        for start, end, m, relation in all_matches:
            if start >= last_end:
                selected.append((start, end, m, relation))
                last_end = end

        cursor = 0
        carried_subject = None
        for start, end, m, relation in selected:
            gap = fragment[cursor:start]
            if gap.strip(" ,.;-"):
                chain_claims, leftover = _extract_headless_chain(gap, carried_subject)
                result.claims.extend(chain_claims)
                if leftover:
                    result.unparsed_fragments.append(leftover)

            subject = m.group(1).strip()
            obj = m.group(2).strip()
            result.claims.append(Claim(
                subject=subject, relation=relation, obj=obj,
                required_log=RELATION_REQUIRED_LOG[relation],
                raw_text=fragment[start:end],
            ))
            carried_subject = subject
            cursor = end

        trailing = fragment[cursor:]
        if trailing.strip(" ,.;-"):
            chain_claims, leftover = _extract_headless_chain(trailing, carried_subject)
            result.claims.extend(chain_claims)
            if leftover:
                result.unparsed_fragments.append(leftover)

    return result


if __name__ == "__main__":
    # Self-test with a mix of TRUE, FALSE, and unparseable sentences --
    # proves the grammar actually discriminates, not just pattern-matches
    # everything as "a claim".
    test_explanation = (
        "198.51.100.155 connected to ssh:22. "
        "198.51.100.155 authenticated as svc23. "
        "198.51.100.155 executed the command 'uname -a && id'. "
        "198.51.100.155 downloaded a malicious payload with hash 6cac3bae3e6b9c949bfc114ff6d127cf141eefe4e8f544ce5261c5ef355008c8. "
        "198.51.100.155 downloaded a malicious payload with hash deadbeef00000000000000000000000000000000000000000000000000000000. "
        "The weather was unusually suspicious that day."
    )
    result = parse_explanation(test_explanation)
    print(f"Parsed {len(result.claims)} claims:")
    for c in result.claims:
        print(f"  ({c.subject}) --{c.relation}--> ({c.obj})  [requires: {c.required_log}]")
    print(f"\nUnparsed fragments ({len(result.unparsed_fragments)}):")
    for f in result.unparsed_fragments:
        print(f"  '{f}'")
