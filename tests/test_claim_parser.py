from conftest import IP, REAL_HASH, FAKE_HASH
from claim_parser import parse_explanation


def _triples(result):
    return [(c.subject, c.relation, c.obj) for c in result.claims]


def test_single_claim():
    r = parse_explanation(f"{IP} connected to ssh:22.")
    assert _triples(r) == [(IP, "CONNECTED_TO", "ssh:22")]
    assert r.unparsed_fragments == []


def test_ip_address_is_not_split_on_its_own_periods():
    r = parse_explanation(f"{IP} authenticated as svc23.")
    assert _triples(r) == [(IP, "AUTHENTICATED_AS", "svc23")]


def test_multiple_sentences_yield_multiple_claims():
    r = parse_explanation(f"{IP} connected to ssh:22. {IP} authenticated as svc23.")
    assert len(r.claims) == 2


def test_two_claims_in_one_sentence_are_not_silently_lost():
    """Regression for the review's P0: only the first claim used to survive."""
    r = parse_explanation(f"{IP} connected to ssh:22 and authenticated as svc23.")
    assert _triples(r) == [(IP, "CONNECTED_TO", "ssh:22"), (IP, "AUTHENTICATED_AS", "svc23")]
    assert r.unparsed_fragments == []


def test_three_chained_clauses_including_a_contradiction():
    r = parse_explanation(
        f"{IP} connected to ssh:22 and authenticated as svc23, but authentication failed as svc23."
    )
    assert _triples(r) == [
        (IP, "CONNECTED_TO", "ssh:22"),
        (IP, "AUTHENTICATED_AS", "svc23"),
        (IP, "AUTH_FAILED_AS", "svc23"),
    ]
    assert r.unparsed_fragments == []


def test_contradiction_in_one_sentence_keeps_both_halves():
    r = parse_explanation(f"{IP} authenticated as svc23, but authentication failed as svc23.")
    relations = {c.relation for c in r.claims}
    assert relations == {"AUTHENTICATED_AS", "AUTH_FAILED_AS"}


def test_equivalent_phrasings_parse_to_the_same_relation():
    for phrase in ("connected to", "made a connection to", "reached out to"):
        r = parse_explanation(f"{IP} {phrase} ssh:22.")
        assert _triples(r) == [(IP, "CONNECTED_TO", "ssh:22")], phrase


def test_command_claim_is_captured():
    r = parse_explanation(f"{IP} executed the command 'uname -a && id'.")
    assert _triples(r) == [(IP, "EXECUTED", "uname -a && id")]


def test_payload_hash_claim_is_captured():
    r = parse_explanation(f"{IP} downloaded a malicious payload with hash {REAL_HASH}.")
    assert _triples(r) == [(IP, "DOWNLOADED_PAYLOAD", REAL_HASH)]


def test_malformed_hash_is_not_accepted_as_a_hash_claim():
    short = "deadbeef" + "0" * 20
    r = parse_explanation(f"{IP} downloaded a malicious payload with hash {short}.")
    assert r.claims == []
    assert r.unparsed_fragments  # surfaced, not silently dropped


def test_interpretive_sentence_is_surfaced_as_unparsed_not_forced_into_a_claim():
    r = parse_explanation("The attacker appears to have compromised the server after obtaining valid credentials.")
    assert r.claims == []
    assert len(r.unparsed_fragments) == 1


def test_unparseable_sentence_next_to_a_parseable_one_is_kept_visible():
    r = parse_explanation(f"{IP} connected to ssh:22. The weather was unusually suspicious that day.")
    assert len(r.claims) == 1
    assert any("weather" in f for f in r.unparsed_fragments)


def test_leftover_text_inside_a_partly_matched_sentence_is_reported():
    r = parse_explanation(f"{IP} connected to ssh:22 while wearing a hat.")
    assert len(r.claims) == 1
    assert any("hat" in f for f in r.unparsed_fragments)


def test_fabricated_well_formed_hash_still_parses_so_it_can_be_checked():
    r = parse_explanation(f"{IP} downloaded a malicious payload with hash {FAKE_HASH}.")
    assert _triples(r) == [(IP, "DOWNLOADED_PAYLOAD", FAKE_HASH)]
