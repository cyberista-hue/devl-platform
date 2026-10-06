import pytest

from conftest import IP, REAL_HASH
from fact_extractor import extract_facts_from_session, FactExtractionError, Relation


def test_extracts_the_real_facts_from_the_demo_session(session):
    facts, skipped, incomplete = extract_facts_from_session(session)
    triples = {(f.subject, f.relation, f.obj) for f in facts}
    assert (IP, Relation.CONNECTED_TO, "ssh:22") in triples
    assert (IP, Relation.AUTHENTICATED_AS, "svc23") in triples
    assert (IP, Relation.EXECUTED, "uname -a && id") in triples
    assert (IP, Relation.DOWNLOADED_PAYLOAD, REAL_HASH) in triples
    assert (IP, Relation.DISCONNECTED_FROM, "ssh:22") in triples


def test_facts_carry_real_timestamps_and_log_sources(session):
    facts, _, _ = extract_facts_from_session(session)
    payload = next(f for f in facts if f.relation == Relation.DOWNLOADED_PAYLOAD)
    assert payload.timestamp == "2026-07-01T00:42:17Z"
    assert payload.log_source == "payload_capture_log"


def test_banner_event_without_banner_text_is_not_fabricated_as_a_fact(session):
    """Regression: the real telemetry's client_banner events carry no banner
    text. They used to become SENT_BANNER facts with an empty-string object."""
    facts, _, incomplete = extract_facts_from_session(session)
    assert not any(f.relation == Relation.SENT_BANNER for f in facts)
    assert any("client_banner" in i["reason"] for i in incomplete)


def test_payload_event_missing_its_hash_is_excluded_not_given_a_placeholder(fresh):
    s = fresh()
    for e in s["events"]:
        if e["action"] == "payload_download":
            del e["payload_sha256"]
    facts, _, incomplete = extract_facts_from_session(s)
    assert not any(f.relation == Relation.DOWNLOADED_PAYLOAD for f in facts)
    assert not any(f.obj == "unknown_hash" for f in facts)
    assert any("payload_download" in i["reason"] for i in incomplete)


def test_command_event_with_no_command_is_excluded(fresh):
    s = fresh()
    for e in s["events"]:
        if e["action"] == "command":
            e["command"] = None
    facts, _, incomplete = extract_facts_from_session(s)
    assert not any(f.relation == Relation.EXECUTED for f in facts)
    assert any("command" in i["reason"] for i in incomplete)


def test_auth_event_with_no_username_is_excluded(fresh):
    s = fresh()
    for e in s["events"]:
        if e["action"] == "auth_success":
            e["username"] = None
    facts, _, incomplete = extract_facts_from_session(s)
    assert not any(f.obj == "unknown_user" for f in facts)
    assert not any(f.relation == Relation.AUTHENTICATED_AS for f in facts)


def test_unrecognised_action_is_reported_as_skipped_not_dropped(fresh):
    s = fresh()
    s["events"].append({"action": "teleport", "utc": "2026-07-01T00:42:19Z"})
    _, skipped, _ = extract_facts_from_session(s)
    assert any(e["action"] == "teleport" for e in skipped)


def test_session_missing_a_required_field_raises(fresh):
    s = fresh()
    del s["source_ip"]
    with pytest.raises(FactExtractionError):
        extract_facts_from_session(s)
