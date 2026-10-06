from pathlib import Path

import pytest

from sysmon_fact_extractor import extract_facts_from_sysmon_xml, SysmonExtractionError

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sysmon_source" / "sample_process_lineage.xml"

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CHCP = r"C:\Windows\System32\chcp.com"
LSASS = r"C:\Windows\system32\lsass.exe"


def test_extracts_the_real_spawned_chain():
    facts, _, _ = extract_facts_from_sysmon_xml(str(SAMPLE))
    triples = {(f.subject, f.relation, f.obj) for f in facts}
    assert (PS, "SPAWNED", CHCP) in triples


def test_extracts_real_process_access_and_file_creation():
    facts, _, _ = extract_facts_from_sysmon_xml(str(SAMPLE))
    triples = {(f.subject, f.relation, f.obj) for f in facts}
    assert (LSASS, "ACCESSED_PROCESS", PS) in triples
    assert any(f.relation == "CREATED_FILE" and f.subject == PS for f in facts)


def test_facts_carry_real_timestamps_and_log_sources():
    facts, _, _ = extract_facts_from_sysmon_xml(str(SAMPLE))
    spawned = next(f for f in facts if f.relation == "SPAWNED" and f.obj == CHCP)
    assert spawned.timestamp == "2020-11-10 13:59:56.687"
    assert spawned.log_source == "process_creation_log"


def test_six_real_events_yield_six_facts_zero_skipped():
    facts, skipped, incomplete = extract_facts_from_sysmon_xml(str(SAMPLE))
    assert len(facts) == 6
    assert skipped == []
    assert incomplete == []


def test_missing_file_raises():
    with pytest.raises(SysmonExtractionError):
        extract_facts_from_sysmon_xml("devl/samples/does_not_exist.xml")


def test_malformed_xml_raises(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<Events><Event>not closed")
    with pytest.raises(SysmonExtractionError):
        extract_facts_from_sysmon_xml(str(bad))


def test_process_create_missing_parent_image_is_excluded_not_fabricated(tmp_path):
    xml = """<Events>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><EventID>1</EventID><EventRecordID>999</EventRecordID></System>
<EventData>
<Data Name='UtcTime'>2020-01-01 00:00:00.000</Data>
<Data Name='Image'>C:\\test.exe</Data>
</EventData>
</Event>
</Events>"""
    f = tmp_path / "incomplete.xml"
    f.write_text(xml)
    facts, skipped, incomplete = extract_facts_from_sysmon_xml(str(f))
    assert facts == []
    assert len(incomplete) == 1
    assert "ParentImage" in incomplete[0]["reason"]


def test_unrecognised_event_id_is_skipped_not_dropped_silently(tmp_path):
    xml = """<Events>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><EventID>7</EventID><EventRecordID>42</EventRecordID></System>
<EventData><Data Name='Image'>C:\\test.dll</Data></EventData>
</Event>
</Events>"""
    f = tmp_path / "unrecognised.xml"
    f.write_text(xml)
    facts, skipped, incomplete = extract_facts_from_sysmon_xml(str(f))
    assert facts == []
    assert skipped == [{"event_record_id": "42", "event_id": "7"}]
