import json
from pathlib import Path

import pytest

from conftest import IP
import custody_bridge as cb
import sys
sys.path.insert(0, str(cb.ROOT / "custody"))
from custody_cli import build_chain


@pytest.fixture
def log_paths(tmp_path):
    return tmp_path / "decision_custody_log.jsonl", tmp_path / "sealed.json"


def test_sealing_reuses_the_real_custody_hash_chain(pipeline, log_paths):
    """Confirms this module calls the SAME build_chain custody_cli.py uses
    for response-action audit logs -- not a second, parallel implementation."""
    log_path, sealed_path = log_paths
    slate = pipeline(f"{IP} connected to ssh:22.", decision="CLOSE")
    sealed = cb.append_and_reseal(slate, log_path=log_path, sealed_output_path=sealed_path)

    recomputed = build_chain(cb.read_decision_log(log_path))
    assert recomputed[-1]["link_hash"] == sealed["root_hash"]


def test_log_grows_across_multiple_decisions(pipeline, log_paths):
    log_path, sealed_path = log_paths
    slate1 = pipeline(f"{IP} connected to ssh:22.", decision="CLOSE")
    slate2 = pipeline(f"{IP} authenticated as svc23.", decision="ESCALATE")

    sealed1 = cb.append_and_reseal(slate1, log_path=log_path, sealed_output_path=sealed_path)
    assert sealed1["entry_count"] == 1

    sealed2 = cb.append_and_reseal(slate2, log_path=log_path, sealed_output_path=sealed_path)
    assert sealed2["entry_count"] == 2
    assert sealed2["root_hash"] != sealed1["root_hash"]  # chain changed, as it must


def test_custody_entry_preserves_the_decision_and_both_digests(pipeline, log_paths):
    log_path, _ = log_paths
    slate = pipeline(f"{IP} connected to ssh:22.", decision="FALSE_POSITIVE")
    entry = cb.append_to_decision_log(slate, log_path=log_path)
    assert entry["analyst_decision"]["stated_decision"] == "FALSE_POSITIVE"
    assert entry["evidence_digest"] == slate["evidence_digest"]
    assert entry["audit_digest"] == slate["audit_digest"]
    assert entry["record_type"] == "devl_decision_verification"


def test_tampering_with_a_sealed_decision_is_detected(pipeline, log_paths):
    log_path, sealed_path = log_paths
    slate = pipeline(f"{IP} connected to ssh:22.", decision="CLOSE")
    sealed = cb.append_and_reseal(slate, log_path=log_path, sealed_output_path=sealed_path)

    tampered_entries = json.loads(json.dumps(sealed["entries"]))  # deep copy via round-trip
    tampered_entries[0]["analyst_decision"]["stated_decision"] = "ESCALATE"
    tampered_chain = build_chain(tampered_entries)
    assert tampered_chain[-1]["link_hash"] != sealed["root_hash"]


def test_sealing_an_empty_log_is_refused(log_paths):
    log_path, _ = log_paths
    with pytest.raises(cb.CustodyBridgeError):
        cb.seal_decision_log(log_path=log_path)
