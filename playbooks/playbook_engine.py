"""
playbook_engine.py

Loads a playbook YAML file, validates it against the required shape
(playbook_schema.yaml), and executes it against a single enriched alert.

Execution model (locked in earlier in the conversation):
  - "safe" steps execute immediately, no gate.
  - "requires_approval" steps are NOT executed on first pass. Instead a
    pending-approval record is created and execution PAUSES at that step.
    A separate call (approve_step / reject_step) is required to proceed.
  - Every step's outcome (auto-run or approved/rejected) is appended to a
    structured, machine-parseable audit log (JSONL) -- this is a direct
    fix for the Stage 6 recurring lesson: "no machine-readable test/audit
    output, only print statements."
"""

import json
import yaml
from pathlib import Path
from datetime import datetime, timezone

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from actions_registry import ACTIONS_REGISTRY

AUDIT_LOG_PATH = Path(__file__).resolve().parent.parent / "audit" / "audit_log.jsonl"
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

REQUIRED_PLAYBOOK_FIELDS = {"playbook_id", "name", "description", "mitre_techniques", "trigger", "steps"}
REQUIRED_STEP_FIELDS = {"step_id", "title", "action", "tag", "description"}
VALID_TAGS = {"safe", "requires_approval"}


class PlaybookValidationError(Exception):
    pass


class PlaybookExecutionError(Exception):
    pass


def load_playbook(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        playbook = yaml.safe_load(f)

    missing = REQUIRED_PLAYBOOK_FIELDS - set(playbook.keys())
    if missing:
        raise PlaybookValidationError(f"Playbook {path} missing required field(s): {missing}")

    for step in playbook["steps"]:
        missing_step_fields = REQUIRED_STEP_FIELDS - set(step.keys())
        if missing_step_fields:
            raise PlaybookValidationError(
                f"Playbook {path}, step {step.get('step_id','?')} missing field(s): {missing_step_fields}"
            )
        if step["tag"] not in VALID_TAGS:
            raise PlaybookValidationError(
                f"Playbook {path}, step {step['step_id']} has invalid tag "
                f"'{step['tag']}' -- must be one of {VALID_TAGS}. No default "
                f"is assumed for an invalid/missing tag."
            )
        if step["action"] not in ACTIONS_REGISTRY:
            raise PlaybookValidationError(
                f"Playbook {path}, step {step['step_id']} references unknown "
                f"action '{step['action']}'. Known actions: {list(ACTIONS_REGISTRY.keys())}"
            )

    return playbook


def _append_audit(entry: dict):
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


class PlaybookRun:
    """Represents one execution of one playbook against one alert.
    Tracks position so a requires_approval step can pause execution and
    be resumed later after an explicit analyst decision."""

    def __init__(self, playbook: dict, alert: dict):
        self.playbook = playbook
        self.alert = alert
        self.run_id = f"RUN-{playbook['playbook_id']}-{alert.get('entity_id')}-{int(datetime.now(timezone.utc).timestamp())}"
        self.step_index = 0
        self.completed_steps = []
        self.status = "in_progress"  # in_progress | awaiting_approval | completed
        self.pending_step = None

    def _log(self, step: dict, outcome: dict, decision: str = None):
        entry = {
            "run_id": self.run_id,
            "playbook_id": self.playbook["playbook_id"],
            "alert_entity_id": self.alert.get("entity_id"),
            "alert_type": self.alert.get("alert_type"),
            "step_id": step["step_id"],
            "step_title": step["title"],
            "tag": step["tag"],
            "decision": decision,  # None for safe steps, "approved"/"rejected" for gated ones
            "outcome": outcome,
            "logged_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        _append_audit(entry)
        return entry

    def run(self):
        """Runs steps until completion or until a requires_approval step
        is hit, at which point it pauses (status becomes awaiting_approval)."""
        steps = self.playbook["steps"]
        while self.step_index < len(steps):
            step = steps[self.step_index]
            if step["tag"] == "safe":
                action_fn = ACTIONS_REGISTRY[step["action"]]
                outcome = action_fn(self.alert, step.get("params", {}) or {})
                entry = self._log(step, outcome)
                self.completed_steps.append(entry)
                self.step_index += 1
            elif step["tag"] == "requires_approval":
                self.status = "awaiting_approval"
                self.pending_step = step
                entry = self._log(step, {"status": "pending_approval"}, decision="pending")
                return self  # PAUSE -- do not proceed without explicit approval
        self.status = "completed"
        return self

    def approve_pending(self):
        if self.status != "awaiting_approval" or self.pending_step is None:
            raise PlaybookExecutionError("No step is currently awaiting approval.")
        step = self.pending_step
        action_fn = ACTIONS_REGISTRY[step["action"]]
        outcome = action_fn(self.alert, step.get("params", {}) or {})
        entry = self._log(step, outcome, decision="approved")
        self.completed_steps.append(entry)
        self.pending_step = None
        self.status = "in_progress"
        self.step_index += 1
        return self.run()  # continue to next step (may hit another gate)

    def reject_pending(self, reason: str = ""):
        if self.status != "awaiting_approval" or self.pending_step is None:
            raise PlaybookExecutionError("No step is currently awaiting approval.")
        step = self.pending_step
        entry = self._log(step, {"status": "rejected", "reason": reason}, decision="rejected")
        self.completed_steps.append(entry)
        self.pending_step = None
        self.status = "completed_with_rejection"
        return self


def run_playbook(playbook_path: str, alert: dict) -> PlaybookRun:
    playbook = load_playbook(playbook_path)
    run = PlaybookRun(playbook, alert)
    return run.run()


if __name__ == "__main__":
    # Self-test with a minimal synthetic alert -- proves the engine's
    # control flow (safe steps run, requires_approval pauses, approve
    # resumes) works correctly. Real alerts come from ingestion+enrichment.
    test_alert = {
        "alert_type": "credential_stuffing_detected",
        "entity_id": "TEST-IP-0.0.0.0",
        "source_ip": "0.0.0.0",
        "mitre": {"status": "resolved", "techniques": []},
        "cti": {"status": "unavailable"},
    }
    import tempfile, os
    test_playbook_yaml = """
playbook_id: test-playbook-v1
name: "Test Playbook"
description: "Self-test only"
mitre_techniques: ["T1110.004"]
trigger:
  alert_type: "credential_stuffing_detected"
steps:
  - step_id: "01"
    title: "Safe step"
    action: "notify"
    tag: safe
    params: {channel: "console"}
    description: "test"
  - step_id: "02"
    title: "Gated step"
    action: "lock_account"
    tag: requires_approval
    params: {}
    description: "test"
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(test_playbook_yaml)
        tmp_path = f.name

    run = run_playbook(tmp_path, test_alert)
    print(f"Status after first run(): {run.status}")
    assert run.status == "awaiting_approval", "Expected engine to pause at requires_approval step"

    run.approve_pending()
    print(f"Status after approve_pending(): {run.status}")
    assert run.status == "completed", "Expected engine to complete after approval"

    os.unlink(tmp_path)
    print("\nSelf-test passed: safe steps auto-run, requires_approval steps pause and resume correctly.")
    print(f"Audit log written to: {AUDIT_LOG_PATH}")
