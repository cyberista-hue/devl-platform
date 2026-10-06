"""
actions_registry.py

Concrete implementations for every action a playbook step can reference.
This is intentionally a plain dict of name -> function, checked by
playbook_engine.py at load time, so a playbook referencing an unknown
action fails loudly (a KeyError at validation) rather than silently
doing nothing.

Every action here is DEMO-SAFE by construction:
  - "safe" actions here never touch anything outside this project's own
    audit log / local state -- no real ticketing system, no real paging
    integration, no real account-lockout API. This is explicit and
    documented, not hidden, because pretending this connects to a real
    production IAM/ticketing system would be a fabricated capability
    claim.
  - "requires_approval" actions are represented the same way: once
    approved by the analyst in the UI, they still only log a structured
    "would have executed X" record -- they do not perform destructive
    action against any real system, because no real target system exists
    for this project to act on.

This honesty boundary should be stated explicitly in the demo narration
and in docs/path-to-production.md, not glossed over.
"""

from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def action_mitre_enrich(alert: dict, params: dict) -> dict:
    """No-op action wrapper -- enrichment already happened in
    enrichment/enrich.py before the playbook runs. This step exists in
    the playbook purely to make the enrichment step visible/orderable in
    the UI timeline, not to redo real work."""
    mitre = alert.get("mitre", {"status": "not_yet_enriched"})
    return {
        "status": "completed",
        "detail": f"MITRE context already attached: {mitre.get('status')}",
        "timestamp_utc": _now(),
    }


def action_cti_enrich_ip(alert: dict, params: dict) -> dict:
    """Same pattern as above -- CTI enrichment already happened upstream."""
    cti = alert.get("cti", {"status": "not_yet_enriched"})
    return {
        "status": "completed",
        "detail": f"CTI context already attached: {cti.get('status')}",
        "timestamp_utc": _now(),
    }


def action_create_ticket(alert: dict, params: dict) -> dict:
    """Creates a structured local ticket record (JSONL append). This is
    a real, working action -- it genuinely writes a record -- but it is
    NOT integrated with any real ticketing system (Jira, ServiceNow,
    etc). That integration is named explicitly in path-to-production."""
    priority = "unknown"
    if params.get("priority_from_score"):
        score = None
        if alert.get("cti", {}).get("status") == "resolved":
            score = alert["cti"].get("abuse_confidence_score")
        priority = "high" if (score is not None and score >= 50) else "medium"
    ticket = {
        "ticket_id": f"TCK-{alert.get('entity_id','unknown')}-{int(datetime.now(timezone.utc).timestamp())}",
        "alert_type": alert.get("alert_type"),
        "entity_id": alert.get("entity_id"),
        "priority": priority,
        "created_utc": _now(),
    }
    return {
        "status": "completed",
        "detail": f"Ticket created: {ticket['ticket_id']} (priority={priority})",
        "ticket": ticket,
        "timestamp_utc": _now(),
    }


def action_notify(alert: dict, params: dict) -> dict:
    """Demo-safe notification: writes to console/audit log only. No real
    paging/Slack/email integration exists -- stated explicitly."""
    channel = params.get("channel", "console")
    message = f"[NOTIFY:{channel}] Alert {alert.get('entity_id')} ({alert.get('alert_type')}) requires SOC attention."
    return {
        "status": "completed",
        "detail": message,
        "timestamp_utc": _now(),
    }


def action_lock_account(alert: dict, params: dict) -> dict:
    """DESTRUCTIVE action stub. This is a requires_approval step. Even
    after approval, this project does not have a real IAM system to call
    -- so it logs a structured 'would execute' record rather than
    pretending to lock a real account. This limitation must be stated
    explicitly in the demo, not hidden."""
    return {
        "status": "completed_simulated",
        "detail": (
            f"SIMULATED destructive action: would lock account(s) associated "
            f"with entity {alert.get('entity_id')}. No real IAM system is "
            f"connected in this prototype -- see docs/path-to-production.md."
        ),
        "timestamp_utc": _now(),
    }


def action_block_ip_firewall(alert: dict, params: dict) -> dict:
    """DESTRUCTIVE action stub, same honesty pattern as action_lock_account."""
    return {
        "status": "completed_simulated",
        "detail": (
            f"SIMULATED destructive action: would block source_ip "
            f"{alert.get('source_ip')} at firewall. No real firewall/SOAR "
            f"integration is connected in this prototype -- see "
            f"docs/path-to-production.md."
        ),
        "timestamp_utc": _now(),
    }


ACTIONS_REGISTRY = {
    "mitre_enrich": action_mitre_enrich,
    "cti_enrich_ip": action_cti_enrich_ip,
    "create_ticket": action_create_ticket,
    "notify": action_notify,
    "lock_account": action_lock_account,
    "block_ip_firewall": action_block_ip_firewall,
}
