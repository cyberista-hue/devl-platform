"""
canonical_schema.py

Defines the single normalized alert shape that ALL data-source adapters
must produce. Enrichment (enrichment/enrich.py), the playbook engine
(playbooks/playbook_engine.py), and the UI all consume ONLY this shape --
none of them know anything about Stage 6's parquet columns, or any other
source's raw format. This is what decouples the platform from any one
data source (see docs/decision-log.md D-005).

An adapter's job is: read whatever raw format its source uses, and
return a list of dicts matching CanonicalAlert's required fields. Nothing
downstream should ever reach back into source-specific raw fields except
through the explicit `raw_evidence` passthrough field, which is treated
as opaque/source-specific supporting detail, not depended upon by
enrichment or playbook logic.
"""

REQUIRED_FIELDS = {
    "alert_type",       # str, e.g. "credential_stuffing_detected" -- must
                         # match a key in enrichment/enrich.py's TECHNIQUE_MAP
    "entity_type",       # str, e.g. "session" | "source_ip" | "host" | "user"
    "entity_id",         # str, stable unique identifier for this entity
    "source_ip",          # str or None -- required for CTI enrichment to run;
                          # None is valid (e.g. an insider-threat alert keyed
                          # on a username has no meaningful source_ip) but
                          # must be explicit, not omitted
    "source_dataset",     # str, which adapter/dataset this came from --
                          # e.g. "ubi_stage6_honeypot", "cicids2017" --
                          # REQUIRED so the UI can show provenance and prove
                          # multi-source support, not silently blend sources
    "first_seen_utc",     # ISO8601 str or None
    "last_seen_utc",      # ISO8601 str or None
    "raw_evidence",        # dict -- source-specific detail, passed through
                           # opaquely for display/audit, never required by
                           # enrichment or playbook logic
}


class SchemaValidationError(Exception):
    pass


def validate_alert(alert: dict, adapter_name: str = "unknown") -> dict:
    """Every adapter MUST call this before returning alerts. Raises loudly
    on a missing field rather than letting a malformed alert silently
    flow into enrichment (which would then fail in a confusing way, or
    worse, silently produce a wrong/empty enrichment)."""
    missing = REQUIRED_FIELDS - set(alert.keys())
    if missing:
        raise SchemaValidationError(
            f"Adapter '{adapter_name}' produced an alert missing required "
            f"canonical field(s): {missing}. Alert entity_id (if present): "
            f"{alert.get('entity_id', '<missing>')}"
        )
    return alert


def validate_batch(alerts: list, adapter_name: str = "unknown") -> list:
    return [validate_alert(a, adapter_name) for a in alerts]
