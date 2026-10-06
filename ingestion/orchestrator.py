"""
orchestrator.py

Runs every registered data-source adapter and merges their canonical
alerts into one combined result. This is the ONLY module enrichment/
playbooks/UI should import from ingestion/ -- they should never import
a specific adapter directly, so adding a new data source never requires
touching downstream code (see docs/decision-log.md D-005).

Adding a new adapter = write adapters/<name>_adapter.py with a
run_adapter() function returning canonical-shaped alerts, then register
it in ADAPTERS below. Nothing else changes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "adapters"))

import stage6_honeypot_adapter
import ssh_bruteforce_csv_adapter

# Registry of active adapters. Each entry's run_adapter() must return the
# {"reconciliation": {...}, "payload_delivery_alerts": [...], ...} shape
# -- alert list keys vary per adapter (whatever alert_types it detects),
# so we merge dynamically rather than assuming fixed keys.
ADAPTERS = {
    "ubi_stage6_honeypot": stage6_honeypot_adapter,
    "public_ssh_bruteforce_csv": ssh_bruteforce_csv_adapter,
}


def run_all_adapters(only: list = None) -> dict:
    """
    Runs all registered adapters (or a subset named in `only`) and merges
    their alerts. Returns per-adapter reconciliation (so provenance/counts
    stay traceable to their real source) plus a merged alert list.
    """
    active = {k: v for k, v in ADAPTERS.items() if only is None or k in only}
    if not active:
        raise ValueError(f"No matching adapters for `only={only}`. Registered: {list(ADAPTERS.keys())}")

    per_adapter_reconciliation = {}
    all_alerts = []

    for name, module in active.items():
        result = module.run_adapter()
        per_adapter_reconciliation[name] = result["reconciliation"]
        # Merge every alert-type key this adapter returned (varies by adapter)
        for key, value in result.items():
            if key == "reconciliation":
                continue
            all_alerts.extend(value)

    return {
        "per_adapter_reconciliation": per_adapter_reconciliation,
        "alerts": all_alerts,
        "total_alerts": len(all_alerts),
        "sources_represented": sorted({a["source_dataset"] for a in all_alerts}),
    }


if __name__ == "__main__":
    import json
    result = run_all_adapters()
    print(json.dumps({
        "per_adapter_reconciliation": result["per_adapter_reconciliation"],
        "total_alerts": result["total_alerts"],
        "sources_represented": result["sources_represented"],
    }, indent=2))
