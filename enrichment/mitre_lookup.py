"""
mitre_lookup.py

Loads the local MITRE ATT&CK Enterprise STIX 2.1 bundle and provides
technique lookups by ATT&CK ID (e.g. "T1110" or "T1055.011").

Data source (verified, not fabricated):
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
Downloaded on: see data/mitre/DOWNLOAD_INFO.txt for the exact date/hash this
copy was pulled, so results are reproducible and traceable to a real source.

No network calls happen at runtime — this module reads the local JSON file
only, so it works offline on demo day.
"""

import json
from pathlib import Path
from functools import lru_cache

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre" / "enterprise-attack.json"


class MitreLookupError(Exception):
    """Raised when the local MITRE bundle is missing or a technique isn't found."""
    pass


@lru_cache(maxsize=1)
def _load_bundle():
    if not DATA_PATH.exists():
        raise MitreLookupError(
            f"MITRE ATT&CK bundle not found at {DATA_PATH}. "
            f"Run: curl -o {DATA_PATH} "
            f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        )
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["objects"]


@lru_cache(maxsize=1)
def _build_technique_index():
    """
    Build a dict keyed by ATT&CK technique ID (e.g. "T1110") mapping to the
    technique's real fields pulled directly from the STIX object — no
    invented fields.
    """
    objects = _load_bundle()
    index = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        # Skip revoked/deprecated techniques to avoid stale mappings
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break
        if not attack_id:
            continue
        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        index[attack_id] = {
            "technique_id": attack_id,
            "name": obj.get("name"),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "description": obj.get("description", ""),
            "url": next(
                (r.get("url") for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"),
                None
            ),
        }
    return index


def get_technique(attack_id: str) -> dict:
    """
    Look up a single technique by its ATT&CK ID (e.g. "T1110", "T1110.003").
    Raises MitreLookupError if not found — never returns a fabricated/guessed
    result.
    """
    index = _build_technique_index()
    if attack_id not in index:
        raise MitreLookupError(
            f"Technique '{attack_id}' not found in the local ATT&CK bundle "
            f"({len(index)} techniques loaded). Verify the ID at "
            f"https://attack.mitre.org/techniques/"
        )
    return index[attack_id]


def get_techniques(attack_ids: list) -> list:
    """Look up multiple technique IDs; raises on the first one not found."""
    return [get_technique(a) for a in attack_ids]


def technique_count() -> int:
    """Sanity-check helper — how many techniques are actually loaded."""
    return len(_build_technique_index())


if __name__ == "__main__":
    # Self-test against real data, not assumed values
    print(f"Loaded {technique_count()} non-deprecated techniques from local bundle.")
    for tid in ["T1110", "T1110.004", "T1059.001"]:
        t = get_technique(tid)
        print(f"{tid}: {t['name']} | tactics={t['tactics']}")
