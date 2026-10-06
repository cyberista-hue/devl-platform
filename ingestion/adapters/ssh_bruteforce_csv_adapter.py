"""
ssh_bruteforce_csv_adapter.py

Second, independent data-source adapter -- proves the platform's
detection/enrichment/playbook logic is not coupled to the UBI Stage 6
honeypot dataset (see docs/decision-log.md D-005/D-006).

Source: a real, public SSH brute-force attempt dataset (kingabzpro's
GitHub gist, credited to a Kaggle dataset). See
data/second_source/DOWNLOAD_INFO.txt for exact provenance, hash, and an
HONEST SCOPE NOTE: this is a genuine but partial sample of the full
dataset (183 rows saved of a larger original), not the complete original.

Schema (real, verified against the actual file -- not assumed):
  username, timestamp, passwords, foreign_ip
No explicit success/failure flag exists in this dataset. Every row
represents a login ATTEMPT. Since this is not a honeypot with zero
legitimate traffic, this adapter is conservative about what it claims:
it flags IPs by attempt VOLUME (a proxy for brute-force behavior), not
by "confirmed malicious" status -- the alert is framed as "high-volume
login attempts from this source", which is honest given what the data
actually shows.
"""

import sys
from pathlib import Path
import pandas as pd
from dateutil import parser as date_parser

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from canonical_schema import validate_batch

SOURCE_DATASET_NAME = "public_ssh_bruteforce_csv"
DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "second_source" / "brute_force_data.csv"

# Threshold chosen to surface genuinely high-volume sources without
# flagging every single-attempt IP (which would be nearly all of them
# in this smaller/partial sample) -- documented, not hidden, see
# docs/decision-log.md.
MIN_ATTEMPTS_TO_ALERT = 5


class AdapterError(Exception):
    pass


def _require_file():
    if not DATA_PATH.exists():
        raise AdapterError(
            f"Required source file missing: {DATA_PATH}. This adapter will "
            f"not proceed with synthetic substitute data."
        )


def load_data() -> pd.DataFrame:
    _require_file()
    df = pd.read_csv(DATA_PATH)
    expected_cols = {"username", "timestamp", "passwords", "foreign_ip"}
    missing = expected_cols - set(df.columns)
    if missing:
        raise AdapterError(
            f"brute_force_data.csv is missing expected column(s): {missing}. "
            f"Schema may differ from what was verified -- re-check before trusting output."
        )
    return df


def _parse_timestamp(ts: str):
    """Real timestamps in this file look like 'Mon Nov 5 08:31:18 2018' --
    parse defensively; a malformed timestamp becomes None rather than
    silently crashing the whole batch."""
    try:
        return date_parser.parse(ts).isoformat()
    except (ValueError, TypeError):
        return None


def derive_bruteforce_alerts(df: pd.DataFrame) -> list:
    """
    Aggregates login attempts per source IP. An IP is flagged if its
    attempt count meets MIN_ATTEMPTS_TO_ALERT. This mirrors the same
    CONCEPTUAL pattern as the Stage 6 credential-stuffing rule (D-002:
    aggregate volume per source IP) but is applied to a completely
    independent dataset with a different schema and no honeypot
    assumption -- proving the platform's alert_type contract
    ("credential_stuffing_detected") is source-agnostic.
    """
    grouped = df.groupby("foreign_ip").agg(
        attempt_count=("username", "count"),
        usernames_tried=("username", lambda s: sorted(set(s.dropna()))),
        first_seen_raw=("timestamp", "min"),
        last_seen_raw=("timestamp", "max"),
    ).reset_index()

    alerts = []
    for _, row in grouped.iterrows():
        if row["attempt_count"] < MIN_ATTEMPTS_TO_ALERT:
            continue
        canonical_alert = {
            "alert_type": "credential_stuffing_detected",
            "entity_type": "source_ip",
            "entity_id": row["foreign_ip"],
            "source_ip": row["foreign_ip"],
            "source_dataset": SOURCE_DATASET_NAME,
            "first_seen_utc": _parse_timestamp(row["first_seen_raw"]),
            "last_seen_utc": _parse_timestamp(row["last_seen_raw"]),
            "raw_evidence": {
                "attempt_count": int(row["attempt_count"]),
                "usernames_tried": row["usernames_tried"],
                "note": (
                    "This dataset has no explicit success/failure flag; "
                    "every row is a login attempt. Alert reflects attempt "
                    "VOLUME, not a confirmed-malicious determination."
                ),
            },
            "is_demo_anchor": False,  # not part of the locked live-demo anchors
        }
        alerts.append(canonical_alert)

    alerts.sort(key=lambda a: a["raw_evidence"]["attempt_count"], reverse=True)
    return alerts


def run_adapter() -> dict:
    df = load_data()
    alerts = derive_bruteforce_alerts(df)
    alerts = validate_batch(alerts, adapter_name=SOURCE_DATASET_NAME)

    return {
        "reconciliation": {
            "source_dataset": SOURCE_DATASET_NAME,
            "total_rows_in_source": len(df),
            "distinct_source_ips": df["foreign_ip"].nunique(),
            "alert_threshold_attempts": MIN_ATTEMPTS_TO_ALERT,
            "credential_stuffing_alert_ips": len(alerts),
        },
        "credential_stuffing_alerts": alerts,
    }


if __name__ == "__main__":
    import json
    result = run_adapter()
    print(json.dumps(result["reconciliation"], indent=2))
    print()
    print("Top 3 flagged IPs:")
    for a in result["credential_stuffing_alerts"][:3]:
        print(f"  {a['entity_id']}: {a['raw_evidence']['attempt_count']} attempts, "
              f"usernames tried: {a['raw_evidence']['usernames_tried']}")
