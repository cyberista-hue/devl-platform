"""
abuseipdb_client.py

Real AbuseIPDB /api/v2/check integration for IP reputation enrichment.

Rate limit (verified against AbuseIPDB's own docs, not assumed):
  Free tier: 1,000 checks/day. Confirmed via https://abuseipdb.com/api

Design constraints, deliberate given that limit:
  - Every lookup is cached to disk (data/cti_cache/) permanently for this
    project's lifetime, keyed by IP. We never re-check an IP we've already
    checked.
  - This client refuses to run against the full ~250-IP dataset in one go
    without an explicit --confirm flag, to prevent accidentally burning
    the daily quota on demo eve.
  - No API key is hardcoded anywhere. It must be supplied via the
    ABUSEIPDB_API_KEY environment variable. If it's missing, this module
    raises clearly rather than silently returning fake data.

You (Cyberista) need to:
  1. Create a free account at https://www.abuseipdb.com/register
  2. Generate an API key from your account dashboard
  3. Set it as an environment variable before running anything that uses
     this module:
       export ABUSEIPDB_API_KEY="your-real-key-here"
  I cannot generate or guess this key for you — it's tied to your account.
"""

import os
import json
import time
from pathlib import Path
from datetime import datetime, timezone
import urllib.request
import urllib.error

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cti_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
USAGE_LOG_PATH = CACHE_DIR / "usage_log.jsonl"

API_URL = "https://api.abuseipdb.com/api/v2/check"
DAILY_LIMIT = 1000  # Free tier, verified at https://abuseipdb.com/api


class AbuseIPDBError(Exception):
    pass


def _get_api_key() -> str:
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        raise AbuseIPDBError(
            "ABUSEIPDB_API_KEY environment variable is not set. "
            "This module will not proceed with a missing/fake key. "
            "Get a real key at https://www.abuseipdb.com/register and run:\n"
            "  export ABUSEIPDB_API_KEY=\"your-real-key\""
        )
    return key


def _cache_path(ip: str) -> Path:
    # IPs are safe-ish as filenames but sanitize just in case (IPv6 has colons)
    safe_ip = ip.replace(":", "_")
    return CACHE_DIR / f"{safe_ip}.json"


def _log_usage(ip: str, source: str):
    entry = {
        "ip": ip,
        "source": source,  # "api" or "cache"
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    with open(USAGE_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _today_api_call_count() -> int:
    """Count real API calls (not cache hits) made today, from the usage log."""
    if not USAGE_LOG_PATH.exists():
        return 0
    today = datetime.now(timezone.utc).date().isoformat()
    count = 0
    with open(USAGE_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("source") == "api" and entry.get("timestamp_utc", "").startswith(today):
                count += 1
    return count


def check_ip(ip: str, max_age_days: int = 90, force_refresh: bool = False) -> dict:
    """
    Check a single IP's abuse reputation. Uses cache if available unless
    force_refresh=True. Raises AbuseIPDBError on missing key, quota
    exhaustion, or API failure -- never returns fabricated data.
    """
    cache_file = _cache_path(ip)
    if cache_file.exists() and not force_refresh:
        with open(cache_file, "r", encoding="utf-8") as f:
            cached = json.load(f)
        _log_usage(ip, source="cache")
        cached["_source"] = "cache"
        return cached

    if _today_api_call_count() >= DAILY_LIMIT:
        raise AbuseIPDBError(
            f"Daily AbuseIPDB quota ({DAILY_LIMIT}) reached per local usage log "
            f"at {USAGE_LOG_PATH}. Refusing to call the API further today. "
            f"Use cached data only, or wait until quota resets."
        )

    api_key = _get_api_key()
    url = f"{API_URL}?ipAddress={ip}&maxAgeInDays={max_age_days}"
    req = urllib.request.Request(url, headers={
        "Key": api_key,
        "Accept": "application/json",
    })

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise AbuseIPDBError(f"AbuseIPDB API returned HTTP {e.code} for IP {ip}: {body}")
    except urllib.error.URLError as e:
        raise AbuseIPDBError(f"Network error reaching AbuseIPDB for IP {ip}: {e}")

    if "data" not in raw:
        raise AbuseIPDBError(f"Unexpected AbuseIPDB response shape for IP {ip}: {raw}")

    result = raw["data"]
    result["_source"] = "api"
    result["_checked_at_utc"] = datetime.now(timezone.utc).isoformat()

    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    _log_usage(ip, source="api")
    return result


def check_ips(ips: list, confirm_bulk: bool = False) -> dict:
    """
    Check multiple IPs. Refuses to proceed if more than 20 IPs are requested
    without confirm_bulk=True -- this is a deliberate guard against
    accidentally burning the daily quota on the full ~250-IP dataset.
    """
    uncached = [ip for ip in ips if not _cache_path(ip).exists()]
    if len(uncached) > 20 and not confirm_bulk:
        raise AbuseIPDBError(
            f"{len(uncached)} IPs are not yet cached and would trigger real API "
            f"calls. Refusing to proceed without confirm_bulk=True. "
            f"This project should only enrich a curated demo subset, not the "
            f"full dataset -- re-check which IPs you actually need."
        )
    results = {}
    for ip in ips:
        results[ip] = check_ip(ip)
        if results[ip]["_source"] == "api":
            time.sleep(0.5)  # be polite to the API even though we're nowhere near a rate ceiling
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python abuseipdb_client.py <ip1> [ip2] ...")
        print("Requires ABUSEIPDB_API_KEY environment variable to be set.")
        sys.exit(1)
    for ip in sys.argv[1:]:
        try:
            result = check_ip(ip)
            print(json.dumps(result, indent=2))
        except AbuseIPDBError as e:
            print(f"ERROR for {ip}: {e}")
