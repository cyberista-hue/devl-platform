"""
explanation_generator.py

Generates a candidate natural-language explanation for a real alert
using the OpenAI API -- this is the "AI Copilot" input the DEVL
architecture spec describes as one possible source of a proposed
explanation. The output of this module is NEVER trusted directly --
it is always passed through claim_parser.py + evidence_matcher.py +
mismatch_engine.py before being shown to an analyst, exactly per the
DEVL design: this generator is allowed to be wrong, because the
verification layer's whole job is to catch it if it is.

Requires your own OPENAI_API_KEY (no key is bundled or hardcoded; the
OpenAI API is billed per token, not free -- see docs/decision-log.md
for current pricing notes, verified via live search on 2026-09-24).
Get one at https://platform.openai.com/api-keys and set it:
    export OPENAI_API_KEY="your-real-key-here"

The prompt is deliberately constrained: the model is given ONLY the
real Fact Triples already extracted from telemetry (never raw session
data it could over-interpret) and instructed to describe only what it's
given -- it is not asked to speculate. This does not guarantee a
hallucination-free explanation (no prompt can guarantee that), which is
exactly why the verification layer downstream exists and does not trust
this module's output.
"""

import os
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fact_extractor import Fact

API_URL = "https://api.openai.com/v1/chat/completions"
# gpt-5.4-mini: a real, current, cost-efficient OpenAI model as of this
# build (verified via live search 2026-09-24: $0.75/1M input, $4.50/1M
# output) -- more than sufficient for a short, constrained explanation
# task like this one. Change via the MODEL constant if a different tier
# is preferred.
MODEL = "gpt-5.4-mini"


class ExplanationGeneratorError(Exception):
    pass


def _facts_to_prompt_text(facts: list) -> str:
    lines = []
    for f in facts:
        lines.append(f"- {f.subject} {f.relation} {f.obj} (source: {f.log_source}, time: {f.timestamp})")
    return "\n".join(lines)


def generate_explanation(facts: list, alert_context: str = "") -> str:
    """
    Calls the real OpenAI API to generate a candidate explanation from
    real Fact Triples. Raises ExplanationGeneratorError with a clear
    message if no API key is set or the call fails -- never returns a
    fabricated explanation as a fallback.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ExplanationGeneratorError(
            "OPENAI_API_KEY environment variable is not set. This module will "
            "not proceed without a real key -- there is no fallback explanation. "
            "Get a key at https://platform.openai.com/api-keys and run:\n"
            "  export OPENAI_API_KEY=\"your-real-key\"\n"
            "Note: the OpenAI API is billed per token (not free) -- a handful "
            "of short prompts like this one typically costs a few cents."
        )

    facts_text = _facts_to_prompt_text(facts)
    system_prompt = (
        "You are assisting a SOC analyst by drafting a plain-language explanation "
        "of an alert, based ONLY on the telemetry facts provided below. "
        "Do not invent, assume, or infer any event, entity, or relationship that is "
        "not explicitly listed. Write 2-4 sentences describing what happened, in "
        "the same subject-relation-object style as the facts. Every factual claim "
        "you make must correspond to one of the listed facts -- do not add "
        "conclusions like 'this is malicious' or speculate about intent; only "
        "describe what was observed."
    )
    user_prompt = f"Alert context: {alert_context}\n\nTelemetry facts:\n{facts_text}\n\nDraft the explanation."

    body = json.dumps({
        "model": MODEL,
        "max_tokens": 400,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        API_URL, data=body,
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        raise ExplanationGeneratorError(f"OpenAI API returned HTTP {e.code}: {error_body}")
    except urllib.error.URLError as e:
        raise ExplanationGeneratorError(f"Network error reaching OpenAI API: {e}")

    choices = raw.get("choices", [])
    if not choices:
        raise ExplanationGeneratorError(f"Unexpected OpenAI API response shape (no choices): {raw}")

    message = choices[0].get("message", {})
    text = message.get("content", "").strip()
    if not text:
        raise ExplanationGeneratorError(f"Unexpected OpenAI API response shape (empty content): {raw}")

    return text


if __name__ == "__main__":
    import pandas as pd
    from fact_extractor import extract_facts_from_session

    sessions_path = Path(__file__).resolve().parent.parent / "data" / "stage6_source" / "sessions.parquet"
    df = pd.read_parquet(sessions_path)
    row = df[df["session_id"] == "S-ed7d82-0000844#192"].iloc[0]
    session = {
        "session_id": row["session_id"], "source_ip": row["source_ip"],
        "protocol": row["protocol"],
        "destination_port": int(row["destination_port"]) if pd.notna(row["destination_port"]) else None,
        "events": json.loads(row["events"]),
    }
    facts, _, _ = extract_facts_from_session(session)

    try:
        explanation = generate_explanation(facts, alert_context="Suspected payload delivery via exposed SSH service")
        print("Generated explanation:\n")
        print(explanation)
    except ExplanationGeneratorError as e:
        print(f"ExplanationGeneratorError (expected without a real API key): {e}")
