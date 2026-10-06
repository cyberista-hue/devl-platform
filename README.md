# DEVL: Decision Evidence Validation Layer

DEVL checks every factual claim in an analyst's reasoning against real telemetry and reports which claims are supported, contradicted, or cannot be verified. The check is deterministic code with no AI in the verification step, so the same input always gives the same result.

The platform also ingests alerts from several sources, enriches them with MITRE ATT&CK and threat intelligence, and runs human-gated response playbooks.

## Run the dashboard

```
pip install -r requirements.txt
streamlit run ui/app.py
```

## Run the tests

```
pytest tests
```

## Optional API keys

Set these environment variables for live threat intelligence. Without them the app reports the lookup as unavailable and carries on.

```
ABUSEIPDB_API_KEY
MALWAREBAZAAR_API_KEY
```

## More detail

See `docs/devl-project-overview.md` and `devl/README.md`.
