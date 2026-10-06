"""
app.py

DEVL (Decision Evidence Validation Layer) -- Streamlit dashboard.

Real wiring to the tested pipeline: ingestion orchestrator -> enrichment
-> playbook engine. Every number and chart on this page is computed from
the actual data files in data/stage6_source/ and data/second_source/ --
nothing here is mocked or hardcoded for looks.

Run with: streamlit run ui/app.py
"""

import sys
from pathlib import Path
from collections import Counter

import streamlit as st
import plotly.graph_objects as go
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ingestion"))
sys.path.insert(0, str(ROOT / "enrichment"))
sys.path.insert(0, str(ROOT / "playbooks"))
sys.path.insert(0, str(ROOT / "devl"))

from orchestrator import run_all_adapters
from enrich import enrich_alert, enrich_mitre
from playbook_engine import run_playbook, PlaybookValidationError

PLAYBOOK_MAP = {
    "credential_stuffing_detected": str(ROOT / "playbooks" / "credential_stuffing_v1.yaml"),
    "payload_delivery_detected": str(ROOT / "playbooks" / "payload_delivery_v1.yaml"),
}

# ---- Palette: dark navy panels, blue + yellow brand (high contrast text) ----
BG = "#0D1421"
SIDEBAR_BG = "#0A101B"
PANEL = "#151E2E"
PANEL_2 = "#1B2740"
BORDER = "#2A3A52"
TEXT = "#EAF1FB"
MUTED = "#A9B8CF"
BLUE = "#4DB5FF"
BLUE_DARK = "#1F6FB5"
YELLOW = "#F5C518"
GREEN = "#5BD38A"
RED = "#FF7B72"
ORANGE = "#FFA657"
GREY = "#8B9BB4"

CHART_COLORWAY = [BLUE, YELLOW, "#7FD1AE", "#FF8A7A", "#B6A6FF", "#8BC3FF"]

APP_NAME = "DEVL"
APP_FULL_NAME = "Decision Evidence Validation Layer"

st.set_page_config(
    page_title=f"{APP_NAME} | {APP_FULL_NAME}",
    page_icon=":shield:",
    layout="wide",
)

st.markdown(
    f"""
    <style>
    [data-testid="stToolbar"] {{visibility: hidden;}}
    footer {{visibility: hidden;}}
    #MainMenu {{visibility: hidden;}}
    .stApp {{ background-color: {BG}; color: {TEXT}; }}
    .block-container {{ padding-top: 1.4rem; max-width: 1400px; }}
    h1, h2, h3, h4, label, p, li, span {{ color: {TEXT}; }}

    /* ---------- Left sidebar: dark navy, all text light and readable ---------- */
    [data-testid="stSidebar"] {{ background-color: {SIDEBAR_BG}; border-right: 1px solid {BORDER}; }}
    [data-testid="stSidebar"] * {{ color: {TEXT}; }}
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] * {{ color: {MUTED}; }}
    .brand-box {{ padding: 0.3rem 0 0.8rem 0; border-bottom: 1px solid {BORDER}; margin-bottom: 0.8rem; }}
    .brand-name {{ font-size: 1.7rem; font-weight: 800; letter-spacing: 0.06em; color: {YELLOW}; line-height: 1; }}
    .brand-sub {{ font-size: 0.78rem; color: {MUTED}; margin-top: 0.3rem; line-height: 1.3; }}
    .side-label {{ font-size: 0.72rem; font-weight: 700; color: {MUTED}; text-transform: uppercase; letter-spacing: 0.08em; margin: 1rem 0 0.3rem 0; }}

    /* radio group styled as a nav list */
    [data-testid="stSidebar"] [role="radiogroup"] {{ gap: 0.25rem; }}
    [data-testid="stSidebar"] [role="radiogroup"] > label {{
        background-color: transparent; border: 1px solid transparent; border-radius: 8px;
        padding: 0.5rem 0.7rem; width: 100%; cursor: pointer;
    }}
    [data-testid="stSidebar"] [role="radiogroup"] > label:hover {{ background-color: {PANEL}; }}
    [data-testid="stSidebar"] [role="radiogroup"] > label:has(input:checked) {{
        background-color: {PANEL_2}; border-color: {BLUE};
    }}
    [data-testid="stSidebar"] [role="radiogroup"] > label > div:first-child {{ display: none; }}
    [data-testid="stSidebar"] [role="radiogroup"] > label p {{ font-size: 0.97rem; font-weight: 600; color: {TEXT}; }}

    /* ---------- Top bar ---------- */
    .topbar {{
        background-color: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px;
        padding: 1rem 1.4rem; margin-bottom: 1.2rem; border-left: 5px solid {YELLOW};
    }}
    .topbar h1 {{ font-size: 1.6rem; margin: 0 0 0.25rem 0; color: {TEXT}; font-weight: 800; }}
    .topbar h1 .abbr {{ color: {YELLOW}; letter-spacing: 0.05em; }}
    .topbar p {{ color: {MUTED}; font-size: 0.95rem; margin: 0; max-width: 900px; line-height: 1.5; }}
    .pill {{
        display: inline-block; background-color: {PANEL_2}; color: {BLUE}; border: 1px solid {BORDER};
        padding: 3px 11px; border-radius: 20px; font-size: 0.78rem; margin: 0.7rem 8px 0 0;
    }}

    /* ---------- Panels / cards (same look as the reference screenshot) ---------- */
    .panel-title {{ font-size: 1.05rem; font-weight: 700; color: {TEXT}; margin: 1.4rem 0 0.5rem 0; }}
    .kpi-card {{
        background-color: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px; padding: 1rem 1.2rem;
        border-top: 3px solid {BLUE};
    }}
    .kpi-label {{ font-size: 0.78rem; color: {MUTED}; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }}
    .kpi-value {{ font-size: 2rem; font-weight: 800; color: {TEXT}; }}
    .section-label {{
        font-size: 0.85rem; font-weight: 700; color: {BLUE}; text-transform: uppercase;
        letter-spacing: 0.06em; margin-top: 1.6rem; margin-bottom: 0.4rem;
    }}
    .badge-safe {{
        background-color: {BLUE}; color: #04101F; padding: 2px 10px; border-radius: 4px;
        font-size: 0.75rem; font-weight: 700; letter-spacing: 0.03em;
    }}
    .badge-approval {{
        background-color: {YELLOW}; color: #1A1400; padding: 2px 10px; border-radius: 4px;
        font-size: 0.75rem; font-weight: 700; letter-spacing: 0.03em;
    }}
    .source-tag {{ font-size: 0.72rem; color: {BLUE}; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; }}
    .console-step {{
        background-color: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px; padding: 0.55rem 0.8rem;
        margin-bottom: 0.4rem; border-left: 3px solid {BLUE}; color: {TEXT};
    }}
    .console-step.gated {{ border-left: 3px solid {YELLOW}; background-color: {PANEL_2}; }}
    .console-step .detail {{ font-size: 0.85rem; color: {MUTED}; }}

    /* ---------- Streamlit widgets on dark background ---------- */
    .stButton > button, .stDownloadButton > button {{
        background-color: {PANEL_2}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 6px; font-weight: 600;
    }}
    .stButton > button:hover, .stDownloadButton > button:hover {{ border-color: {BLUE}; color: {BLUE}; }}
    .stButton > button[kind="primary"] {{ background-color: {BLUE}; color: #04101F; border: 1px solid {BLUE}; }}
    .stButton > button[kind="primary"]:hover {{ background-color: #7CCBFF; color: #04101F; }}
    .stButton > button[kind="primary"] p, .stButton > button[kind="primary"] span {{ color: #04101F; font-weight: 700; }}
    .stButton > button:disabled {{ opacity: 0.55; }}
    [data-testid="stExpander"] {{ background-color: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px; }}
    [data-testid="stExpander"] summary p {{ color: {TEXT}; font-weight: 600; }}
    [data-baseweb="tab-list"] {{ gap: 0.5rem; }}
    [data-baseweb="tab"] p {{ color: {MUTED}; font-weight: 600; }}
    [aria-selected="true"][data-baseweb="tab"] p {{ color: {BLUE}; }}
    [data-testid="stMetricValue"] {{ color: {TEXT}; }}
    [data-testid="stMetricLabel"] p {{ color: {MUTED}; }}

    /* ---------- DEVL verification cards ---------- */
    .incident-bar {{
        background-color: {PANEL}; border: 1px solid {BORDER}; border-left: 5px solid {BLUE};
        border-radius: 10px; padding: 1rem 1.4rem; margin-bottom: 1rem;
        display: flex; flex-wrap: wrap; gap: 1.8rem; align-items: baseline;
    }}
    .incident-bar .field-label {{ color: {MUTED}; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; display: block; }}
    .incident-bar .field-value {{ color: {TEXT}; font-size: 1.1rem; font-weight: 700; }}
    .decision-box {{
        background-color: {PANEL}; border: 1px solid {BLUE}; border-radius: 10px;
        padding: 1.1rem 1.4rem; margin-bottom: 1rem;
    }}
    .decision-box .decision-label {{ color: {BLUE}; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }}
    .decision-box .decision-value {{ color: {TEXT}; font-size: 1.3rem; font-weight: 800; margin: 0.15rem 0 0.6rem 0; }}
    .decision-box .decision-reasoning {{ color: {TEXT}; font-size: 0.95rem; font-style: italic; line-height: 1.5; }}
    .vcard {{ border-radius: 10px; padding: 0.9rem 1.1rem; margin-bottom: 0.7rem; background-color: {PANEL}; border: 1px solid {BORDER}; border-top: 3px solid {GREY}; }}
    .vcard .vcard-title {{ font-weight: 700; font-size: 0.9rem; margin-bottom: 0.3rem; color: {TEXT}; }}
    .vcard .vcard-count {{ font-size: 1.7rem; font-weight: 800; color: {TEXT}; }}
    .vcard-support {{ border-top-color: {GREEN}; }}
    .vcard-contra {{ border-top-color: {RED}; }}
    .vcard-related {{ border-top-color: {YELLOW}; }}
    .vcard-missing {{ border-top-color: {GREY}; }}
    .vcard-confidence {{ border-top-color: {BLUE}; }}
    .summary-sentence {{
        background-color: {PANEL}; border: 1px solid {BORDER}; border-left: 6px solid {YELLOW}; border-radius: 8px;
        padding: 1rem 1.3rem; color: {TEXT}; font-size: 1.02rem; line-height: 1.6; margin: 1rem 0;
    }}
    .evidence-row {{ border-radius: 8px; padding: 0.6rem 0.9rem; margin-bottom: 0.4rem; color: {TEXT}; background-color: {PANEL}; border: 1px solid {BORDER}; }}
    .evidence-row.verified {{ border-left: 4px solid {GREEN}; }}
    .evidence-row.contradicted {{ border-left: 4px solid {RED}; }}
    .evidence-row.unsupported {{ border-left: 4px solid {ORANGE}; }}
    .evidence-row.missing {{ border-left: 4px solid {GREY}; }}
    .evidence-row.unaccounted {{ border-left: 4px solid {YELLOW}; }}
    .evidence-row .sub {{ font-size: 0.82rem; color: {MUTED}; }}
    .section-title {{ color: {TEXT}; font-size: 1.1rem; font-weight: 800; margin: 1.5rem 0 0.5rem 0; border-bottom: 1px solid {BORDER}; padding-bottom: 0.3rem; }}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(ttl=120)
def load_alerts():
    return run_all_adapters()


@st.cache_data(ttl=120)
def load_alerts_with_mitre():
    """Bulk local MITRE enrichment (no network call) across every alert --
    verified at ~1.5s for 554 real alerts -- powers the tactic chart
    without needing any API key."""
    result = run_all_adapters()
    return [enrich_mitre(dict(a)) for a in result["alerts"]]


def severity_score(alert: dict) -> int:
    ev = alert.get("raw_evidence", {})
    if alert["alert_type"] == "credential_stuffing_detected":
        return ev.get("total_auth_fail") or ev.get("attempt_count") or 0
    if alert["alert_type"] == "payload_delivery_detected":
        base = 50
        if ev.get("known_infrastructure_match"):
            base += 50
        return base
    return 0


def render_hero():
    st.markdown(
        f"""
        <div class="topbar">
            <h1><span class="abbr">{APP_NAME}</span> &nbsp;|&nbsp; {APP_FULL_NAME}</h1>
            <p>
            DEVL checks every factual claim in an analyst's reasoning against the real telemetry
            and shows which claims are supported, contradicted, or cannot be checked. The check is
            plain deterministic code, so the same input always gives the same answer. The platform
            also ingests alerts, enriches them with MITRE ATT&amp;CK and threat intelligence, and runs
            human-gated response playbooks.
            </p>
            <span class="pill">Deterministic verification</span>
            <span class="pill">Evidence-backed decisions</span>
            <span class="pill">MITRE ATT&amp;CK-mapped</span>
            <span class="pill">Human-gated actions</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpis(alerts):
    cols = st.columns(4)
    values = [
        ("Total Alerts", len(alerts)),
        ("Credential Stuffing", sum(1 for a in alerts if a["alert_type"] == "credential_stuffing_detected")),
        ("Payload Delivery", sum(1 for a in alerts if a["alert_type"] == "payload_delivery_detected")),
        ("Independent Data Sources", len({a["source_dataset"] for a in alerts})),
    ]
    for col, (label, val) in zip(cols, values):
        col.markdown(
            f'<div class="kpi-card"><div class="kpi-label">{label}</div>'
            f'<div class="kpi-value">{val}</div></div>',
            unsafe_allow_html=True,
        )


def _plotly_layout(fig, title):
    fig.update_layout(
        title=dict(text=title, font=dict(color=TEXT, size=15)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT),
        colorway=CHART_COLORWAY,
        margin=dict(l=10, r=10, t=45, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=TEXT)),
        height=320,
    )
    fig.update_xaxes(gridcolor=BORDER, zerolinecolor=BORDER, color=TEXT)
    fig.update_yaxes(gridcolor=BORDER, zerolinecolor=BORDER, color=TEXT)
    return fig


def render_charts(alerts, mitre_alerts):
    st.markdown('<div class="section-label">Threat Landscape Overview</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    c3, c4 = st.columns(2)

    with c1:
        type_counts = Counter(a["alert_type"] for a in alerts)
        fig = go.Figure(data=[go.Pie(
            labels=list(type_counts.keys()), values=list(type_counts.values()),
            hole=0.55, marker=dict(colors=CHART_COLORWAY, line=dict(color=BG, width=2)), textfont=dict(color="#04101F"),
        )])
        st.plotly_chart(_plotly_layout(fig, "Alerts by Type"), width="stretch")

    with c2:
        ranked = sorted(alerts, key=severity_score, reverse=True)[:10]
        labels = [a["entity_id"] for a in ranked]
        scores = [severity_score(a) for a in ranked]
        fig = go.Figure(data=[go.Bar(
            x=scores, y=labels, orientation="h",
            marker=dict(color=scores, colorscale=[[0, BLUE_DARK], [1, YELLOW]]),
        )])
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(_plotly_layout(fig, "Top 10 Highest-Priority Entities"), width="stretch")

    with c3:
        tactic_counter = Counter()
        for a in mitre_alerts:
            mitre = a.get("mitre", {})
            if mitre.get("status") == "resolved":
                for t in mitre["techniques"]:
                    for tactic in t.get("tactics", []):
                        tactic_counter[tactic] += 1
        tactics_sorted = tactic_counter.most_common()
        fig = go.Figure(data=[go.Bar(
            x=[t[1] for t in tactics_sorted], y=[t[0] for t in tactics_sorted],
            orientation="h", marker=dict(color=YELLOW),
        )])
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(_plotly_layout(fig, "MITRE ATT&CK Tactic Coverage"), width="stretch")

    with c4:
        rows = []
        for a in alerts:
            ts = a.get("first_seen_utc")
            if not ts:
                continue
            try:
                day = pd.to_datetime(ts).date()
            except (ValueError, TypeError):
                continue
            rows.append({"day": day, "alert_type": a["alert_type"]})
        if rows:
            df = pd.DataFrame(rows)
            grouped = df.groupby(["day", "alert_type"]).size().reset_index(name="count")
            fig = go.Figure()
            for atype in grouped["alert_type"].unique():
                sub = grouped[grouped["alert_type"] == atype]
                fig.add_trace(go.Scatter(
                    x=sub["day"], y=sub["count"], mode="lines+markers",
                    name=atype, stackgroup="one",
                ))
            st.plotly_chart(_plotly_layout(fig, "Alert Volume Over Time"), width="stretch")
        else:
            st.caption("No timestamped alerts available to chart.")


NAV_ITEMS = ["Dashboard", "Alert Queue", "DEVL Verification", "Data Sources"]


def render_nav():
    st.sidebar.markdown(
        f'''<div class="brand-box"><div class="brand-name">{APP_NAME}</div>
        <div class="brand-sub">{APP_FULL_NAME}</div></div>''',
        unsafe_allow_html=True,
    )
    st.sidebar.markdown('<div class="side-label">Navigation</div>', unsafe_allow_html=True)
    return st.sidebar.radio("Navigation", NAV_ITEMS, label_visibility="collapsed")


def render_sidebar(all_alerts):
    sources = sorted({a["source_dataset"] for a in all_alerts})
    alert_types = sorted({a["alert_type"] for a in all_alerts})

    st.sidebar.markdown('<div class="side-label">Filters</div>', unsafe_allow_html=True)
    selected_sources = st.sidebar.multiselect("Data source", sources, default=sources)
    selected_types = st.sidebar.multiselect("Alert type", alert_types, default=alert_types)
    demo_only = st.sidebar.checkbox("Show demo anchors only", value=False)
    return selected_sources, selected_types, demo_only


def render_sidebar_footer():
    st.sidebar.divider()
    st.sidebar.caption(
        "Destructive response actions in this prototype are SIMULATED "
        "(no real IAM or firewall connected)."
    )


def render_alert_table(alerts):
    st.markdown('<div class="section-label">Prioritized Alert Queue</div>', unsafe_allow_html=True)
    ranked = sorted(alerts, key=severity_score, reverse=True)

    for i, alert in enumerate(ranked[:50]):
        score = severity_score(alert)
        anchor_tag = " ⭐ DEMO ANCHOR" if alert.get("is_demo_anchor") else ""
        with st.expander(f"[{score}] {alert['alert_type']} — {alert['entity_id']}{anchor_tag}"):
            render_alert_detail(alert, key_prefix=f"alert_{i}")


def render_alert_detail(alert: dict, key_prefix: str):
    col_a, col_b = st.columns([2, 1])
    with col_a:
        st.markdown(f'<span class="source-tag">Source: {alert["source_dataset"]}</span>', unsafe_allow_html=True)
        st.write(f"**Entity:** `{alert['entity_id']}`  |  **Type:** {alert['entity_type']}")
        st.write(f"**Source IP:** `{alert.get('source_ip')}`")
        st.write(f"**First seen:** {alert.get('first_seen_utc')}  |  **Last seen:** {alert.get('last_seen_utc')}")
        with st.popover("Raw evidence"):
            st.json(alert.get("raw_evidence", {}))
    with col_b:
        st.metric("Priority score", severity_score(alert))

    st.divider()

    enrich_key = f"{key_prefix}_enriched"
    if st.button("Run enrichment (MITRE + CTI + hash reputation)", key=f"{key_prefix}_enrich_btn"):
        with st.spinner("Enriching..."):
            st.session_state[enrich_key] = enrich_alert(dict(alert))

    enriched = st.session_state.get(enrich_key)
    if enriched:
        col_m, col_c, col_h = st.columns(3)
        with col_m:
            st.markdown("**MITRE ATT&CK**")
            mitre = enriched.get("mitre", {})
            if mitre.get("status") == "resolved":
                for t in mitre["techniques"]:
                    st.write(f"- `{t['technique_id']}` — {t['name']} ({', '.join(t['tactics'])})")
            else:
                st.warning(f"{mitre.get('status')} — {mitre.get('note', '')}")
        with col_c:
            st.markdown("**CTI Reputation**")
            cti = enriched.get("cti", {})
            if cti.get("status") == "resolved":
                st.write(f"Abuse confidence: {cti.get('abuse_confidence_score')}")
                st.write(f"Reports: {cti.get('total_reports')} | Country: {cti.get('country_code')}")
            else:
                st.info(f"{cti.get('status')} — {cti.get('note', '')}")
        with col_h:
            st.markdown("**Hash Reputation**")
            hr = enriched.get("hash_reputation", {})
            if hr.get("status") == "checked":
                for h, r in hr["results"].items():
                    st.write(f"`{h[:12]}...`: **{r.get('status')}**")
                    if r.get("status") == "known_malicious":
                        st.caption(f"Signature: {r.get('signature')} | Tags: {', '.join(r.get('tags', []))}")
            else:
                st.caption(hr.get("status", "n/a"))

        st.divider()
        render_playbook_section(enriched, key_prefix)
    else:
        st.caption("Run enrichment to unlock playbook execution.")


def render_playbook_section(enriched_alert: dict, key_prefix: str):
    alert_type = enriched_alert["alert_type"]
    playbook_path = PLAYBOOK_MAP.get(alert_type)
    if not playbook_path:
        st.caption(f"No playbook mapped for alert_type '{alert_type}' yet (architecturally designed, not live).")
        return

    st.markdown("**Response Console**")
    run_key = f"{key_prefix}_run"

    if run_key not in st.session_state:
        if st.button("Execute playbook", key=f"{key_prefix}_exec_btn"):
            try:
                run = run_playbook(playbook_path, enriched_alert)
                st.session_state[run_key] = run
                st.rerun()
            except PlaybookValidationError as e:
                st.error(f"Playbook validation failed: {e}")
        return

    run = st.session_state[run_key]

    for step in run.completed_steps:
        gated = step["tag"] == "requires_approval"
        badge_class = "badge-approval" if gated else "badge-safe"
        css_class = "console-step gated" if gated else "console-step"
        decision = step.get("decision")
        status_note = f" ({decision})" if decision and decision != "pending" else ""
        st.markdown(
            f'<div class="{css_class}"><span class="{badge_class}">{step["tag"]}</span> '
            f'&nbsp; <b>{step["step_title"]}</b>{status_note}<br>'
            f'<span class="detail">{step["outcome"].get("detail","")}</span></div>',
            unsafe_allow_html=True,
        )

    if run.status == "awaiting_approval":
        st.warning(f"⚠️ **Approval required:** {run.pending_step['title']}")
        st.caption(run.pending_step["description"])
        col_ap, col_rj = st.columns(2)
        with col_ap:
            if st.button("Approve", key=f"{key_prefix}_approve_btn", type="primary"):
                run.approve_pending()
                st.rerun()
        with col_rj:
            if st.button("Reject", key=f"{key_prefix}_reject_btn"):
                run.reject_pending(reason="Rejected via UI")
                st.rerun()
    elif run.status == "completed":
        st.success("Playbook completed.")
    elif run.status == "completed_with_rejection":
        st.info("Playbook completed — destructive step was rejected by analyst.")


def _list_devl_sessions() -> dict:
    """Real session files from devl/samples/ -- only files that actually
    have the session shape (session_id + events), so manifests and
    generated reason-slate/batch-report JSONs are never offered as
    selectable sessions."""
    import json as _json
    sessions = {}
    samples_dir = ROOT / "devl" / "samples"
    for path in sorted(samples_dir.glob("*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = _json.load(f)
        except (ValueError, OSError):
            continue
        if isinstance(data, dict) and "session_id" in data and "events" in data:
            sessions[f"{data['session_id']}  ({data.get('source_ip')}, {data.get('protocol')})"] = data
    return sessions


def _run_devl_pipeline(session: dict, explanation: str, decision, sysmon_path=None, scope=None):
    """Runs the REAL DEVL pipeline -- same modules and same order as the
    CLI's `verify` command (including optional Sysmon process-lineage
    evidence and investigation scope, so the GUI has full parity with
    the CLI, not a reduced subset of it) -- and returns (slate, facts)."""
    from fact_extractor import extract_facts_from_session
    from graph_builder import build_graph
    from claim_parser import parse_explanation
    from evidence_matcher import verify_claims
    from mismatch_engine import compute_integrity
    from coverage_checker import find_unaccounted_evidence, detect_timestamp_gaps
    from reason_slate import generate_reason_slate

    facts, _, incomplete = extract_facts_from_session(session)

    if sysmon_path:
        from sysmon_fact_extractor import extract_facts_from_sysmon_xml
        sysmon_facts, _, sysmon_incomplete = extract_facts_from_sysmon_xml(sysmon_path)
        facts = facts + sysmon_facts
        incomplete = incomplete + sysmon_incomplete

    graph = build_graph(facts)
    parsed = parse_explanation(explanation)
    verdicts = verify_claims(parsed.claims, graph)
    report = compute_integrity(verdicts)
    unaccounted = find_unaccounted_evidence(graph, parsed.claims, scope=scope)
    gaps = detect_timestamp_gaps(facts, scope=scope)
    slate = generate_reason_slate(
        alert_id=(scope.incident_id if scope else f"ALT-{session.get('session_id', 'unknown')}"),
        explanation_text=explanation,
        graph=graph, report=report,
        analyst_decision=decision,
        unaccounted_evidence=unaccounted,
        timestamp_gaps=gaps,
        unparsed_fragments=parsed.unparsed_fragments,
        investigation_scope=scope,
    )
    slate["_incomplete_events"] = incomplete
    return slate, facts


def _event_summary(subject: str, relation: str, obj: str) -> str:
    label = relation.replace("_", " ").title()
    return f"{subject} → {label} → {obj}"


def render_devl_tab():
    import json as _json
    from reason_slate import DECISION_CHOICES
    from relevance_engine import InvestigationScope

    st.markdown('<div class="section-title">🛡️ Decision Evidence Validation Layer</div>', unsafe_allow_html=True)
    st.write(
        "The analyst stays the decision-maker. DEVL checks whether the stated **reasoning** behind a "
        "decision is supported by real telemetry, what it contradicts or never mentions, and whether "
        "the evidence used is actually relevant to this investigation."
    )

    sessions = _list_devl_sessions()
    if not sessions:
        st.error("No session files found in devl/samples/. Cannot run verification without real telemetry.")
        return

    # ---- Input controls ----
    col_sess, col_sysmon = st.columns([2, 1])
    with col_sess:
        choice = st.selectbox("Incident session (real telemetry)", list(sessions.keys()))
    session = sessions[choice]

    sysmon_sample = ROOT / "data" / "sysmon_source" / "sample_process_lineage.xml"
    with col_sysmon:
        include_sysmon = st.checkbox(
            "Include real Sysmon process-lineage evidence", value=False,
            disabled=not sysmon_sample.exists(),
            help="Merges real Windows process creation/access/file-creation facts into the evidence graph.",
        )
    sysmon_path = str(sysmon_sample) if (include_sysmon and sysmon_sample.exists()) else None

    with st.expander("Investigation scope (optional) — limits findings to evidence relevant to THIS investigation"):
        sc1, sc2 = st.columns(2)
        incident_id = sc1.text_input("Incident ID", value="INC-2026-014")
        entities_raw = sc2.text_input(
            "Affected entities (comma-separated: IPs, users, process paths)",
            value=session.get("source_ip", ""),
        )
        sc3, sc4 = st.columns(2)
        window_start = sc3.text_input("Window start (ISO8601, optional)", value="")
        window_end = sc4.text_input("Window end (ISO8601, optional)", value="")
        use_scope = st.checkbox("Apply this scope to the verification", value=False)

    scope = None
    if use_scope:
        entities = {e.strip() for e in entities_raw.split(",") if e.strip()}
        scope = InvestigationScope(
            incident_id=incident_id or "INC-UNSPECIFIED",
            affected_entities=entities,
            window_start=window_start or None,
            window_end=window_end or None,
        )

    with st.expander("View raw telemetry events for this session"):
        st.json(session.get("events", []))

    st.markdown('<div class="section-title">📝 Analyst Decision & Reasoning</div>', unsafe_allow_html=True)
    decision_label = st.selectbox("Decision", ["— not stated —"] + sorted(DECISION_CHOICES))
    decision = None if decision_label.startswith("—") else decision_label

    explanation = st.text_area(
        "Analyst reasoning",
        height=120,
        placeholder="e.g. 198.51.100.155 connected to ssh:22. 198.51.100.155 authenticated as svc23.",
        help="One factual statement per sentence, naming the IP/process explicitly, for the deterministic parser to decompose.",
    )

    if st.button("Verify Decision Reasoning", type="primary", disabled=not explanation.strip()):
        with st.spinner("Running DEVL verification against real telemetry..."):
            slate, facts = _run_devl_pipeline(session, explanation, decision, sysmon_path=sysmon_path, scope=scope)
            st.session_state["devl_slate"] = slate
            st.session_state["devl_facts"] = facts

    slate = st.session_state.get("devl_slate")
    facts = st.session_state.get("devl_facts")
    if not slate:
        st.info("Enter reasoning above and click **Verify Decision Reasoning** to run the check against real telemetry.")
        return

    outcome = slate["verification_outcome"]
    review = slate["decision_support"]["human_review_required"]
    integ = slate["explanation_integrity"]
    size = integ["sample_size"]
    eb = slate["evidence_breakdown"]
    cov = slate["evidence_coverage"]
    pc = slate["parsing_coverage"]
    completeness = slate["evidence_completeness"]
    d = slate.get("analyst_decision")

    # ======================= INCIDENT OVERVIEW =======================
    status_label = {"FULLY_SUPPORTED": "Reasoning Supported", "MISMATCH_DETECTED": "Mismatch Detected",
                    "PARTIAL_VERIFICATION_ONLY": "Partial Verification"}.get(outcome, outcome)
    priority = "HIGH" if (size["contradicted"] > 0 or cov["unaccounted_count"] > 2) else ("MEDIUM" if review else "LOW")
    st.markdown(
        f'''<div class="incident-bar">
            <div><span class="field-label">Incident ID</span><span class="field-value">{slate["alert_id"]}</span></div>
            <div><span class="field-label">Status</span><span class="field-value">{status_label}</span></div>
            <div><span class="field-label">Priority (heuristic)</span><span class="field-value">{priority}</span></div>
            <div><span class="field-label">Confidence (integrity score)</span><span class="field-value">{integ["score"]}</span></div>
            <div><span class="field-label">Affected entity</span><span class="field-value">{session.get("source_ip","—")}</span></div>
            <div><span class="field-label">Human review required</span><span class="field-value">{"YES" if review else "NO"}</span></div>
        </div>''',
        unsafe_allow_html=True,
    )

    # ======================= ANALYST DECISION =======================
    if d:
        st.markdown(
            f'''<div class="decision-box">
                <span class="decision-label">Analyst Decision</span>
                <div class="decision-value">{d["stated_decision"]}</div>
                <span class="decision-label">Reasoning</span>
                <div class="decision-reasoning">"{slate["explanation_text"]}"</div>
            </div>''',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'''<div class="decision-box">
                <span class="decision-label">Reasoning (no decision stated)</span>
                <div class="decision-reasoning">"{slate["explanation_text"]}"</div>
            </div>''',
            unsafe_allow_html=True,
        )

    # ======================= VERIFICATION SUMMARY SENTENCE =======================
    summary = (
        f'The analyst\'s reasoning is <b>supported</b> by {size["verified"]} piece(s) of real evidence, '
        f'<b>contradicted</b> by {size["contradicted"]}, with <b>{cov["unaccounted_count"]}</b> piece(s) of '
        f'relevant evidence not accounted for and <b>{size["missing_telemetry"]}</b> item(s) of missing telemetry.'
    )
    if pc["unparsed_count"]:
        summary += f' {pc["unparsed_count"]} statement(s) in the reasoning could not be parsed and were not verified either way.'
    st.markdown(f'<div class="summary-sentence">📊 <b>Verification Summary:</b> {summary}</div>', unsafe_allow_html=True)
    st.caption(slate["decision_support"]["note"])

    # ======================= DEVL VERIFICATION CARDS =======================
    st.markdown('<div class="section-title">🔍 DEVL Verification</div>', unsafe_allow_html=True)
    vc1, vc2, vc3, vc4, vc5 = st.columns(5)
    vc1.markdown(f'<div class="vcard vcard-support"><div class="vcard-title">✅ Supporting</div><div class="vcard-count">{size["verified"]}</div></div>', unsafe_allow_html=True)
    vc2.markdown(f'<div class="vcard vcard-contra"><div class="vcard-title">⚠️ Contradicting</div><div class="vcard-count">{size["contradicted"]}</div></div>', unsafe_allow_html=True)
    vc3.markdown(f'<div class="vcard vcard-related"><div class="vcard-title">🔎 Related, unaccounted</div><div class="vcard-count">{cov["unaccounted_count"]}</div></div>', unsafe_allow_html=True)
    vc4.markdown(f'<div class="vcard vcard-missing"><div class="vcard-title">❓ Missing telemetry</div><div class="vcard-count">{size["missing_telemetry"]}</div></div>', unsafe_allow_html=True)
    vc5.markdown(f'<div class="vcard vcard-confidence"><div class="vcard-title">📊 Confidence</div><div class="vcard-count">{integ["score"]}</div></div>', unsafe_allow_html=True)
    st.caption(
        "Confidence is a deterministic heuristic over claims that could be parsed — not a probability "
        "that the incident is real. Evidence integrity: " + slate["evidence_integrity_assessment"]["completeness_status"]
    )

    def _claim_row(i: dict, css_class: str):
        c = i["claim"]
        ev = (i.get("matched_evidence") or [{}])[0]
        ts = f' · {ev.get("timestamp")}' if ev.get("timestamp") else ""
        src = f' · {ev.get("log_source")}' if ev.get("log_source") else ""
        st.markdown(
            f'<div class="evidence-row {css_class}">{_event_summary(c["subject"], c["relation"], c["object"])}'
            f'<br><span class="sub">{i["note"]}{ts}{src}</span></div>',
            unsafe_allow_html=True,
        )

    cols = st.columns(2)
    with cols[0]:
        st.markdown("**✅ Supporting evidence**")
        for i in eb["supporting"]:
            _claim_row(i, "verified")
        if not eb["supporting"]:
            st.caption("None.")
        st.markdown("**⚠️ Contradicting evidence**")
        for i in eb["contradictory"]:
            _claim_row(i, "contradicted")
        if not eb["contradictory"]:
            st.caption("None.")
    with cols[1]:
        st.markdown("**❌ Unsupported / fabricated claims**")
        for i in eb["unsupported_claims"]:
            _claim_row(i, "unsupported")
        if not eb["unsupported_claims"]:
            st.caption("None.")
        st.markdown("**❓ Missing telemetry**")
        for i in eb["telemetry_gaps"]:
            _claim_row(i, "missing")
        if not eb["telemetry_gaps"]:
            st.caption("None.")

    st.markdown("**🔎 Related evidence the analyst may have missed**")
    if cov["unaccounted_evidence"]:
        for u in cov["unaccounted_evidence"]:
            rel = u.get("relevance", {})
            tier_note = f' · relevance: {rel["relevance_tier"]}' if rel else ""
            st.markdown(
                f'<div class="evidence-row unaccounted">{_event_summary(u["subject"], u["relation"], u["object"])}'
                f'<br><span class="sub">{u.get("timestamp","")}{tier_note}</span></div>',
                unsafe_allow_html=True,
            )
    else:
        st.caption("Every relevant real telemetry event was referenced by the reasoning.")

    if pc["unparsed_fragments"]:
        st.markdown("**✂️ Reasoning text that could not be parsed (not verified true or false)**")
        for frag in pc["unparsed_fragments"]:
            st.code(frag, language=None)

    if completeness["timestamp_gaps"]:
        st.markdown("**⏱️ Unusual timing gaps (prompt for review, not a tampering claim)**")
        for g in completeness["timestamp_gaps"]:
            st.markdown(
                f'<div class="evidence-row missing">{g["gap_seconds"]:.1f}s between "{g["after_event"]}" and "{g["before_event"]}"</div>',
                unsafe_allow_html=True,
            )

    if slate.get("_incomplete_events"):
        st.caption(f"⚠️ {len(slate['_incomplete_events'])} recorded event(s) were excluded because a required "
                   f"field was missing (never filled with a placeholder value).")

    # ======================= EVIDENCE TIMELINE =======================
    st.markdown('<div class="section-title">⏳ Evidence Timeline</div>', unsafe_allow_html=True)
    if facts:
        from relevance_engine import _parse_ts
        timeline_rows = []
        for f in facts:
            ts = _parse_ts(f.timestamp)
            if ts is not None:
                timeline_rows.append({"ts": ts, "label": _event_summary(f.subject, f.relation, f.obj), "log_source": f.log_source})
        timeline_rows.sort(key=lambda r: r["ts"])
        if timeline_rows:
            fig = go.Figure(data=[go.Scatter(
                x=[r["ts"] for r in timeline_rows], y=[0] * len(timeline_rows),
                mode="markers+text", text=[r["log_source"] for r in timeline_rows],
                textposition="top center", marker=dict(size=14, color=BLUE, line=dict(width=2, color=YELLOW)),
                hovertext=[r["label"] for r in timeline_rows], hoverinfo="text+x",
            )])
            fig.update_yaxes(visible=False, range=[-1, 1])
            fig = _plotly_layout(fig, "Chronological real event sequence")
            fig.update_layout(height=220)
            st.plotly_chart(fig, width="stretch")
        else:
            st.caption("No timestamped facts available to chart.")
    else:
        st.caption("No facts available to chart.")

    # ======================= EVIDENCE EXPLORER =======================
    st.markdown('<div class="section-title">🧾 Evidence Explorer</div>', unsafe_allow_html=True)
    if facts:
        explorer_rows = [{
            "timestamp": f.timestamp, "subject": f.subject, "relation": f.relation,
            "object": f.obj, "log_source": f.log_source,
        } for f in facts]
        st.dataframe(explorer_rows, width="stretch")
    else:
        st.caption("No facts extracted for this session.")

    with st.expander("Digests & full Reason Slate (tamper-evidence detail)"):
        st.write("`evidence_digest` — reproducible for the same telemetry + reasoning + decision:")
        st.code(slate["evidence_digest"], language=None)
        st.write("`audit_digest` — identifies this specific generated record (includes timestamp):")
        st.code(slate["audit_digest"], language=None)
        export = {k: v for k, v in slate.items() if not k.startswith("_")}
        st.download_button("Download Reason Slate (JSON)", _json.dumps(export, indent=2, default=str),
                            file_name="reason_slate.json", mime="application/json")


def main():
    render_hero()
    page = render_nav()

    if page == "DEVL Verification":
        render_devl_tab()
        render_sidebar_footer()
        return

    with st.spinner("Loading alerts from all registered adapters..."):
        result = load_alerts()
        mitre_alerts = load_alerts_with_mitre()
    all_alerts = result["alerts"]

    if page == "Data Sources":
        st.markdown('<div class="section-title">Per-source reconciliation (data provenance)</div>', unsafe_allow_html=True)
        st.json(result["per_adapter_reconciliation"])
        render_sidebar_footer()
        return

    selected_sources, selected_types, demo_only = render_sidebar(all_alerts)
    render_sidebar_footer()

    def _keep(a):
        return (a["source_dataset"] in selected_sources
                and a["alert_type"] in selected_types
                and (not demo_only or a.get("is_demo_anchor")))

    filtered = [a for a in all_alerts if _keep(a)]
    filtered_mitre = [a for a in mitre_alerts if _keep(a)]

    if page == "Dashboard":
        render_kpis(filtered)
        render_charts(filtered, filtered_mitre)
    else:
        render_alert_table(filtered)


if __name__ == "__main__":
    main()
