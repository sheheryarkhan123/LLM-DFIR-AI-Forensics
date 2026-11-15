"""LLM-DFIR | Modern, local-first forensic triage dashboard."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from app.core import MAX_UPLOAD_BYTES, analyze, report_markdown
from app.llm import explain

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "synthetic_wazuh_alerts.json"
CASE_FILES = {
    "Case 001 · Account & group change": ROOT / "samples" / "case_001_account_group_change.json",
    "Case 002 · Authentication review": ROOT / "samples" / "case_002_authentication_review.json",
}
CASE_DOCS = {
    "Case 001 · Account & group change": ROOT / "cases" / "CASE-001-account-group-change.md",
    "Case 002 · Authentication review": ROOT / "cases" / "CASE-002-authentication-review.md",
}

st.set_page_config(
    page_title="LLM-DFIR | Investigation Workspace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
/* Identity: Graphite / Electric Indigo / Signal Cyan */
[data-testid="stAppViewContainer"] {
  background: radial-gradient(ellipse 950px 480px at 80% 0%, #17234c 0%, transparent 75%),
              linear-gradient(160deg, #080d1b 0%, #0c1324 58%, #080e19 100%);
  color: #e7edf9;
}
[data-testid="stSidebar"] {background: #0b1325; border-right: 1px solid #24314a;}
[data-testid="stHeader"] {background: transparent;}
.block-container {max-width: 1420px; padding-top: 1.45rem; padding-bottom: 2.2rem;}
h1,h2,h3,h4 {letter-spacing: -0.035em; color:#f0f5ff !important;}
[data-testid="stCaptionContainer"] {color: #8fa2c1 !important;}
[data-testid="stMetric"] {
  background: linear-gradient(142deg, rgba(28,40,70,.88), rgba(14,22,40,.94));
  border: 1px solid #2b3b59; border-radius: 17px; padding: 1.25rem 1.35rem;
}
[data-testid="stMetricLabel"] {color: #aab9d5 !important;}
[data-testid="stMetricValue"] {color: #f4f8ff !important;}
[data-testid="stFileUploader"] {border-radius: 16px;}
[data-testid="stDataFrame"] {border: 1px solid #2b3b59; border-radius: 12px; overflow:hidden;}
div.stButton > button[kind="primary"] {background: linear-gradient(90deg, #5e73ff, #6774f5); color:white; border:none; border-radius: 11px; font-weight: 700;}
div.stDownloadButton > button {border: 1px solid #5265a3; border-radius: 11px;}
section[data-testid="stSidebar"] .block-container {padding-top: 2rem;}
.hero-card {
 background: linear-gradient(112deg,rgba(47,61,107,.92),rgba(21,31,54,.96) 65%, rgba(13,29,48,.97));
 border: 1px solid #354b7b; border-radius: 22px; padding: 28px 30px 26px;
 box-shadow: 0 18px 60px #05091244; margin-bottom: 26px;
}
.hero-card h1 {margin: 12px 0 7px; font-size: clamp(1.9rem, 3.3vw, 3rem); font-weight: 760; line-height: 1.15;}
.hero-card p {color:#b6c6e0; margin: 0; font-size: 1.02rem; max-width: 780px;}
.pill {display:inline-block; border-radius: 999px; color: #a5f5e8; background: #063b3d88;
 border:1px solid #216c75; padding:6px 11px; font-size:.73rem; font-weight:750; letter-spacing:.12em;}
.pill-secondary {color:#c1c9ff; background:#343d7880; border-color:#6066ba; margin-left:7px;}
.section-head {margin: 6px 0 12px; color:#b8c7e1; letter-spacing:.08em; font-size:.76rem; font-weight:800; text-transform: uppercase;}
.status-line {color:#aec0db; font-size:.9rem; margin-bottom:8px;}
.fineprint {border-top:1px solid #273650; padding-top:1.2rem; margin-top:2rem; color:#8295b3; font-size:.8rem;}
[data-testid="stTabs"] [data-baseweb="tab"] {font-weight: 650;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero-card">
  <span class="pill">● LOCAL-FIRST DFIR</span><span class="pill pill-secondary">RESEARCH PROTOTYPE / V1.2</span>
  <h1>LLM-DFIR <span style="color:#88caff">/</span> Investigation Workspace</h1>
  <p>From raw security telemetry to defensible investigation leads.
  Deterministic evidence analysis with an optional, human-reviewed AI copilot.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## ⬡ LLM-DFIR")
    st.caption("Evidence-aware investigation console")
    st.divider()
    st.markdown('<div class="section-head">Evidence intake</div>', unsafe_allow_html=True)
    source = st.radio("Source", ["Synthetic demo", *CASE_FILES.keys(), "Upload evidence"], label_visibility="collapsed")
    if source == "Synthetic demo":
        filename = SAMPLE.name
        data = SAMPLE.read_bytes()
        st.info("**DEMO MODE** · Synthetic, fictional events. Not real case evidence.")
    elif source in CASE_FILES:
        sample_path = CASE_FILES[source]
        filename = sample_path.name
        data = sample_path.read_bytes()
        st.info("**SYNTHETIC CASEBOOK** · Fictional Windows 11/Wazuh events, NOT real evidence.")
    else:
        uploaded = st.file_uploader(
            "JSON / JSONL / NDJSON / CSV", type=["json", "jsonl", "ndjson", "csv"],
            help="Use exported, authorized working copies only. Max 15 MB."
        )
        filename = uploaded.name if uploaded else None
        data = uploaded.getvalue() if uploaded else None
    st.markdown('<div class="section-head">Workspace safeguards</div>', unsafe_allow_html=True)
    st.caption("🔐 Hash original file bytes")
    st.caption("🧩 Detection logic runs offline")
    st.caption("🌐 External AI only on explicit request")
    st.caption("🧑‍⚖️ Analyst verification required")
    st.divider()
    st.caption("LLM-DFIR is an educational triage aid, not a courtroom-validated forensic platform.")

if data is None:
    st.markdown("### Import a working copy to begin")
    st.info("Upload a JSON/JSONL/CSV file containing Windows or Wazuh events. Or choose **Synthetic demo** in the sidebar.")
    st.stop()

try:
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload limit: 15 MB")
    result = analyze(data, filename)
except (ValueError, UnicodeError, json.JSONDecodeError, KeyError) as exc:
    st.error(f"Unable to interpret uploaded file: {exc}")
    st.stop()

records = result["events"]
df = pd.DataFrame(records)
flagged = sum(record["severity"] in ("medium", "high") for record in records)
hosts = len({record["host"] for record in records if record["host"]})

st.markdown(
    f'<div class="status-line">🟢 Parsed working copy &nbsp; • &nbsp; '
    f'{"Synthetic sample" if source != "Upload evidence" else "Uploaded evidence"} &nbsp; • &nbsp; '
    f'{len(data):,} bytes &nbsp; • &nbsp; SHA-256 computed locally</div>',
    unsafe_allow_html=True,
)

m1, m2, m3, m4 = st.columns(4)
m1.metric("EVENTS PARSED", f"{result['count']:,}")
m2.metric("REVIEW CANDIDATES", f"{flagged:,}")
m3.metric("HOSTS OBSERVED", f"{hosts:,}")
m4.metric("SEQUENCE LEADS", f"{len(result['sequences']):,}")

st.markdown("")
overview, explorer, casebook, copilot, exports = st.tabs([
    "◉  Overview", "▤  Evidence explorer", "◫  Casebook", "✦  AI copilot", "⇩  Reports & export"
])

with overview:
    left, right = st.columns([1.12, 0.88], gap="large")
    with left:
        st.subheader("Event distribution")
        if not df.empty:
            counts = df["finding"].value_counts().rename_axis("Observation").to_frame("Events")
            st.bar_chart(counts, horizontal=True, use_container_width=True)
        else:
            st.info("No event records.")
    with right:
        st.subheader("Severity for analyst review")
        if not df.empty:
            severity_counts = df["severity"].value_counts().reindex(["high", "medium", "info"], fill_value=0)
            st.bar_chart(severity_counts, use_container_width=True)
        else:
            st.info("No event records.")
    st.subheader("Event sequence leads")
    st.caption("Pairs share host and user and occur within 30 minutes. These are **not confirmed attacks**.")
    if result["sequences"]:
        st.dataframe(pd.DataFrame(result["sequences"]), hide_index=True, use_container_width=True)
    else:
        st.info("No predefined event sequence candidates found.")
    if result["unverified_timestamps"]:
        st.warning(f"{result['unverified_timestamps']} record(s) have timestamps without verified UTC offsets. Review timeline order manually.")

with explorer:
    st.subheader("Searchable event timeline")
    if df.empty:
        st.info("No records found.")
    else:
        f1, f2, f3 = st.columns([1, 1, 1.4])
        sev = f1.multiselect("Severity", ["high", "medium", "info"], default=["high", "medium", "info"])
        event_ids = sorted(df["event_id"].unique())
        ids = f2.multiselect("Event IDs", event_ids, default=event_ids)
        term = f3.text_input("Host, user, description, evidence ID", placeholder="Search events…")
        view = df[df["severity"].isin(sev) & df["event_id"].isin(ids)].copy()
        if term:
            cols = ["host", "user", "description", "evidence_id", "event_id"]
            view = view[view[cols].astype(str).agg(" ".join, axis=1).str.contains(term, case=False, regex=False)]
        st.caption(f"Showing {len(view):,} of {len(df):,} records · timestamps normalized to UTC only when source includes timezone")
        visible_cols = ["evidence_id", "timestamp", "host", "user", "event_id", "finding", "severity", "mitre_candidate"]
        st.dataframe(view[visible_cols], use_container_width=True, hide_index=True, height=350)
        if len(view):
            chosen = st.selectbox("Inspect original normalized event", view["evidence_id"].tolist())
            st.json(view.loc[view["evidence_id"] == chosen].iloc[0].to_dict(), expanded=False)

with casebook:
    st.subheader("Evidence-driven investigation casebook")
    st.caption("These cases are synthetic exercises. Choose a case in the sidebar to compare its documented lead to the event explorer.")
    if source in CASE_DOCS:
        st.markdown(CASE_DOCS[source].read_text(encoding="utf-8"))
    else:
        st.info("Select 'Case 001' or 'Case 002' in the sidebar. For real lab data, use Upload evidence and follow docs/real-wazuh-workflow.md.")
    st.markdown("**Next action:** corroborate every candidate against authorized source logs, user/change records, and Windows event field semantics.")

with copilot:
    st.subheader("AI investigation copilot")
    st.caption("LLM output is a hypothesis, not validated forensic evidence. Every factual claim must be checked against event IDs.")
    mode = st.radio("Processing mode", ["Offline", "Ollama (local)", "OpenAI API (cloud)"], horizontal=True)
    if mode == "Offline":
        st.success("**Offline selected.** Analysis and reports remain available without an LLM or internet connection.")
        st.markdown("**How to interpret this dataset**")
        st.write("Review high/medium events, inspect source evidence IDs, and correlate with authentication, process, and change-management records.")
    else:
        if mode == "Ollama (local)":
            model = st.text_input("Local model", value="llama3.2")
            api_key = ""
            st.info("Requests go only to `http://127.0.0.1:11434`. Ensure your Ollama service and model are ready.")
            permission = True
        else:
            model = st.text_input("Cloud model", value="gpt-4o-mini")
            api_key = st.text_input("API key (not saved)", type="password")
            st.warning("Cloud mode sends up to 40 selected event summaries to an external service. Hostnames, timestamps, and evidence IDs may be sensitive. Never send private case evidence without authorization.")
            permission = st.checkbox("I am authorized to transmit these event summaries to this external AI provider.")
        if st.button("Generate investigation hypotheses", type="primary", disabled=not permission):
            try:
                with st.spinner("Analyzing bounded event summaries…"):
                    generated = explain(records, mode, model.strip(), api_key.strip())
                st.session_state["llm_notes"] = {"digest": result["sha256"], "text": generated}
            except Exception as exc:
                st.error(f"AI request failed ({type(exc).__name__}). Check the model, endpoint, and network settings.")
        previous = st.session_state.get("llm_notes")
        if previous and previous.get("digest") == result["sha256"]:
            st.divider()
            st.markdown("#### AI hypotheses — analyst review required")
            st.info("Do not treat the response as a verified finding. Check cited evidence IDs and corroborate claims with other artifacts.")
            st.markdown(previous["text"])

with exports:
    st.subheader("Evidence manifest")
    st.code(result["sha256"], language="text")
    st.caption(f"SHA-256 · exact uploaded file bytes · {result['byte_count']:,} bytes · {result['filename']}")
    st.subheader("Investigation notes")
    analyst_notes = st.text_area("Optional analyst notes (clearly marked unverified)", height=120,
                                 placeholder="Record observations, validation steps, and outstanding questions…")
    report = report_markdown(result, analyst_notes)
    a, b = st.columns(2)
    with a:
        st.download_button(
            "⇩ Download Markdown report", data=report, file_name="llm_dfir_triage_report.md",
            mime="text/markdown", use_container_width=True,
        )
    with b:
        st.download_button(
            "⇩ Download normalized JSON", data=json.dumps(result, indent=2, ensure_ascii=False),
            file_name="llm_dfir_normalized_events.json", mime="application/json", use_container_width=True,
        )
    with st.expander("Preview report"):
        st.markdown(report)

st.markdown('<div class="fineprint">LLM-DFIR • Human-in-the-loop security investigations • Source evidence is not persisted by this application • Use authorized data only</div>', unsafe_allow_html=True)
