import streamlit as st
import tempfile
import os
import pandas as pd
import streamlit.components.v1 as components

from evtx_parser import parse_security_events, generate_sample_attack_data
from ai_ueba_engine import run_deterministic_rules, run_ml_ueba, evaluate_containment_tier
from attack_graph import generate_identity_attack_graph
from ai_llm_agent import generate_ai_triage

st.set_page_config(page_title="AI-Driven ITDR Engine", page_icon="🛡️", layout="wide")

st.title("🛡️ AI-Driven Identity Threat Detection & Response (ITDR)")
st.markdown("Automated Active Directory Defense combining **Windows Event Telemetry**, **Deterministic Kerberos Inspection**, **Isolation Forest UEBA**, and **Local LLM Incident Triage**.")

st.divider()

with st.sidebar:
    st.header("⚙️ Data & Model Ingestion")
    data_source = st.radio("Telemetry Source", ["Load Built-in Attack Scenario", "Upload Raw Windows .evtx File"])
    
    uploaded_file = None
    if data_source == "Upload Raw Windows .evtx File":
        uploaded_file = st.file_uploader("Upload Security.evtx", type=["evtx"])
        
    contamination = st.slider("UEBA Sensitivity (Anomaly %)", 0.01, 0.10, 0.03, step=0.01)
    llm_model = st.selectbox("Ollama Model", ["llama3", "mistral", "qwen2.5"], index=0)
    st.info("🔍 **Active Detections**\n- Event 4624 (Logon UEBA)\n- Event 4769 (Kerberos 0x17)\n- MITRE T1558.003 & T1078")

df = pd.DataFrame()
if data_source == "Load Built-in Attack Scenario":
    df = generate_sample_attack_data()
    st.success("Loaded enterprise telemetry with simulated 02:45 AM RDP anomaly & Kerberoasting (0x17) attack.")
elif uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name
    with st.spinner("Parsing binary .evtx records..."):
        df = parse_security_events(tmp_path)
        os.remove(tmp_path)

if not df.empty:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events Ingested", len(df))
    c2.metric("Logon Events (4624)", len(df[df["event_id"] == "4624"]))
    c3.metric("Kerberos Tickets (4769)", len(df[df["event_id"] == "4769"]))
    c4.metric("Unique Identities", df["user"].nunique())

    rule_alerts = run_deterministic_rules(df)
    ml_alerts = run_ml_ueba(df, contamination=contamination)

    st.subheader("🕸️ Identity Attack Path & Blast Radius Graph")
    graph_html = generate_identity_attack_graph(rule_alerts, ml_alerts, df)
    components.html(graph_html, height=480)

    t1, t2, t3 = st.tabs(["⚡ Graduated Containment & AI Triage", "🚨 Kerberoasting Detections", "🧠 UEBA Anomaly Baseline"])

    with t1:
        st.subheader("Autonomous Containment & LLM Briefing")
        flagged_users = list(set([a["user"] for a in rule_alerts] + [m["user"] for m in ml_alerts]))
        
        if flagged_users:
            selected_user = st.selectbox("Select Compromised Account for Triage:", flagged_users)
            containment = evaluate_containment_tier(selected_user, rule_alerts, ml_alerts)

            col_tier, col_details = st.columns([1, 2])
            with col_tier:
                st.metric("Correlated Risk Score", f"{containment['risk_score']}/100")
                if containment["tier"] == "TIER_3_HARD_CONTAINMENT":
                    st.error(f"🔴 **{containment['tier']}**")
                elif containment["tier"] == "TIER_2_SOFT_CONTAINMENT":
                    st.warning(f"🟡 **{containment['tier']}**")
                else:
                    st.info(f"🔵 **{containment['tier']}**")
                st.write(f"**Action:** `{containment['action']}`")

            with col_details:
                st.write("**Justification:**", containment["justification"])
                st.write("**Detected Signals:**", ", ".join(containment["detected_signals"]))
                if containment["powershell_command"]:
                    st.code(containment["powershell_command"], language="powershell")

            st.divider()
            if st.button("🤖 Generate AI Security Briefing (Ollama / MITRE ATT&CK)", type="primary"):
                with st.spinner("Generating SecOps Incident Triage Report..."):
                    briefing = generate_ai_triage(containment, model=llm_model)
                    st.markdown(briefing)
        else:
            st.success("No identities flagged for containment.")

    with t2:
        st.subheader("Kerberoasting & Signature Detections (Event 4769)")
        if rule_alerts:
            st.error(f"Detected {len(rule_alerts)} High-Risk Kerberos Ticket Downgrade(s)")
            st.dataframe(pd.DataFrame(rule_alerts), use_container_width=True)
        else:
            st.info("No legacy RC4 ticket requests detected.")

    with t3:
        st.subheader("Isolation Forest Statistical Outliers (Event 4624)")
        if ml_alerts:
            st.warning(f"Identified {len(ml_alerts)} Behavioral Logon Outlier(s)")
            st.dataframe(pd.DataFrame(ml_alerts), use_container_width=True)
        else:
            st.info("Logon patterns conform to normal baseline.")
else:
    st.info("Select a telemetry source in the sidebar to begin analysis.")