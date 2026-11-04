# 🛡️ AI-Driven Identity Threat Detection & Response (ITDR) Engine

An automated Active Directory defense pipeline combining Windows Event Telemetry, deterministic Kerberos inspection, unsupervised Machine Learning (Isolation Forest UEBA), interactive blast-radius network graphing, and privacy-preserving local GenAI incident triage (Ollama / Llama 3).

---

## 📸 Project Visuals & Execution

### 1. Hybrid Detection Engine (CLI)
![CLI Detection Engine](assets/1_cli_detection.PNG)
*Running the detection engine locally to correlate deterministic Kerberoasting rules and Isolation Forest UEBA anomalies, scoring compromised identity `john.doe` at 100/100.*
### 2. Identity Attack Path & Blast Radius Graph

![Attack Graph](assets/2_attack_graph.PNG)
*Interactive PyVis blast-radius visualization mapping source RDP compromise nodes to targeted production Service Principal Names (SPN diamonds).*

![Web Launch Interface](assets/2_web_launch.PNG)
*Streamlit web launch and dashboard interface showcasing live SOC controls.*

### 3. Graduated Containment Panel
![Containment Panel](assets/3_containment_panel.PNG)
*Automated Tier 3 hard containment evaluating risk severity and generating pre-written PowerShell remediation scripts (`Disable-ADAccount`).*
![Kerberoasting and Signature Detection](assets/3_Kerberoasting&Signature_Detection.PNG)


### 4. Local AI SecOps Incident Briefing
![AI Triage Report](assets/4_ai_triage_report.PNG)
*Generated local LLM (Ollama / Llama 3) security briefing outlining executive summary, MITRE ATT&CK alignment, and forensic recommendations.*

---

## 🏗️ Architecture & Features

1. **Telemetry Ingestion Layer (`evtx_parser.py`)**: Parses raw Windows Event logs or enterprise baseline templates (Events `4624` for successful logons and `4769` for Kerberos TGS requests).
2. **Hybrid Detection Engine (`ai_ueba_engine.py`)**: 
   * **Deterministic Signatures:** Flags offline Kerberoasting attempts by identifying weak RC4 (`0x17`) ticket encryption requests on non-machine accounts.
   * **Unsupervised UEBA:** Utilizes scikit-learn's `IsolationForest` on logon hours, weekdays, and logon types (e.g., Type 10 RDP off-hours) to detect statistical behavioral anomalies.
   * **Graduated Response Scoring:** Correlates rule hits and UEBA anomalies into Tiers 1 through 3, automatically generating PowerShell containment commands.
3. **Interactive Blast-Radius Graph (`attack_graph.py`)**: Renders dynamic network graphs mapping source IPs, user identities, and target SPN assets.
4. **Local GenAI Triage Agent (`ai_llm_agent.py`)**: Integrates with local Ollama (`llama3`) to synthesize automated incident reports mapped directly to **MITRE ATT&CK (`T1558.003` & `T1078`)**.
    
   > *Note: Ensure Ollama is installed and running locally with `ollama run llama3` to enable autonomous local GenAI incident triage briefings.*
6. **Streamlit Web Dashboard (`app.py`)**: A modern SOC analyst interface providing live metrics, interactive tabs, and autonomous containment controls.

---

## 🚀 Quick Start

1. Clone the repository:
   ```bash
   git clone [https://github.com/Kavana-as/AI-Identity-Defense-ITDR.git](https://github.com/Kavana-as/AI-Identity-Defense-ITDR.git)
   cd AI-Identity-Defense-ITDR

2. Create and activate a virtual environment:
    ```bash
    PowerShell
    python -m venv .venv
    .venv\Scripts\Activate.ps1
   
4. Install dependencies:
    ```bash
    PowerShell
    pip install -r requirements.txt
   
6. Run the hybrid detection engine:
    ```bash
    PowerShell
    python ai_ueba_engine.py
   
8. Launch the Streamlit SOC Web Dashboard:
    ```bash
    PowerShell
    streamlit run app.py
