import json
import pandas as pd
from sklearn.ensemble import IsolationForest
from evtx_parser import generate_sample_attack_data

def run_deterministic_rules(df):
    """Flags Kerberoasting: Event 4769 with 0x17 (RC4) on non-machine accounts."""
    rule_alerts = []
    kerb_requests = df[df["event_id"] == "4769"]
    
    for _, row in kerb_requests.iterrows():
        if row["ticket_encryption"] == "0x17" and not str(row["service_name"]).endswith("$"):
            rule_alerts.append({
                "type": "RULE_MATCH",
                "attack": "Kerberoasting (T1558.003)",
                "user": row["user"],
                "target_service": row["service_name"],
                "ip_address": row["ip_address"],
                "timestamp": str(row["timestamp"]),
                "base_severity": 55,
                "details": f"Legacy RC4 (0x17) encryption requested for SPN '{row['service_name']}'."
            })
    return rule_alerts


def run_ml_ueba(df, contamination=0.03):
    """
    Trains Isolation Forest on logon telemetry (Event 4624) AND evaluates 
    behavioral ticket velocity/SPN diversity (Event 4769) to catch stealthy AES-256 sweeps.
    """
    ml_alerts = []

    # 1. Logon Behavior Anomaly Detection (Event 4624)
    logons = df[df["event_id"] == "4624"].copy()
    if len(logons) >= 5:
        features = logons[["hour", "day_of_week", "logon_type"]]
        model = IsolationForest(contamination=contamination, random_state=42)
        logons["anomaly_label"] = model.fit_predict(features)
        logons["score"] = model.decision_function(features)

        anomalies = logons[logons["anomaly_label"] == -1]
        
        for _, row in anomalies.iterrows():
            behavioral_risk = min(40, max(25, int(abs(row["score"]) * 100)))
            ml_alerts.append({
                "type": "ML_ANOMALY",
                "attack": "Anomalous Credential Access (T1078)",
                "user": row["user"],
                "ip_address": row["ip_address"],
                "timestamp": str(row["timestamp"]),
                "base_severity": behavioral_risk,
                "details": f"Off-hours authentication at {row['hour']:02d}:00 with LogonType {row['logon_type']}."
            })

    # 2. v2.0 Upgrade: Behavioral SPN Sweep / Ticket Velocity Detection (Event 4769)
    # Catches stealthy AES-256 (0x12) Kerberoasting where 0x17 deterministic signatures are 0
    tgs_events = df[df["event_id"] == "4769"].copy()
    if not tgs_events.empty:
        for user, group in tgs_events.groupby("user"):
            unique_spns = group["service_name"].nunique()
            total_tickets = len(group)
            rc4_count = len(group[group["ticket_encryption"] == "0x17"])

            # If a user requests >= 5 unique SPNs using only strong encryption (AES-256 0x12)
            if unique_spns >= 5 and rc4_count == 0:
                latest_row = group.iloc[-1]
                ml_alerts.append({
                    "type": "ML_ANOMALY",
                    "attack": "Stealthy AES-256 Kerberoasting Sweep (T1558.003 - Behavioral)",
                    "user": user,
                    "ip_address": latest_row["ip_address"],
                    "timestamp": str(latest_row["timestamp"]),
                    "base_severity": 65,
                    "details": (
                        f"High-velocity TGS sweep: {total_tickets} tickets across {unique_spns} unique SPNs "
                        f"using AES-256 (0x12) to evade legacy 0x17 signature rules."
                    )
                })

    return ml_alerts


def get_user_xai_baseline(df, user="john.doe"):
    """
    v2.0 Explainable AI (XAI) Helper: Computes historical peer baseline vs. target user's 
    observed session behavior to display alongside the Ollama Llama 3 incident report.
    """
    tgs_df = df[df["event_id"] == "4769"]
    user_tgs = tgs_df[tgs_df["user"] == user]
    peer_tgs = tgs_df[tgs_df["user"] != user]

    peer_avg_spns = int(peer_tgs.groupby("user")["service_name"].nunique().mean()) if not peer_tgs.empty else 1
    user_unique_spns = int(user_tgs["service_name"].nunique())
    user_total_tgs = len(user_tgs)
    rc4_tickets = len(user_tgs[user_tgs["ticket_encryption"] == "0x17"])
    aes_tickets = len(user_tgs[user_tgs["ticket_encryption"] == "0x12"])

    return {
        "user": user,
        "peer_baseline_spns_per_day": peer_avg_spns,
        "observed_unique_spns": user_unique_spns,
        "spn_delta": user_unique_spns - peer_avg_spns,
        "observed_total_tgs": user_total_tgs,
        "rc4_0x17_count": rc4_tickets,
        "aes_0x12_count": aes_tickets,
        "raw_tgs_records": user_tgs[["timestamp", "event_id", "user", "ip_address", "ticket_encryption", "service_name"]]
    }


def evaluate_containment_tier(user, rule_alerts, ml_alerts):
    """Correlates rule hits and UEBA anomalies into graduated containment tiers."""
    total_risk_score = 0
    signals = []

    user_rules = [r for r in rule_alerts if r["user"] == user]
    user_ml = [m for m in ml_alerts if m["user"] == user]

    for r in user_rules:
        total_risk_score += r["base_severity"]
        signals.append(r["attack"])

    for m in user_ml:
        total_risk_score += m["base_severity"]
        signals.append(m["attack"])

    total_risk_score = min(total_risk_score, 100)

    if total_risk_score >= 80:
        tier = "TIER_3_HARD_CONTAINMENT"
        action = "AUTO_EXECUTE_DISABLE_AND_ISOLATE"
        ps_cmd = f'Disable-ADAccount -Identity "{user}"; Revoke-AzureADUserAllRefreshToken -ObjectId "{user}"'
        if len(user_rules) == 0:
            reason = f"Critical Risk ({total_risk_score}/100): Behavioral UEBA caught high-velocity AES-256 (0x12) SPN sweep + off-hours RDP (0 deterministic signature hits)."
        else:
            reason = f"Critical Risk ({total_risk_score}/100): Confirmed Kerberoasting downgrade paired with behavioral anomaly."
    elif total_risk_score >= 40:
        tier = "TIER_2_SOFT_CONTAINMENT"
        action = "REVOKE_SESSION_AND_REQUIRE_MFA"
        ps_cmd = f'Revoke-MgUserAllRefreshToken -UserId "{user}"'
        reason = f"Elevated Risk ({total_risk_score}/100): Statistical anomaly detected. Revoking active refresh tokens."
    else:
        tier = "TIER_1_MONITORING"
        action = "FLAG_FOR_ANALYST_REVIEW"
        ps_cmd = None
        reason = f"Low Risk ({total_risk_score}/100): Monitored within tolerable deviation baseline."

    return {
        "user": user,
        "risk_score": total_risk_score,
        "tier": tier,
        "action": action,
        "powershell_command": ps_cmd,
        "detected_signals": list(set(signals)),
        "justification": reason
    }


if __name__ == "__main__":
    print("=" * 70)
    print(" 🛡️  AI-ITDR HYBRID DETECTION & GRADUATED CONTAINMENT ENGINE (CLI)")
    print("=" * 70)
    df = generate_sample_attack_data()
    
    rule_alerts = run_deterministic_rules(df)
    ml_alerts = run_ml_ueba(df, contamination=0.03)
    
    print(f"\n[+] Deterministic Signature Hits (Kerberoasting 0x17): {len(rule_alerts)}")
    for r in rule_alerts:
        print(f"    -> [RULE] User: {r['user']} | SPN: {r['target_service']} | IP: {r['ip_address']}")

    print(f"\n[+] Unsupervised ML Outliers (Isolation Forest UEBA): {len(ml_alerts)}")
    for m in ml_alerts:
        print(f"    -> [UEBA] User: {m['user']} | Details: {m['details']}")

    print("\n[+] Correlating Signals & Evaluating Graduated Response for 'john.doe':")
    decision = evaluate_containment_tier("john.doe", rule_alerts, ml_alerts)
    print(json.dumps(decision, indent=2))
    print("=" * 70)