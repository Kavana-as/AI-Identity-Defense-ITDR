from pyvis.network import Network
import pandas as pd

def generate_identity_attack_graph(rule_alerts, ml_alerts, df_events):
    """Builds an interactive PyVis network graph highlighting compromised paths."""
    net = Network(height="460px", width="100%", bgcolor="#0E1117", font_color="white")
    net.force_atlas_2based()

    compromised_users = set([a["user"] for a in rule_alerts] + [m["user"] for m in ml_alerts])
    added_nodes = set()

    for _, row in df_events.iterrows():
        user = str(row["user"])
        ip = str(row["ip_address"]) if row["ip_address"] and row["ip_address"] != "-" else "Unknown_IP"
        service = str(row["service_name"]) if pd.notna(row["service_name"]) and row["service_name"] else None

        # 1. Source IP Node (Gray Box)
        if ip not in added_nodes:
            net.add_node(ip, label=ip, color="#757575", size=14, shape="box", title=f"Source IP: {ip}")
            added_nodes.add(ip)

        # 2. User Identity Node (Red if Compromised, Blue if Normal)
        if user not in added_nodes:
            if user in compromised_users:
                net.add_node(user, label=user, color="#FF4B4B", size=28, title=f"COMPROMISED IDENTITY: {user}")
            else:
                net.add_node(user, label=user, color="#2196F3", size=16, title=f"Standard User: {user}")
            added_nodes.add(user)

        net.add_edge(ip, user, title="Event 4624: Authenticates From")

        # 3. Target Service SPN Node (Orange if Attacked via 0x17, Green if AES-256)
        if service:
            if service not in added_nodes:
                is_targeted = any(r.get("target_service") == service for r in rule_alerts)
                color = "#FF9800" if is_targeted else "#4CAF50"
                net.add_node(service, label=service, color=color, size=22, shape="diamond", title=f"Target SPN: {service}")
                added_nodes.add(service)
            net.add_edge(user, service, title="Event 4769: Kerberos TGS Requested")

    return net.generate_html()