import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import pandas as pd

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def parse_security_events(evtx_file_path):
    """Parses raw binary .evtx files into a structured Pandas DataFrame."""
    from Evtx.Evtx import Evtx
    records = []
    
    with Evtx(evtx_file_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                event_id_elem = root.find(f".//{NS}EventID")
                if event_id_elem is None:
                    continue
                event_id = event_id_elem.text
                time_elem = root.find(f".//{NS}TimeCreated")
                time_created = time_elem.attrib.get("SystemTime") if time_elem is not None else datetime.utcnow().isoformat()

                data = {}
                for d in root.findall(f".//{NS}Data"):
                    name = d.attrib.get("Name")
                    if name:
                        data[name] = d.text

                dt = datetime.fromisoformat(time_created.replace("Z", "+00:00"))

                if event_id == "4624":
                    records.append({
                        "timestamp": dt,
                        "event_id": "4624",
                        "user": data.get("TargetUserName", "Unknown"),
                        "domain": data.get("TargetDomainName", ""),
                        "logon_type": int(data.get("LogonType", 3)),
                        "ip_address": data.get("IpAddress", "10.0.0.15"),
                        "hour": dt.hour,
                        "day_of_week": dt.weekday(),
                        "ticket_encryption": None,
                        "service_name": None
                    })
                elif event_id == "4769":
                    records.append({
                        "timestamp": dt,
                        "event_id": "4769",
                        "user": data.get("TargetUserName", "Unknown"),
                        "domain": data.get("TargetDomainName", ""),
                        "logon_type": None,
                        "ip_address": data.get("IpAddress", "10.0.0.15"),
                        "hour": dt.hour,
                        "day_of_week": dt.weekday(),
                        "ticket_encryption": data.get("TicketEncryptionType", ""),
                        "service_name": data.get("ServiceName", "")
                    })
            except Exception:
                continue
                
    return pd.DataFrame(records)


def generate_sample_attack_data():
    """Generates enterprise baseline telemetry with an embedded 2:45 AM Kerberoasting attack."""
    records = []
    base_time = datetime.now() - timedelta(days=2)
    standard_users = ["alice.smith", "bob.jones", "charlie.brown", "dev_deployer"]

    # 1. Normal daytime logins (8 AM - 6 PM, LogonType 2 & 3)
    for i in range(120):
        user = standard_users[i % len(standard_users)]
        ts = base_time + timedelta(hours=(i % 10) + 8, minutes=(i * 17) % 60)
        records.append({
            "timestamp": ts,
            "event_id": "4624",
            "user": user,
            "domain": "CORP",
            "logon_type": 3 if user == "dev_deployer" else 2,
            "ip_address": f"192.168.1.{50 + (i % 10)}",
            "hour": ts.hour,
            "day_of_week": ts.weekday(),
            "ticket_encryption": None,
            "service_name": None
        })

    # 2. Normal Kerberos service tickets using strong AES-256 encryption (0x12)
    for i in range(30):
        ts = base_time + timedelta(hours=10 + (i % 6))
        records.append({
            "timestamp": ts,
            "event_id": "4769",
            "user": "alice.smith",
            "domain": "CORP",
            "logon_type": None,
            "ip_address": "192.168.1.52",
            "hour": ts.hour,
            "day_of_week": ts.weekday(),
            "ticket_encryption": "0x12",
            "service_name": "MSSQLSvc/db01.corp.local"
        })

    # 3. THE ATTACK: Compromised account 'john.doe' logs in via RDP (Type 10) at 02:45 AM
    attack_ts = base_time.replace(hour=2, minute=45, second=12) + timedelta(days=1)
    records.append({
        "timestamp": attack_ts,
        "event_id": "4624",
        "user": "john.doe",
        "domain": "CORP",
        "logon_type": 10,
        "ip_address": "172.16.4.99",
        "hour": 2,
        "day_of_week": attack_ts.weekday(),
        "ticket_encryption": None,
        "service_name": None
    })

    # 4. THE ESCALATION: 'john.doe' requests weak RC4 (0x17) Kerberos tickets (Kerberoasting)
    for target_spn in ["MSSQLSvc/prod-db.corp.local", "backup_admin_svc"]:
        records.append({
            "timestamp": attack_ts + timedelta(minutes=4),
            "event_id": "4769",
            "user": "john.doe",
            "domain": "CORP",
            "logon_type": None,
            "ip_address": "172.16.4.99",
            "hour": 2,
            "day_of_week": attack_ts.weekday(),
            "ticket_encryption": "0x17",
            "service_name": target_spn
        })

    return pd.DataFrame(records)


if __name__ == "__main__":
    print("[*] Generating and parsing enterprise authentication telemetry...")
    df = generate_sample_attack_data()
    print(f"[+] Total Events Extracted: {len(df)}")
    print(f"    - Event 4624 (Logons): {len(df[df['event_id'] == '4624'])}")
    print(f"    - Event 4769 (Kerberos Tickets): {len(df[df['event_id'] == '4769'])}")
    print("\n[*] Previewing the last 5 records (Notice john.doe at 02:45 AM):")
    print(df[["timestamp", "event_id", "user", "ip_address", "logon_type", "ticket_encryption", "service_name"]].tail(5).to_string(index=False))