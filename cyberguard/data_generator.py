"""
Sample security log data generator for CyberGuard AI Agent.
Generates realistic security events with normal activity and anomalies.
"""
import random
import numpy as np
from datetime import datetime, timedelta
from typing import List

random.seed(42)
np.random.seed(42)

SOURCES = ["firewall", "windows_event", "syslog", "antivirus", "vpn", "email_gateway", "active_directory", "web_server"]
EVENT_TYPES = ["login_attempt", "failed_login", "malware_detected", "usb_insertion", 
               "network_scan", "data_exfiltration", "phishing_email", "privilege_escalation",
               "vpn_connection", "dns_query", "port_scan", "policy_violation"]
SEVERITIES = ["low", "medium", "high", "critical"]
PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMTP"]
DEPARTMENTS = ["Engineering", "Finance", "HR", "Marketing", "Sales", "IT", "Executive", "Research"]
USERS_BY_DEPT = {
    "Engineering": ["alice", "bob", "charlie", "diana", "eve"],
    "Finance": ["frank", "grace", "henry"],
    "HR": ["isabel", "jack"],
    "Marketing": ["kate", "leo", "mia"],
    "Sales": ["noah", "olivia", "peter"],
    "IT": ["quinn", "rachel", "sam", "tracy"],
    "Executive": ["ursula", "victor"],
    "Research": ["wendy", "xavier", "yara", "zane"],
}
INTERNAL_IPS = [f"192.168.{random.randint(0,5)}.{random.randint(2,254)}" for _ in range(30)]
EXTERNAL_IPS = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]

MALICIOUS_IPS = [
    "45.33.32.156", "185.220.101.42", "91.121.87.123", "51.75.144.98",
    "162.247.74.201", "198.98.51.29", "107.189.8.184", "23.129.64.201",
]
SUSPICIOUS_PORTS = [22, 23, 3389, 445, 135, 139, 1433, 3306, 5900, 8080]


def _pick_user() -> tuple:
    dept = random.choice(DEPARTMENTS)
    user = random.choice(USERS_BY_DEPT[dept])
    return user, dept


def generate_normal_event(timestamp: str) -> dict:
    user, dept = _pick_user()
    source = random.choice(SOURCES)
    event_type = random.choice(EVENT_TYPES)
    severity = random.choices(
        SEVERITIES, weights=[0.6, 0.25, 0.12, 0.03]
    )[0]
    src_ip = random.choice(INTERNAL_IPS) if random.random() < 0.7 else random.choice(EXTERNAL_IPS)
    dst_ip = random.choice(INTERNAL_IPS)
    
    return {
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "username": user,
        "department": dept,
        "protocol": random.choice(PROTOCOLS),
        "port": random.choice([80, 443, 22, 8080, 53, 25, 3306, 5432]),
        "status": "normal",
        "details": f"Normal {event_type} from {src_ip} by user {user}",
        "raw_log": f"{timestamp} {source} {event_type} src={src_ip} dst={dst_ip} user={user}",
    }


def generate_attack_event(timestamp: str) -> dict:
    """Generate a malicious/anomalous event."""
    user, dept = _pick_user()
    attack_type = random.choice([
        "brute_force", "port_scan", "malware", "data_exfiltration", 
        "phishing", "privilege_escalation", "lateral_movement"
    ])
    
    src_ip = random.choice(MALICIOUS_IPS)
    dst_ip = random.choice(INTERNAL_IPS)
    
    if attack_type == "brute_force":
        return {
            "timestamp": timestamp,
            "source": "firewall",
            "event_type": "failed_login",
            "severity": "critical",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "username": user,
            "department": dept,
            "protocol": "SSH",
            "port": 22,
            "status": "attack",
            "details": f"Brute force attack detected: 320 failed logins from {src_ip} to {dst_ip} within 10 minutes",
            "raw_log": f"{timestamp} firewall failed_login src={src_ip} dst={dst_ip} user={user} count=320",
        }
    elif attack_type == "port_scan":
        return {
            "timestamp": timestamp,
            "source": "firewall",
            "event_type": "port_scan",
            "severity": "high",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "username": user,
            "department": dept,
            "protocol": "TCP",
            "port": random.choice(SUSPICIOUS_PORTS),
            "status": "attack",
            "details": f"Port scan detected from {src_ip} targeting {dst_ip} across 50+ ports",
            "raw_log": f"{timestamp} firewall port_scan src={src_ip} dst={dst_ip} ports=50",
        }
    elif attack_type == "malware":
        return {
            "timestamp": timestamp,
            "source": "antivirus",
            "event_type": "malware_detected",
            "severity": "critical",
            "source_ip": dst_ip,
            "dest_ip": src_ip,
            "username": user,
            "department": dept,
            "protocol": "HTTPS",
            "port": 443,
            "status": "attack",
            "details": f"Malware detected on {user}'s workstation: Trojan.Generic.12345 from {src_ip}",
            "raw_log": f"{timestamp} antivirus malware_detected host={dst_ip} user={user} threat=Trojan.Generic.12345",
        }
    elif attack_type == "data_exfiltration":
        return {
            "timestamp": timestamp,
            "source": "firewall",
            "event_type": "data_exfiltration",
            "severity": "critical",
            "source_ip": dst_ip,
            "dest_ip": src_ip,
            "username": user,
            "department": dept,
            "protocol": "HTTPS",
            "port": 443,
            "status": "attack",
            "details": f"Data exfiltration detected: 2.5GB uploaded from {user}'s machine to {src_ip}",
            "raw_log": f"{timestamp} firewall data_exfiltration src={dst_ip} dst={src_ip} user={user} volume=2.5GB",
        }
    elif attack_type == "phishing":
        return {
            "timestamp": timestamp,
            "source": "email_gateway",
            "event_type": "phishing_email",
            "severity": "high",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "username": user,
            "department": dept,
            "protocol": "SMTP",
            "port": 25,
            "status": "attack",
            "details": f"Phishing email detected from {src_ip} targeting {user} with malicious attachment",
            "raw_log": f"{timestamp} email_gateway phishing_email src={src_ip} to={user}@company.com subject='Urgent Invoice'",
        }
    elif attack_type == "privilege_escalation":
        return {
            "timestamp": timestamp,
            "source": "windows_event",
            "event_type": "privilege_escalation",
            "severity": "high",
            "source_ip": dst_ip,
            "dest_ip": dst_ip,
            "username": user,
            "department": dept,
            "protocol": "N/A",
            "port": 0,
            "status": "attack",
            "details": f"Privilege escalation detected: user {user} added to admin group from {src_ip}",
            "raw_log": f"{timestamp} windows_event privilege_escalation user={user} action=admin_group_add src={src_ip}",
        }
    else:
        return {
            "timestamp": timestamp,
            "source": "active_directory",
            "event_type": "login_attempt",
            "severity": "high",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "username": user,
            "department": dept,
            "protocol": "Kerberos",
            "port": 88,
            "status": "attack",
            "details": f"Lateral movement detected: {user} accessing {dst_ip} from unauthorized source {src_ip}",
            "raw_log": f"{timestamp} active_directory login_attempt src={src_ip} dst={dst_ip} user={user}",
        }


def seed_database(days: int = 7, events_per_hour: int = 50, attack_probability: float = 0.08) -> List[dict]:
    """Generate and return sample security events."""
    from .database import store_event, store_alert, get_connection
    from .anomaly_detector import compute_risk_score

    now = datetime.now()
    events = []

    for day_offset in range(days):
        for hour in range(24):
            for _ in range(events_per_hour):
                ts = now - timedelta(days=day_offset, hours=hour, 
                                    minutes=random.randint(0, 59),
                                    seconds=random.randint(0, 59))
                ts_str = ts.isoformat()

                if random.random() < attack_probability:
                    event = generate_attack_event(ts_str)
                else:
                    event = generate_normal_event(ts_str)

                event_id = store_event(event)
                event["id"] = event_id
                events.append(event)

                # Generate alerts for attack events
                if event["status"] == "attack":
                    risk = compute_risk_score(event)
                    alert = {
                        "timestamp": ts_str,
                        "event_id": event_id,
                        "alert_type": event["event_type"],
                        "risk_score": risk,
                        "risk_level": "critical" if risk > 0.8 else "high" if risk > 0.6 else "medium",
                        "description": event["details"],
                        "recommendation": _get_recommendation(event["event_type"]),
                    }
                    store_alert(alert)

    return events


def _get_recommendation(event_type: str) -> str:
    recommendations = {
        "failed_login": "Block source IP immediately. Enable MFA for affected accounts. Force password reset.",
        "port_scan": "Block scanning IP at firewall. Run vulnerability assessment on targeted systems.",
        "malware_detected": "Isolate affected workstation. Run full antivirus scan. Check for lateral movement.",
        "data_exfiltration": "Block outbound connection to destination. Revoke access credentials. Initiate incident response.",
        "phishing_email": "Delete email from all inboxes. Block sender domain. Educate user on phishing awareness.",
        "privilege_escalation": "Revert privilege changes. Audit admin group membership. Enable monitoring on critical systems.",
        "login_attempt": "Investigate login origin. Verify with user. Check for compromised credentials.",
        "network_scan": "Block source IP. Review firewall rules. Check for unauthorized devices.",
    }
    return recommendations.get(event_type, "Investigate and contain the threat. Escalate to SOC team.")
