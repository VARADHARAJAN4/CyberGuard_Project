"""
CyberGuard AI Agent - LangChain-powered cybersecurity analysis agent.
Provides natural language reasoning about security events, threat intelligence,
and remediation recommendations.
"""
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Optional

from .database import (
    get_recent_events, get_open_alerts, get_top_attackers,
    get_department_risk, get_event_stats, get_events_by_type,
    get_incident_reports, store_incident_report, get_connection,
)
from .anomaly_detector import AnomalyDetector, compute_risk_score, classify_risk_level


class CyberGuardAgent:
    """
    AI Agent that analyzes security logs, detects threats, explains findings,
    and recommends remediation actions using rule-based reasoning and ML.
    """

    def __init__(self):
        self.detector = AnomalyDetector()
        self._detector_fitted = False

    def fit_detector(self, events: Optional[List[dict]] = None):
        """Fit the ML anomaly detector on historical events."""
        if events is None:
            events = get_recent_events(limit=5000, hours=168)
        if len(events) >= 10:
            self.detector.fit(events)
            self._detector_fitted = True

    # ── Analysis Methods ────────────────────────────────────────────

    def analyze_recent_events(self, hours: int = 24) -> dict:
        """Analyze recent security events and return insights."""
        events = get_recent_events(limit=1000, hours=hours)
        if not events:
            return {"summary": "No recent events found.", "findings": []}

        stats = get_event_stats(hours=hours)
        attackers = get_top_attackers(hours=hours)
        dept_risk = get_department_risk(hours=hours)
        alerts = get_open_alerts(hours=hours)

        findings = []

        # Check for brute force indicators
        failed_logins = [e for e in events if e["event_type"] == "failed_login"]
        if len(failed_logins) > 10:
            ips = set(e["source_ip"] for e in failed_logins)
            findings.append(
                f"⚠️ {len(failed_logins)} failed logins detected from {len(ips)} IPs. "
                f"Possible brute-force attack in progress."
            )

        # Check for malware
        malware = [e for e in events if e["event_type"] == "malware_detected"]
        if malware:
            hosts = set(e.get("username", "unknown") for e in malware)
            findings.append(
                f"🚨 {len(malware)} malware alerts on {len(hosts)} workstations. "
                f"Affected users: {', '.join(hosts)}."
            )

        # Check for data exfiltration
        exfil = [e for e in events if e["event_type"] == "data_exfiltration"]
        if exfil:
            findings.append(
                f"🔴 {len(exfil)} data exfiltration attempts detected. "
                f"Immediate investigation required."
            )

        # Top attacker analysis
        if attackers:
            top = attackers[0]
            findings.append(
                f"🎯 Top attacker IP: {top['source_ip']} with {top['count']} events "
                f"({top['critical_count']} critical)."
            )

        # Department risk
        if dept_risk:
            highest = dept_risk[0]
            findings.append(
                f"📊 Highest risk department: {highest['department']} "
                f"(risk score: {highest['risk_score']:.2f})."
            )

        # Overall assessment
        threat_level = "CRITICAL" if len(alerts) > 20 else "HIGH" if len(alerts) > 10 else "MEDIUM" if len(alerts) > 3 else "LOW"
        summary = (
            f"📋 Security Assessment (last {hours}h): {stats['total_events']} total events, "
            f"{stats['open_alerts']} open alerts. Threat level: {threat_level}."
        )

        return {
            "summary": summary,
            "findings": findings,
            "threat_level": threat_level,
            "total_events": stats["total_events"],
            "open_alerts": stats["open_alerts"],
            "attackers": attackers[:5],
            "department_risk": dept_risk,
            "event_breakdown": stats["by_type"],
        }

    def analyze_event(self, event: dict) -> str:
        """Generate a plain-language explanation for a security event."""
        event_type = event.get("event_type", "unknown")
        severity = event.get("severity", "low")
        source_ip = event.get("source_ip", "unknown")
        username = event.get("username", "unknown")
        details = event.get("details", "")

        explanations = {
            "failed_login": (
                f"User **{username}** had a failed login from IP **{source_ip}**. "
                f"Multiple such attempts may indicate a brute-force attack."
            ),
            "malware_detected": (
                f"🚨 Malware detected on **{username}**'s workstation originating from "
                f"**{source_ip}**. Immediate isolation recommended."
            ),
            "port_scan": (
                f"🔍 Port scan detected from **{source_ip}**. This is often a reconnaissance "
                f"step before a targeted attack."
            ),
            "data_exfiltration": (
                f"🔴 **{username}**'s machine sent unusual data volume to **{source_ip}**. "
                f"This could indicate data theft."
            ),
            "phishing_email": (
                f"📧 Phishing email targeting **{username}** from **{source_ip}**. "
                f"User may have received a malicious attachment."
            ),
            "privilege_escalation": (
                f"⚡ Privilege escalation by **{username}** from **{source_ip}**. "
                f"Unauthorized admin access attempted."
            ),
        }

        base = explanations.get(event_type,
            f"Event: {event_type} from {source_ip} involving {username}."
        )
        return f"{base}\nSeverity: **{severity.upper()}**\nDetails: {details}"

    def predict_attack(self, event: dict) -> dict:
        """Use ML model to predict if an event is an attack."""
        if not self._detector_fitted:
            return {"prediction": "Model not trained", "confidence": 0.0}

        result = self.detector.predict(event)
        risk = compute_risk_score(event)
        level = classify_risk_level(risk)

        return {
            "prediction": "ATTACK" if result["is_anomaly"] or risk > 0.5 else "NORMAL",
            "ml_anomaly_score": result["anomaly_score"],
            "risk_score": risk,
            "risk_level": level,
            "confidence": max(result["anomaly_score"], risk),
        }

    def recommend_actions(self, alert: dict) -> List[str]:
        """Generate remediation recommendations for an alert."""
        alert_type = alert.get("alert_type", "")
        risk_score = alert.get("risk_score", 0.5)
        description = alert.get("description", "")

        recommendations = {
            "failed_login": [
                "🔒 Block the source IP address at the firewall",
                "🔑 Enable Multi-Factor Authentication (MFA) for affected accounts",
                "🔄 Force password reset for compromised credentials",
                "📋 Review account lockout policies",
                "🔍 Investigate if other accounts show similar patterns",
            ],
            "port_scan": [
                "🚫 Block scanning IP at perimeter firewall",
                "🔍 Run vulnerability scan on targeted systems",
                "📋 Review firewall rules for unnecessary open ports",
                "🛡️ Enable intrusion prevention system (IPS) rules",
            ],
            "malware_detected": [
                "🛑 Isolate affected workstation from network immediately",
                "🔄 Run full antivirus/EDR scan on host",
                "🔍 Check for lateral movement to other systems",
                "📊 Review recent outbound connections from affected host",
                "🔄 Update antivirus signatures across the organization",
            ],
            "data_exfiltration": [
                "🚫 Block outbound connection to destination IP",
                "🔑 Revoke access credentials for affected user",
                "🚨 Initiate incident response process",
                "📋 Review Data Loss Prevention (DLP) policies",
                "🔍 Investigate scope of data accessed",
            ],
            "phishing_email": [
                "🗑️ Delete email from all user mailboxes",
                "🚫 Block sender domain at email gateway",
                "📋 Educate user on phishing awareness",
                "🔍 Check if other users received similar emails",
                "📊 Report threat to threat intelligence platform",
            ],
            "privilege_escalation": [
                "🔄 Revert privilege changes immediately",
                "📋 Audit all admin group memberships",
                "🔍 Enable advanced auditing on domain controllers",
                "📊 Review recent privileged access logs",
                "🔒 Implement just-in-time (JIT) admin access",
            ],
        }

        recs = recommendations.get(alert_type, [
            "🔍 Investigate and contain the threat",
            "📋 Escalate to SOC team for further analysis",
            "📊 Document findings in incident report",
        ])

        if risk_score > 0.8:
            recs.insert(0, "🚨 **CRITICAL** - Immediate action required")

        return recs

    def generate_incident_report(self, hours: int = 24) -> str:
        """Generate a comprehensive incident report for the time period."""
        analysis = self.analyze_recent_events(hours=hours)
        alerts = get_open_alerts(hours=hours)
        attackers = get_top_attackers(hours=hours)
        dept_risk = get_department_risk(hours=hours)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        period_start = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            "=" * 60,
            "         CYBERGUARD INCIDENT REPORT",
            "=" * 60,
            f"Generated: {now}",
            f"Period: {period_start} to {now}",
            "",
            "── EXECUTIVE SUMMARY ──",
            analysis["summary"],
            "",
            "── KEY FINDINGS ──",
        ]

        for f in analysis["findings"]:
            lines.append(f"  {f}")

        lines.extend([
            "",
            "── TOP ATTACKERS ──",
        ])
        for a in attackers[:5]:
            lines.append(f"  • {a['source_ip']}: {a['count']} events ({a['critical_count']} critical)")

        lines.extend([
            "",
            "── DEPARTMENT RISK ──",
        ])
        for d in dept_risk[:5]:
            lines.append(f"  • {d['department']}: risk {d['risk_score']:.2f}, {d['event_count']} events")

        lines.extend([
            "",
            "── OPEN ALERTS ──",
        ])
        for a in alerts[:10]:
            lines.append(f"  • [{a['risk_level'].upper()}] {a['alert_type']}: {a['description'][:100]}")

        # Top recommended actions
        if alerts:
            lines.extend([
                "",
                "── RECOMMENDED ACTIONS ──",
            ])
            for a in alerts[:3]:
                recs = self.recommend_actions(a)
                lines.append(f"  • {recs[0]}")
                if len(recs) > 1:
                    lines.append(f"    {recs[1]}")

        lines.append("")
        lines.append("=" * 60)
        lines.append("         END OF REPORT")
        lines.append("=" * 60)

        report_text = "\n".join(lines)

        # Store report in database
        store_incident_report({
            "timestamp": datetime.now().isoformat(),
            "title": f"Incident Report - {period_start.split('T')[0]}",
            "summary": analysis["summary"],
            "attack_type": ", ".join(set(a["alert_type"] for a in alerts[:10])),
            "affected_systems": ", ".join(set(a.get("source_ip", "") for a in alerts[:10])),
            "severity": analysis["threat_level"],
            "recommendations": report_text,
        })

        return report_text

    def answer_query(self, query: str) -> str:
        """Answer natural language questions about security posture."""
        query = query.lower()
        alerts = get_open_alerts(hours=48)
        stats = get_event_stats(hours=24)
        attackers = get_top_attackers()
        dept_risk = get_department_risk()

        if "attack" in query and "today" in query:
            types = stats.get("by_type", {})
            attack_types = {k: v for k, v in types.items() 
                          if k in ["failed_login", "malware_detected", "data_exfiltration", 
                                   "phishing_email", "port_scan", "privilege_escalation"]}
            if attack_types:
                parts = [f"  • {k.replace('_', ' ').title()}: {v} events" for k, v in attack_types.items()]
                return f"Today's attacks detected:\n" + "\n".join(parts)
            return "No significant attacks detected in the last 24 hours."

        if "suspicious" in query and "ip" in query:
            if attackers:
                parts = [f"  • {a['source_ip']}: {a['count']} events" for a in attackers[:5]]
                return f"Most suspicious IP addresses:\n" + "\n".join(parts)
            return "No suspicious IPs detected."

        if "department" in query and ("risk" in query or "cyber" in query):
            if dept_risk:
                parts = [f"  • {d['department']}: risk {d['risk_score']:.2f}" for d in dept_risk[:5]]
                return f"Department cyber risk assessment:\n" + "\n".join(parts)
            return "No department risk data available."

        if "malware" in query:
            count = stats.get("by_type", {}).get("malware_detected", 0)
            return f"There {'is' if count == 1 else 'are'} {count} malware event{'s' if count != 1 else ''} in the last 24 hours."

        if "predict" in query and "risk" in query:
            total = stats.get("total_events", 0)
            alert_count = stats.get("open_alerts", 0)
            ratio = alert_count / max(total, 1)
            if ratio > 0.1:
                return f"⚠️ Tomorrow's cyber risk is predicted to be HIGH based on {alert_count} open alerts from {total} events today."
            elif ratio > 0.05:
                return f"📊 Tomorrow's cyber risk is MEDIUM. Monitor {attackers[0]['source_ip']} if available."
            return "✅ Tomorrow's cyber risk is LOW. Continue normal monitoring."

        if "patching" in query or "patch" in query:
            return ("🔧 Systems requiring immediate patching:\n"
                    "  • Servers with open RDP ports (3389)\n"
                    "  • Systems with known vulnerabilities from recent port scans\n"
                    "  • Workstations with out-of-date antivirus signatures")

        if "report" in query:
            return self.generate_incident_report(hours=24)

        return (
            f"I can analyze your security posture. Here's a snapshot:\n"
            f"• {stats['total_events']} events, {stats['open_alerts']} open alerts in 24h\n"
            f"• Top threat: {attackers[0]['source_ip'] if attackers else 'N/A'}\n\n"
            f"Try asking about: attacks today, suspicious IPs, department risk, "
            f"malware events, risk prediction, patching, or generate a report."
        )
