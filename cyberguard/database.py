"""
Database module for CyberGuard AI Agent.
Uses SQLite for storing security events, alerts, and recommendations.
"""
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
from .config import DB_PATH


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT DEFAULT 'low',
                source_ip TEXT,
                dest_ip TEXT,
                username TEXT,
                department TEXT,
                protocol TEXT,
                port INTEGER,
                status TEXT DEFAULT 'normal',
                details TEXT,
                raw_log TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_id INTEGER,
                alert_type TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                description TEXT,
                recommendation TEXT,
                status TEXT DEFAULT 'open',
                FOREIGN KEY (event_id) REFERENCES security_events(id)
            );

            CREATE TABLE IF NOT EXISTS incident_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                attack_type TEXT,
                affected_systems TEXT,
                severity TEXT,
                recommendations TEXT,
                status TEXT DEFAULT 'generated'
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk_score);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        """)


def store_event(event: dict) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO security_events 
               (timestamp, source, event_type, severity, source_ip, dest_ip,
                username, department, protocol, port, status, details, raw_log)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.get("timestamp", datetime.now().isoformat()),
                event.get("source", "unknown"),
                event.get("event_type", "unknown"),
                event.get("severity", "low"),
                event.get("source_ip"),
                event.get("dest_ip"),
                event.get("username"),
                event.get("department"),
                event.get("protocol"),
                event.get("port"),
                event.get("status", "normal"),
                event.get("details", ""),
                event.get("raw_log", ""),
            ),
        )
        return cur.lastrowid


def store_alert(alert: dict) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO alerts
               (timestamp, event_id, alert_type, risk_score, risk_level, description, recommendation)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.get("timestamp", datetime.now().isoformat()),
                alert.get("event_id"),
                alert.get("alert_type", "unknown"),
                alert.get("risk_score", 0.0),
                alert.get("risk_level", "low"),
                alert.get("description", ""),
                alert.get("recommendation", ""),
            ),
        )
        return cur.lastrowid


def get_recent_events(limit: int = 100, hours: int = 24) -> list:
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM security_events WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
            (cutoff, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_open_alerts(hours: int = 48) -> list:
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE timestamp >= ? AND status = 'open' ORDER BY risk_score DESC",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_events_by_type(event_type: str, hours: int = 24) -> list:
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM security_events WHERE event_type = ? AND timestamp >= ? ORDER BY timestamp DESC",
            (event_type, cutoff),
        ).fetchall()
        return [dict(r) for r in rows]


def get_top_attackers(limit: int = 10, hours: int = 24) -> list:
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT source_ip, COUNT(*) as count, 
               SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical_count
               FROM security_events 
               WHERE timestamp >= ? AND source_ip IS NOT NULL
               GROUP BY source_ip 
               ORDER BY count DESC LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_department_risk(hours: int = 24) -> list:
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT department, COUNT(*) as event_count,
               AVG(CASE WHEN severity='critical' THEN 1.0 WHEN severity='high' THEN 0.7 
                   WHEN severity='medium' THEN 0.4 ELSE 0.1 END) as risk_score
               FROM security_events 
               WHERE timestamp >= ? AND department IS NOT NULL
               GROUP BY department ORDER BY risk_score DESC""",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_event_stats(hours: int = 24) -> dict:
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) as c FROM security_events WHERE timestamp >= ?", (cutoff,)
        ).fetchone()["c"]

        by_type = conn.execute(
            "SELECT event_type, COUNT(*) as c FROM security_events WHERE timestamp >= ? GROUP BY event_type ORDER BY c DESC",
            (cutoff,),
        ).fetchall()

        by_severity = conn.execute(
            "SELECT severity, COUNT(*) as c FROM security_events WHERE timestamp >= ? GROUP BY severity",
            (cutoff,),
        ).fetchall()

        alerts_count = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE timestamp >= ? AND status = 'open'",
            (cutoff,),
        ).fetchone()["c"]

        return {
            "total_events": total,
            "by_type": {r["event_type"]: r["c"] for r in by_type},
            "by_severity": {r["severity"]: r["c"] for r in by_severity},
            "open_alerts": alerts_count,
        }


def store_incident_report(report: dict) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO incident_reports
               (timestamp, title, summary, attack_type, affected_systems, severity, recommendations)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                report.get("timestamp", datetime.now().isoformat()),
                report.get("title", ""),
                report.get("summary", ""),
                report.get("attack_type", ""),
                report.get("affected_systems", ""),
                report.get("severity", ""),
                report.get("recommendations", ""),
            ),
        )
        return cur.lastrowid


def get_incident_reports(limit: int = 20) -> list:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM incident_reports ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
