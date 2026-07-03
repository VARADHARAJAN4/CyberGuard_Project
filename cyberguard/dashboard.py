"""
Streamlit Dashboard for CyberGuard AI Agent.
Provides visual security monitoring, alert management, and AI analysis.
"""
import sys
import os

# Ensure project root is on path for module imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Optional

from cyberguard.database import (
    get_recent_events, get_open_alerts, get_top_attackers,
    get_department_risk, get_event_stats, get_events_by_type,
    get_incident_reports, init_db,
)
from cyberguard.agent import CyberGuardAgent
from cyberguard.anomaly_detector import AnomalyDetector
from cyberguard.config import STREAMLIT_TITLE, STREAMLIT_ICON, DB_PATH


def init_session_state():
    """Initialize Streamlit session state."""
    if "agent" not in st.session_state:
        st.session_state.agent = CyberGuardAgent()
    if "detector" not in st.session_state:
        st.session_state.detector = AnomalyDetector()
    if "initialized" not in st.session_state:
        st.session_state.initialized = False


@st.cache_data(ttl=30)
def load_stats(hours: int = 24) -> dict:
    return get_event_stats(hours=hours)


@st.cache_data(ttl=30)
def load_alerts(hours: int = 48) -> list:
    return get_open_alerts(hours=hours)


@st.cache_data(ttl=30)
def load_attackers(limit: int = 10) -> list:
    return get_top_attackers(limit=limit)


@st.cache_data(ttl=30)
def load_dept_risk() -> list:
    return get_department_risk()


@st.cache_data(ttl=30)
def load_recent_events(limit: int = 100) -> list:
    return get_recent_events(limit=limit)


def render_sidebar():
    """Render the sidebar with navigation and quick stats."""
    with st.sidebar:
        st.markdown("## 🛡️ CyberGuard")
        st.markdown("### Navigation")
        page = st.radio(
            "Go to",
            ["📊 Dashboard Overview", "🔍 Event Analysis", "🚨 Alerts",
             "🤖 AI Agent Chat", "📋 Incident Reports", "⚙️ Settings"],
            label_visibility="collapsed",
        )
        st.divider()

        stats = load_stats()
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Events", stats["total_events"])
        with col2:
            st.metric("Open Alerts", stats["open_alerts"])

        severity = stats.get("by_severity", {})
        if severity:
            st.markdown("### Event Severity")
            for sev, count in sorted(severity.items()):
                color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                st.markdown(f"{color.get(sev, '⚪')} **{sev.title()}**: {count}")

    return page


def render_dashboard():
    """Main dashboard overview page."""
    st.header("📊 Security Dashboard")
    stats = load_stats()
    alerts = load_alerts()
    attackers = load_attackers(5)

    # Top-level KPIs
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Events (24h)", stats["total_events"])
    with col2:
        st.metric("Open Alerts", stats["open_alerts"],
                  delta=len(alerts) - 10 if alerts else 0)
    with col3:
        critical = stats.get("by_severity", {}).get("critical", 0)
        st.metric("Critical Events", critical, delta_color="inverse")
    with col4:
        if len(alerts) > 20:
            threat_level = "🔴 CRITICAL"
        elif len(alerts) > 10:
            threat_level = "🟠 HIGH"
        elif len(alerts) > 3:
            threat_level = "🟡 MEDIUM"
        else:
            threat_level = "🟢 LOW"
        st.metric("Threat Level", threat_level)

    st.divider()

    # Charts row
    col1, col2 = st.columns(2)

    with col1:
        event_breakdown = stats.get("by_type", {})
        if event_breakdown:
            df = pd.DataFrame([
                {"Event Type": k.replace("_", " ").title(), "Count": v}
                for k, v in sorted(event_breakdown.items(), key=lambda x: x[1], reverse=True)
            ])
            fig = px.bar(
                df.head(10), x="Event Type", y="Count",
                title="Events by Type (24h)",
                color="Count", color_continuous_scale="RdYlGn_r",
            )
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        dept_risk = load_dept_risk()
        if dept_risk:
            df = pd.DataFrame(dept_risk)
            fig = px.pie(
                df, values="event_count", names="department",
                title="Events by Department",
                hole=0.4,
            )
            st.plotly_chart(fig, use_container_width=True)

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🎯 Top Attackers")
        if attackers:
            df = pd.DataFrame(attackers)
            fig = px.bar(
                df, x="source_ip", y="count",
                title="Most Active Attacker IPs",
                color="critical_count",
                color_continuous_scale="Reds",
                labels={"source_ip": "IP Address", "count": "Events"},
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attackers identified.")

    with col2:
        st.subheader("🚨 Recent Alerts")
        if alerts:
            for a in alerts[:5]:
                color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                st.markdown(
                    f"{color.get(a['risk_level'], '⚪')} "
                    f"**{a['alert_type'].replace('_', ' ').title()}** "
                    f"(Risk: {a['risk_score']:.2f})"
                )
                st.caption(a["description"][:120] + "...")
                st.divider()
        else:
            st.success("No open alerts! ✓")

    st.divider()
    st.subheader("⏱️ Recent Events Timeline")
    events = load_recent_events(50)
    if events:
        df = pd.DataFrame(events)
        df["ts"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("ts")
        severity_colors = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green"}

        fig = go.Figure()
        for sev in ["critical", "high", "medium", "low"]:
            subset = df[df["severity"] == sev]
            if not subset.empty:
                fig.add_trace(go.Scatter(
                    x=subset["ts"], y=[sev] * len(subset),
                    mode="markers",
                    name=sev.title(),
                    marker=dict(size=10, color=severity_colors[sev]),
                ))
        fig.update_layout(
            title="Security Events Timeline",
            xaxis_title="Time",
            yaxis_title="Severity",
            height=300,
        )
        st.plotly_chart(fig, use_container_width=True)


def render_event_analysis():
    """Event analysis page with ML anomaly detection."""
    st.header("🔍 Event Analysis")

    agent: CyberGuardAgent = st.session_state.agent

    if st.button("🧠 Train ML Anomaly Detector"):
        with st.spinner("Training on historical events..."):
            agent.fit_detector()
            st.session_state.initialized = True
        st.success("Model trained!")

    hours = st.slider("Analysis period (hours)", 1, 168, 24, 1)

    if st.button("🔍 Run Analysis", type="primary"):
        with st.spinner("Analyzing events..."):
            analysis = agent.analyze_recent_events(hours=hours)

        st.subheader("📋 Security Assessment")
        st.info(analysis["summary"])

        if analysis["findings"]:
            st.subheader("⚠️ Findings")
            for f in analysis["findings"]:
                st.warning(f)

        if analysis.get("event_breakdown"):
            st.subheader("📊 Event Breakdown")
            df = pd.DataFrame([
                {"Event Type": k.replace("_", " ").title(), "Count": v}
                for k, v in analysis["event_breakdown"].items()
            ])
            st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("🔬 Single Event Analysis")

    events = get_recent_events(limit=20)
    if events:
        event_options = {
            f"{e['timestamp'][:19]} | {e['event_type']} | {e.get('username', 'N/A')}": e
            for e in events
        }
        selected_label = st.selectbox("Select an event to analyze", list(event_options.keys()))
        selected_event = event_options[selected_label]

        if selected_event and st.button("🤖 Analyze Event"):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Event Details**")
                st.json(selected_event)

            with col2:
                st.markdown("**AI Analysis**")
                explanation = agent.analyze_event(selected_event)
                st.markdown(explanation)

                prediction = agent.predict_attack(selected_event)
                pred_color = "red" if prediction["prediction"] == "ATTACK" else "green"
                st.markdown(
                    f"**ML Prediction:** :{pred_color}[{prediction['prediction']}]  \n"
                    f"**Confidence:** {prediction['confidence']:.2%}  \n"
                    f"**Risk Score:** {prediction['risk_score']:.2f}  \n"
                    f"**Risk Level:** {prediction['risk_level'].upper()}"
                )

                if prediction["prediction"] == "ATTACK":
                    st.error("⚠️ This event appears to be malicious!")
                else:
                    st.success("✅ This event appears normal.")


def render_alerts():
    """Alerts management page."""
    st.header("🚨 Security Alerts")

    agent: CyberGuardAgent = st.session_state.agent
    alerts = load_alerts()

    if not alerts:
        st.success("🎉 No open alerts! Your security posture looks good.")
        return

    st.markdown(f"**{len(alerts)}** open alerts requiring attention.")

    col1, col2 = st.columns(2)
    with col1:
        risk_filter = st.selectbox(
            "Minimum risk level",
            ["all", "critical", "high", "medium", "low"],
        )
    with col2:
        type_filter = st.multiselect(
            "Alert types",
            options=list(set(a["alert_type"] for a in alerts)),
            default=[],
        )

    filtered = alerts
    if risk_filter != "all":
        levels = {"critical": 0.8, "high": 0.6, "medium": 0.3, "low": 0.0}
        min_score = levels[risk_filter]
        filtered = [a for a in filtered if a["risk_score"] >= min_score]
    if type_filter:
        filtered = [a for a in filtered if a["alert_type"] in type_filter]

    for alert in filtered:
        color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        with st.expander(
            f"{color.get(alert['risk_level'], '⚪')} "
            f"[{alert['risk_level'].upper()}] "
            f"{alert['alert_type'].replace('_', ' ').title()} "
            f"(Risk: {alert['risk_score']:.2f})",
            expanded=alert["risk_level"] in ("critical", "high"),
        ):
            st.markdown(f"**Description:** {alert['description']}")
            st.markdown(f"**Time:** {alert['timestamp']}")
            st.markdown(f"**Risk Score:** {alert['risk_score']:.2f}")

            st.markdown("**Recommended Actions:**")
            recs = agent.recommend_actions(alert)
            for r in recs:
                st.markdown(f"- {r}")


def render_ai_chat():
    """AI Agent chat interface."""
    st.header("🤖 AI Agent Chat")
    st.markdown("Ask the CyberGuard AI Agent about your security posture.")

    agent: CyberGuardAgent = st.session_state.agent

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    quick_questions = [
        "What attacks happened today?",
        "Which IP address is most suspicious?",
        "Which department has the highest cyber risk?",
        "How many malware events occurred?",
        "Predict tomorrow's cyber risk.",
        "Which systems need immediate patching?",
        "Generate a security incident report.",
    ]

    if prompt := st.chat_input("Ask a security question..."):
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Analyzing..."):
                response = agent.answer_query(prompt)
            st.markdown(response)

        st.session_state.chat_history.append({"role": "assistant", "content": response})

    cols = st.columns(4)
    for i, q in enumerate(quick_questions):
        with cols[i % 4]:
            label = q[:18] + "..." if len(q) > 18 else q
            if st.button(label, key=f"qq_{i}", use_container_width=True):
                st.session_state.chat_history.append({"role": "user", "content": q})
                with st.chat_message("user"):
                    st.markdown(q)
                with st.chat_message("assistant"):
                    with st.spinner("Analyzing..."):
                        response = agent.answer_query(q)
                    st.markdown(response)
                st.session_state.chat_history.append({"role": "assistant", "content": response})
                st.rerun()

    if st.session_state.chat_history and st.button("🗑️ Clear Chat"):
        st.session_state.chat_history = []
        st.rerun()


def render_reports():
    """Incident reports page."""
    st.header("📋 Incident Reports")
    reports = get_incident_reports()

    if not reports:
        st.info("No incident reports generated yet. Go to the AI Agent chat and ask to generate one.")
        return

    for report in reports:
        with st.expander(
            f"📄 {report['title']} — {report['timestamp'][:19]} [{report['severity']}]"
        ):
            st.markdown(f"**Summary:** {report['summary']}")
            st.markdown(f"**Attack Type:** {report['attack_type']}")
            st.markdown(f"**Affected Systems:** {report['affected_systems']}")
            st.markdown(f"**Severity:** {report['severity']}")
            st.markdown("**Full Report:**")
            st.text(report["recommendations"])


def render_settings():
    """Settings page."""
    st.header("⚙️ Settings")

    st.subheader("Database")
    st.markdown(f"**Database location:** `{DB_PATH}`")
    if st.button("🗑️ Reset Database", type="secondary"):
        if DB_PATH.exists():
            DB_PATH.unlink()
            st.success("Database deleted. Restart to recreate.")
            st.rerun()

    st.divider()
    st.subheader("Sample Data")
    st.markdown("Generate sample security events to populate the database.")
    col1, col2 = st.columns(2)
    with col1:
        days = st.number_input("Days of data", min_value=1, max_value=30, value=3)
    with col2:
        events_per_hour = st.number_input("Events per hour", min_value=10, max_value=500, value=50)

    if st.button("📥 Generate Sample Data", type="primary"):
        from cyberguard.data_generator import seed_database
        with st.spinner(f"Generating {days * 24 * events_per_hour} events..."):
            seed_database(days=days, events_per_hour=events_per_hour)
        st.success("Sample data generated!")
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.subheader("ML Model")
    if st.button("🧠 Train Anomaly Detection Model"):
        agent: CyberGuardAgent = st.session_state.agent
        with st.spinner("Training on historical data..."):
            agent.fit_detector()
        st.success("Model trained!")
        st.session_state.initialized = True


def run():
    """Main entry point for the Streamlit dashboard."""
    st.set_page_config(
        page_title=STREAMLIT_TITLE,
        page_icon=STREAMLIT_ICON,
        layout="wide",
        initial_sidebar_state="expanded",
    )

    init_db()
    init_session_state()

    page = render_sidebar()

    if page == "📊 Dashboard Overview":
        render_dashboard()
    elif page == "🔍 Event Analysis":
        render_event_analysis()
    elif page == "🚨 Alerts":
        render_alerts()
    elif page == "🤖 AI Agent Chat":
        render_ai_chat()

    elif page == "📋 Incident Reports":
        render_reports()
    elif page == "⚙️ Settings":
        render_settings()


if __name__ == "__main__":
    run()
