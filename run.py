#!/usr/bin/env python3
"""
CyberGuard AI Agent - Entry Point
Cybersecurity Monitoring, Anomaly Detection, and AI Analysis Dashboard.

Usage:
    python run.py            # Start the interactive CLI agent
    python run.py --seed     # Generate sample data and start CLI
    python run.py --dashboard  # Launch the Streamlit web dashboard
    python run.py --seed-only # Only generate sample data, then exit
"""
import sys
import argparse
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ CyberGuard AI Agent - Cybersecurity Monitoring Platform"
    )
    parser.add_argument(
        "--seed", action="store_true",
        help="Generate sample security events before starting"
    )
    parser.add_argument(
        "--dashboard", action="store_true",
        help="Launch the Streamlit web dashboard"
    )
    parser.add_argument(
        "--seed-only", action="store_true",
        help="Only generate sample data, then exit"
    )
    parser.add_argument(
        "--cli", action="store_true",
        help="Run in interactive CLI mode"
    )
    args = parser.parse_args()

    # Initialize database
    from cyberguard.database import init_db
    init_db()

    # Seed data if requested
    if args.seed or args.seed_only or args.dashboard:
        print("📥 Generating sample security events...")
        from cyberguard.data_generator import seed_database
        events = seed_database(days=3, events_per_hour=50)
        print(f"✅ Generated {len(events)} security events with realistic attack patterns.")
        if args.seed_only:
            print("Done. Exiting.")
            return

    # Launch dashboard
    if args.dashboard:
        print("🚀 Launching CyberGuard Dashboard at http://localhost:8501")
        import subprocess
        import sys as _sys
        subprocess.run([
            _sys.executable, "-m", "streamlit", "run",
            "cyberguard/dashboard.py",
            "--server.port=8501",
            "--server.headless=true",
        ])
        return

    # CLI mode or interactive
    print("""
╔═══════════════════════════════════════════════╗
║         🛡️  CYBERGUARD AI AGENT               ║
║   Cybersecurity Monitoring & Analysis System  ║
╚═══════════════════════════════════════════════╝
    """)

    from cyberguard.agent import CyberGuardAgent
    agent = CyberGuardAgent()

    # Train ML model
    print("🧠 Training ML anomaly detector...")
    agent.fit_detector()
    print("✅ Model ready.\n")

    # Run initial analysis
    analysis = agent.analyze_recent_events()
    print(analysis["summary"])
    print()

    if args.cli:
        # Interactive CLI loop
        print("Enter a security question or command (type 'help' for options, 'quit' to exit):")
        while True:
            try:
                query = input("\n🤖 You: ").strip()
                if query.lower() in ("quit", "exit", "q"):
                    print("👋 Goodbye!")
                    break
                elif query.lower() == "help":
                    print("""
Available questions:
  • What attacks happened today?
  • Which IP address is most suspicious?
  • Which department has the highest cyber risk?
  • How many malware events occurred?
  • Predict tomorrow's cyber risk.
  • Which systems need immediate patching?
  • Generate a security incident report.
  • help    - Show this help
  • quit    - Exit the program
                    """)
                    continue
                elif query.lower() == "report":
                    print("\n" + agent.generate_incident_report())
                    continue

                response = agent.answer_query(query)
                print(f"\n🤖 Agent: {response}")

            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except EOFError:
                print("\n👋 Goodbye!")
                break
    else:
        # Show summary and recommendations
        print("📊 Recent Security Assessment:")
        for finding in analysis["findings"]:
            print(f"  {finding}")
        print()

        if analysis["open_alerts"] > 0:
            print(f"🚨 {analysis['open_alerts']} open alerts require attention.")
            from cyberguard.database import get_open_alerts
            alerts = get_open_alerts()
            for alert in alerts[:3]:
                recs = agent.recommend_actions(alert)
                print(f"\n  [{alert['risk_level'].upper()}] {alert['alert_type']}")
                print(f"    → {recs[0]}")

        print("\n💡 Run 'python run.py --cli' for interactive mode or 'python run.py --dashboard' for web UI.")


if __name__ == "__main__":
    main()
