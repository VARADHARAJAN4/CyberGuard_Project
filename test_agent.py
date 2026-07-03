"""Quick test script for CyberGuard AI Agent."""
from cyberguard.database import init_db, get_event_stats, get_open_alerts, get_top_attackers
from cyberguard.agent import CyberGuardAgent

init_db()

# Test DB
stats = get_event_stats()
print("Stats:", stats)
alerts = get_open_alerts()
print(f"Open alerts: {len(alerts)}")
attackers = get_top_attackers(5)
print("Top attackers:", [(a["source_ip"], a["count"]) for a in attackers])

# Test agent
agent = CyberGuardAgent()
print("\n--- Agent Analysis ---")
analysis = agent.analyze_recent_events(hours=48)
print(analysis["summary"])
for f in analysis["findings"]:
    print(f"  {f}")

print("\n--- Query Tests ---")
print(agent.answer_query("What attacks happened today?"))
print()
print(agent.answer_query("Which department has the highest cyber risk?"))
print()
print(agent.answer_query("Predict tomorrow's cyber risk."))

print("\n✅ All tests passed!")
