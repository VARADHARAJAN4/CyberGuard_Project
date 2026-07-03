"""
Configuration module for CyberGuard AI Agent.
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
DB_PATH = DATA_DIR / "cyberguard.db"
SAMPLES_DIR = DATA_DIR / "samples"

# Ensure directories exist
for d in [DATA_DIR, LOGS_DIR, SAMPLES_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ML Model settings
MODEL_PATH = DATA_DIR / "models"
ANOMALY_CONTAMINATION = 0.05
RANDOM_STATE = 42

# Streamlit settings
STREAMLIT_TITLE = "🛡️ CyberGuard AI Agent"
STREAMLIT_ICON = "🛡️"
PAGE_REFRESH_SECONDS = 30

# Alert thresholds
CRITICAL_THRESHOLD = 0.9
HIGH_THRESHOLD = 0.7
MEDIUM_THRESHOLD = 0.4
