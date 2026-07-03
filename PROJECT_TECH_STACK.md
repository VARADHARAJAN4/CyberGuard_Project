# CyberGuard — Concepts & Technologies Used

## Core Concepts
- **Cybersecurity Monitoring (SOC Assist)**: continuous processing of security telemetry to surface high-risk events.
- **Alert Fatigue Reduction**: prioritization using a **Threat Score / Risk Level** so analysts focus on the most important alerts.
- **Explainable AI (Human-readable outputs)**:
  - Deterministic, plain-language summaries.
  - Actionable recommendations mapped to alert/event types.
- **Anomaly Detection (Unsupervised)**:
  - Identify unusual behavior patterns without labeled ground truth.
- **Feature Engineering for Logs**:
  - Convert heterogeneous log fields into numeric vectors.
  - Include time-of-day and “suspicious port” indicators.
- **Rule-based Reasoning + ML Scoring**:
  - Heuristic risk scoring works even before ML training.
  - Optional IsolationForest/LOF adds an additional anomalousness signal.
- **Retrieval/Question Answering style interface (Agent Q&A)**:
  - The “chat” uses structured business logic over stored metrics (snapshot answers).
- **Incident Reporting Automation**:
  - Consolidate findings + top alerts into a report and persist it.

## Technologies / Libraries
- **Python 3**: main implementation language.

### Data / Analytics
- **pandas**: tabular transformations for visualization and analysis.
- **NumPy**: numerical operations.

### Machine Learning
- **scikit-learn**:
  - `IsolationForest` (unsupervised anomaly detection)
  - `LocalOutlierFactor` (novelty mode)
  - `StandardScaler` for feature scaling
  - `LabelEncoder` for categorical encoding

### Storage
- **SQLite**:
  - Stores normalized security events (`security_events`).
  - Stores derived prioritized alerts (`alerts`).
  - Stores generated incident reports (`incident_reports`).

### AI Agent / Reasoning Style
- **LangChain/LangGraph are listed in the requirements**, but this repo’s current working version implements reasoning deterministically (rule templates + ML score + risk classification). The architecture is compatible with adding LLM-based reasoning later.

### Visualization / Dashboard
- **Streamlit**: multi-page dashboard, interactive filters, and chat UI.
- **Plotly**:
  - Bar charts / pie charts / timeline scatter overlays.

## Project Modules (Mapping to Concepts)
- `cyberguard/data_generator.py`
  - **Concept**: synthetic security telemetry for training/demo.
- `cyberguard/database.py`
  - **Concept**: event persistence + alert/report storage.
- `cyberguard/anomaly_detector.py`
  - **Concept**: feature engineering + IsolationForest/LOF + heuristic risk scoring.
- `cyberguard/agent.py`
  - **Concept**: reasoning, scoring integration, explanations, recommendations, report generation.
- `cyberguard/dashboard.py`
  - **Concept**: SOC-style UI, alert triage, monitoring KPIs, Q&A, and report viewing.
- `run.py`
  - **Concept**: CLI + dashboard launcher + optional seeding.

## Output Artifacts
- `PROJECT_WORKING_PRINCIPLE.md`
- `LINKEDIN_POST.md`
- `PROJECT_TECH_STACK.md`


