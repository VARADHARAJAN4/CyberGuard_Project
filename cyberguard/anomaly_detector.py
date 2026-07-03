"""
Anomaly Detection Engine for CyberGuard AI Agent.
Uses Isolation Forest, LOF, and rule-based heuristics.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import LabelEncoder, StandardScaler
from typing import List, Optional
from .config import ANOMALY_CONTAMINATION, RANDOM_STATE


class AnomalyDetector:
    """Multi-model anomaly detection engine."""

    def __init__(self, contamination: float = ANOMALY_CONTAMINATION):
        self.contamination = contamination
        self.isolation_forest: Optional[IsolationForest] = None
        self.lof: Optional[LocalOutlierFactor] = None
        self.scaler = StandardScaler()
        self.label_encoders: dict = {}
        self._fitted = False

    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert raw event data into numerical feature vectors."""
        features = df.copy()

        # Encode categorical columns
        cat_cols = ["source", "event_type", "severity", "protocol", "status", "department"]
        for col in cat_cols:
            if col in features.columns:
                le = LabelEncoder()
                features[f"{col}_encoded"] = le.fit_transform(features[col].fillna("unknown"))
                self.label_encoders[col] = le

        # Time-based features
        if "timestamp" in features.columns:
            features["ts"] = pd.to_datetime(features["timestamp"])
            features["hour"] = features["ts"].dt.hour
            features["day_of_week"] = features["ts"].dt.dayofweek
            features["is_business_hours"] = features["hour"].between(8, 18).astype(int)
            features["is_weekend"] = (features["day_of_week"] >= 5).astype(int)

        # Port features
        if "port" in features.columns:
            features["is_suspicious_port"] = features["port"].isin(
                [22, 23, 3389, 445, 135, 139, 1433, 3306, 5900]
            ).astype(int)

        # Select numeric columns for model input
        numeric_cols = [
            "hour", "day_of_week", "is_business_hours", "is_weekend",
            "is_suspicious_port",
        ]
        for col in cat_cols:
            ec = f"{col}_encoded"
            if ec in features.columns:
                numeric_cols.append(ec)

        available = [c for c in numeric_cols if c in features.columns]
        return features[available].fillna(0)

    def fit(self, events: List[dict]) -> "AnomalyDetector":
        """Fit anomaly detection models on historical events."""
        df = pd.DataFrame(events)
        if df.empty:
            return self

        X = self._extract_features(df)
        if X.shape[0] < 10:
            return self

        X_scaled = self.scaler.fit_transform(X)

        # Isolation Forest
        self.isolation_forest = IsolationForest(
            contamination=self.contamination,
            random_state=RANDOM_STATE,
            n_estimators=100,
        )
        self.isolation_forest.fit(X_scaled)

        # Local Outlier Factor (novelty detection mode requires fitting)
        self.lof = LocalOutlierFactor(
            contamination=self.contamination,
            novelty=True,
            n_neighbors=min(20, max(2, X.shape[0] // 10)),
        )
        self.lof.fit(X_scaled)

        self._fitted = True
        return self

    def predict(self, event: dict) -> dict:
        """Predict anomaly score for a single event."""
        df = pd.DataFrame([event])
        X = self._extract_features(df)

        if X.empty or not self._fitted:
            return {"is_anomaly": False, "anomaly_score": 0.0}

        # Pad missing columns with 0
        missing_cols = set(self.scaler.feature_names_in_) - set(X.columns)
        for col in missing_cols:
            X[col] = 0

        X = X[list(self.scaler.feature_names_in_)]
        X_scaled = self.scaler.transform(X)

        results = {}

        if self.isolation_forest:
            if_score = self.isolation_forest.decision_function(X_scaled)[0]
            # Normalize to [0, 1] where 1 = most anomalous
            if_norm = 1 - (if_score + 0.5)  # decision_function range ~ [-0.5, 0.5]
            results["if_anomaly_score"] = float(np.clip(if_norm, 0, 1))

        if self.lof:
            lof_score = self.lof.decision_function(X_scaled)[0]
            lof_norm = 1 - (lof_score + 0.5)
            results["lof_anomaly_score"] = float(np.clip(lof_norm, 0, 1))

        # Combined score
        scores = [v for v in results.values() if isinstance(v, (int, float))]
        combined = float(np.mean(scores)) if scores else 0.0

        return {
            "is_anomaly": combined > 0.5,
            "anomaly_score": combined,
            "details": results,
        }

    def predict_batch(self, events: List[dict]) -> List[dict]:
        """Predict anomalies for multiple events."""
        return [self.predict(e) for e in events]


# Rule-based risk scoring (used when ML models aren't fitted)
def compute_risk_score(event: dict) -> float:
    """
    Compute a heuristic risk score for an event (0.0 - 1.0).
    Used for immediate alert generation independently of ML models.
    """
    score = 0.0
    severity = event.get("severity", "low")
    event_type = event.get("event_type", "")
    status = event.get("status", "normal")

    # Baseline from severity
    severity_map = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 0.9}
    score += severity_map.get(severity, 0.1)

    # Boost for known attack patterns
    attack_types = {
        "failed_login": 0.3, "port_scan": 0.3, "malware_detected": 0.4,
        "data_exfiltration": 0.5, "phishing_email": 0.3, "privilege_escalation": 0.4,
    }
    score += attack_types.get(event_type, 0.0)

    # Boost if explicitly marked as attack
    if status == "attack":
        score += 0.2

    # Suspicious ports
    suspicious_ports = [22, 23, 3389, 445, 135, 139, 1433, 3306, 5900]
    if event.get("port") in suspicious_ports:
        score += 0.1

    return min(score, 1.0)


def classify_risk_level(score: float) -> str:
    if score >= 0.8:
        return "critical"
    elif score >= 0.6:
        return "high"
    elif score >= 0.3:
        return "medium"
    return "low"
