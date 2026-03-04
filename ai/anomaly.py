"""
Anomaly Detection Module
========================
Uses a streaming IsolationForest model trained on access-log features to flag
unusual record-access patterns in real time.

Features extracted per access event:
  - Hour of day          (0–23)
  - Day of week          (0=Monday … 6=Sunday)
  - User role encoded    (admin=0, doctor=1, nurse=2)
  - Access type encoded  (view=0, edit=1, decrypt=2, bulk_export=3)
  - Records accessed in the past hour by this user
  - Records accessed in the past 24 hours by this user
  - Unique patients accessed today by this user
  - Is outside normal working hours? (bool → 0/1)

The detector maintains a lightweight in-memory model that is (re-)fitted
whenever enough new log entries accumulate.  In production this would be
backed by a scheduled job; here it runs on-demand.
"""

import json
import math
from datetime import datetime, timedelta
from typing import List, Optional

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NORMAL_HOURS_START = 6    # 06:00
NORMAL_HOURS_END   = 22   # 22:00

ROLE_MAP   = {"admin": 0, "doctor": 1, "nurse": 2, "analyst": 3}
ACTION_MAP = {"view": 0, "edit": 1, "decrypt": 2, "export": 3, "login": 4, "delete": 5}

CONTAMINATION  = 0.05   # Expected fraction of anomalies
MIN_FIT_SAMPLES = 30    # Need at least this many logs before the model is useful


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(log_entry, all_logs: list) -> List[float]:
    """
    Convert a single AccessLog ORM object + surrounding history into a
    feature vector.

    Parameters
    ----------
    log_entry : AccessLog ORM instance (must have .user_id, .action,
                .timestamp, .user relationship with .role)
    all_logs  : list of all AccessLog ORM instances (for history context)
    """
    ts:   datetime = log_entry.timestamp
    uid:  int      = log_entry.user_id
    role: str      = getattr(log_entry, 'user_role', 'nurse')
    action: str    = log_entry.action

    recent_1h  = [l for l in all_logs
                  if l.user_id == uid and (ts - l.timestamp) <= timedelta(hours=1)]
    recent_24h = [l for l in all_logs
                  if l.user_id == uid and (ts - l.timestamp) <= timedelta(hours=24)]
    unique_today = len({l.patient_id for l in recent_24h if l.patient_id is not None})

    outside_hours = int(not (NORMAL_HOURS_START <= ts.hour < NORMAL_HOURS_END))

    return [
        float(ts.hour),
        float(ts.weekday()),
        float(ROLE_MAP.get(role, 2)),
        float(ACTION_MAP.get(action, 0)),
        float(len(recent_1h)),
        float(len(recent_24h)),
        float(unique_today),
        float(outside_hours),
    ]


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Wraps an IsolationForest tuned for hospital access-log anomalies.

    Usage:
        detector = AnomalyDetector()
        detector.fit(all_logs)
        result = detector.score_log(log_entry, all_logs)
    """

    def __init__(self):
        self._model: Optional[object] = None
        self._fitted = False

    def fit(self, logs: list) -> bool:
        """
        Fit the model on a list of AccessLog ORM objects.
        Returns True if the model was actually fitted (enough data).
        """
        if not _SKLEARN_AVAILABLE:
            return False
        if len(logs) < MIN_FIT_SAMPLES:
            return False

        X = np.array([extract_features(l, logs) for l in logs])
        self._model = IsolationForest(
            n_estimators    = 100,
            contamination   = CONTAMINATION,
            random_state    = 42,
        )
        self._model.fit(X)
        self._fitted = True
        return True

    def score_log(self, log_entry, all_logs: list) -> dict:
        """
        Score a single access log entry.

        Returns a dict:
          {
            "is_anomaly":  bool,
            "score":       float,    # −1 = very anomalous … 0 = borderline … 1 = normal
            "reason":      str,      # human-readable explanation
            "confidence":  float,    # 0–1
          }
        """
        features = extract_features(log_entry, all_logs)
        result = {
            "is_anomaly": False,
            "score":      0.5,
            "reason":     "Insufficient data for anomaly model",
            "confidence": 0.0,
        }

        # ── Heuristic rules (always run, no ML needed) ──────────────────
        flags = []
        hour       = int(features[0])
        records_1h = int(features[4])
        records_24h = int(features[5])
        outside    = bool(features[7])
        action_code = int(features[3])

        if outside:
            flags.append(f"Access at {hour:02d}:xx (outside normal hours)")
        if records_1h > 30:
            flags.append(f"High per-hour access rate: {records_1h} records")
        if records_24h > 200:
            flags.append(f"Very high daily access rate: {records_24h} records")
        if action_code in (3, 5):  # export or delete
            flags.append(f"Sensitive action: {log_entry.action}")

        if flags:
            result["is_anomaly"] = True
            result["reason"]     = "; ".join(flags)
            result["confidence"] = min(0.9, 0.4 + 0.15 * len(flags))

        # ── ML model scoring ─────────────────────────────────────────────
        if _SKLEARN_AVAILABLE and self._fitted and self._model is not None:
            X = np.array([features])
            raw_score   = float(self._model.score_samples(X)[0])
            prediction  = int(self._model.predict(X)[0])   # -1=anomaly, 1=normal
            is_anomaly  = (prediction == -1)
            # score_samples returns negative; map to [0,1]
            normalized  = 1.0 / (1.0 + math.exp(-raw_score * 5))

            result["score"]     = raw_score
            result["confidence"] = max(result["confidence"], abs(normalized - 0.5) * 2)
            if is_anomaly and not result["is_anomaly"]:
                result["is_anomaly"] = True
                result["reason"]     = (result["reason"] + "; ML model flagged anomaly").lstrip("; ")

        return result

    def score_all(self, logs: list) -> List[dict]:
        """Score every log entry.  Fits if not already fitted."""
        if not self._fitted:
            self.fit(logs)
        return [self.score_log(l, logs) for l in logs]


# Module-level singleton so the model persists across requests within a process
_detector_instance = AnomalyDetector()


def get_detector() -> AnomalyDetector:
    return _detector_instance
