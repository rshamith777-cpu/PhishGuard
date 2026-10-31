"""Audit Log System - Privacy-preserving local analysis logging."""

import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from .models import AnalysisResult

AUDIT_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "audit_history.json")


class AuditManager:
    """Manages sanitized local audit logs without storing credentials or sensitive query strings."""

    @classmethod
    def record(cls, result: AnalysisResult) -> None:
        """Appends a privacy-preserving summary of the analysis."""
        entry = {
            "analysis_id": result.analysis_id,
            "timestamp": result.timestamp,
            "sanitized_url": result.sanitized_url,
            "indicator_count": result.indicator_count,
            "classification": result.classification.value,
            "detected_checks": [f.check_id for f in result.findings if f.detected]
        }

        history = cls.get_history()
        history.insert(0, entry)
        # Keep maximum last 100 entries locally
        history = history[:100]

        os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)
        try:
            with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass  # Avoid halting operation if local file write is restricted

    @classmethod
    def get_history(cls) -> List[Dict[str, Any]]:
        if not os.path.exists(AUDIT_LOG_FILE):
            return []
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    @classmethod
    def clear_history(cls) -> bool:
        if os.path.exists(AUDIT_LOG_FILE):
            try:
                os.remove(AUDIT_LOG_FILE)
                return True
            except Exception:
                return False
        return True

