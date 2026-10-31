"""Scoring Engine - Educational classification based on detected structural indicators."""

from typing import List
from .models import Finding, Classification


class ScoringEngine:
    """Translates indicator counts into educational awareness classifications.
    
    IMPORTANT: This is not an automated machine-learning classifier or definitive safety test.
    It highlights heuristic structural indicators to assist human review.
    """

    @classmethod
    def calculate_score(cls, findings: List[Finding]) -> tuple[int, Classification]:
        detected_count = sum(1 for f in findings if f.detected)

        if detected_count == 0:
            classification = Classification.NO_WARNING_SIGNS
        elif 1 <= detected_count <= 2:
            classification = Classification.REVIEW
        else:
            classification = Classification.ELEVATED_REVIEW

        return detected_count, classification

    @classmethod
    def get_educational_summary(cls, classification: Classification) -> str:
        if classification == Classification.NO_WARNING_SIGNS:
            return (
                "No listed structural warning signs were flagged by the 6 workbook checks. "
                "CRITICAL: This does not guarantee that the destination is safe or authentic. "
                "Sophisticated phishing attacks frequently use clean-looking, HTTPS-enabled domains."
            )
        elif classification == Classification.REVIEW:
            return (
                "One or two structural indicators were detected. The link warrants closer review "
                "before interacting or providing any personal details."
            )
        else:
            return (
                "Three or more structural indicators were detected. The URL exhibits multiple "
                "anomalies commonly associated with deceptive link structures. Exercise extreme caution."
            )

    @classmethod
    def get_safe_next_steps(cls, classification: Classification) -> List[str]:
        steps = [
            "Never enter credentials or sensitive information on unverified sites.",
            "Inspect the true domain by searching for the official institution via a trusted search engine or bookmarks.",
            "If in doubt, contact the alleged sender through an independent, verified communication channel."
        ]
        if classification == Classification.ELEVATED_REVIEW:
            steps.insert(0, "Avoid clicking or opening this link in a standard browser session.")
        return steps

