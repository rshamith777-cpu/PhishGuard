"""PhishGuard - Data Models for URL Analysis and Educational Indicators."""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from enum import Enum


class Classification(str, Enum):
    NO_WARNING_SIGNS = "NO LISTED WARNING SIGNS"
    REVIEW = "REVIEW"
    ELEVATED_REVIEW = "ELEVATED REVIEW"


@dataclass
class Finding:
    """Represents an individual structural heuristic finding."""
    check_id: str
    name: str
    detected: bool
    why_it_matters: str
    limitations: str
    agent_name: str
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParsedURL:
    """Represents a validated and parsed URL representation."""
    raw_url: str
    scheme: str
    netloc: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    length: int
    is_valid: bool
    error_message: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete analysis output for a single URL inspection."""
    analysis_id: str
    timestamp: str
    url: str
    sanitized_url: str
    indicator_count: int
    classification: Classification
    findings: List[Finding] = field(default_factory=list)
    safe_next_steps: List[str] = field(default_factory=list)
    limitations: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["classification"] = self.classification.value
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


@dataclass
class BatchAnalysisSummary:
    """Summary of multiple URL analyses."""
    total_inputs: int
    successful_count: int
    with_indicators_count: int
    results: List[AnalysisResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_inputs": self.total_inputs,
            "successful_count": self.successful_count,
            "with_indicators_count": self.with_indicators_count,
            "results": [r.to_dict() for r in self.results]
        }

