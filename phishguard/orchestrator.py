"""Orchestrator - Coordinates agents, executes checks, and formats analysis results."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from .models import AnalysisResult, BatchAnalysisSummary, Finding, Classification, ParsedURL
from .agents import ValidationAgent, StructureAgent, HostnameAgent, ProtocolAgent
from .scoring import ScoringEngine


class AnalysisOrchestrator:
    """Central coordinator executing deterministic multi-agent URL inspection."""

    @classmethod
    def analyze_url(cls, raw_url: str) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Step 1: Input Validation & Offline Parsing
        parsed: ParsedURL = ValidationAgent.validate_and_parse(raw_url)
        sanitized = ValidationAgent.sanitize_for_audit(parsed)

        if not parsed.is_valid:
            # Return result documenting validation failure
            return AnalysisResult(
                analysis_id=analysis_id,
                timestamp=now_iso,
                url=raw_url or "[EMPTY]",
                sanitized_url="[INVALID]",
                indicator_count=0,
                classification=Classification.NO_WARNING_SIGNS,
                findings=[],
                safe_next_steps=["Please provide a valid, well-formed URL string to inspect."],
                limitations=f"URL parsing rejected: {parsed.error_message}"
            )

        # Step 2: Agent Execution (Strictly deterministic offline checks)
        findings: List[Finding] = []
        findings.extend(StructureAgent.analyze(parsed))
        findings.extend(HostnameAgent.analyze(parsed))
        findings.extend(ProtocolAgent.analyze(parsed))

        # Step 3: Scoring & Educational Classification
        count, classification = ScoringEngine.calculate_score(findings)
        safe_steps = ScoringEngine.get_safe_next_steps(classification)
        limitations = (
            "Educational evaluation only. PhishGuard conducts local structural heuristic checks. "
            "It does not query live DNS, reputation databases, or inspect destination web content."
        )

        return AnalysisResult(
            analysis_id=analysis_id,
            timestamp=now_iso,
            url=parsed.raw_url,
            sanitized_url=sanitized,
            indicator_count=count,
            classification=classification,
            findings=findings,
            safe_next_steps=safe_steps,
            limitations=limitations
        )

    @classmethod
    def analyze_batch(cls, raw_urls: List[str]) -> BatchAnalysisSummary:
        results: List[AnalysisResult] = []
        with_indicators = 0
        successful = 0

        for candidate in raw_urls:
            candidate_cleaned = candidate.strip()
            if not candidate_cleaned:
                continue
            res = cls.analyze_url(candidate_cleaned)
            results.append(res)
            if "rejected" not in res.limitations:
                successful += 1
            if res.indicator_count > 0:
                with_indicators += 1

        return BatchAnalysisSummary(
            total_inputs=len(results),
            successful_count=successful,
            with_indicators_count=with_indicators,
            results=results
        )

