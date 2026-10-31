#!/usr/bin/env python3
"""
=============================================================================
PHISHGUARD — Phishing URL Awareness & Intelligence Platform
Entry-point: phishing_checker.py
Compliant with EWB Cybersecurity Mini Project Workbook
=============================================================================
"Don't trust the link. Understand it."

This tool performs strictly local, offline heuristic analysis of URL structures
based on 6 workbook indicators:
  1. @ Symbol detection
  2. URL Length > 100 characters
  3. IPv4 address hostname
  4. Multiple hostname segments (>= 5)
  5. Punycode encoding marker (xn--)
  6. Unencrypted HTTP scheme

IMPORTANT: This is an educational awareness tool. It never claims a URL is
definitely safe or definitively malicious based only on these indicators.
=============================================================================
"""

import sys
import argparse
from phishguard.orchestrator import AnalysisOrchestrator
from phishguard.reporting import ReportGenerator
from phishguard.web_server import run_server
from phishguard.models import Classification


OFFICIAL_WORKBOOK_SAMPLES = [
    {
        "url": "https://www.example.com/login",
        "description": "Official Sample 1: Expected no listed warning signs",
        "expected_indicators": set(),
        "expected_classification": Classification.NO_WARNING_SIGNS,
    },
    {
        "url": "http://192.0.2.10/account",
        "description": "Official Sample 2: Expected IP-address hostname & HTTP",
        "expected_indicators": {"CHECK_3_IPV4_HOST", "CHECK_6_HTTP_SCHEME"},
        "expected_classification": Classification.REVIEW,
    },
    {
        "url": "http://example.com@sample.invalid/login",
        "description": "Official Sample 3: Expected @ symbol & HTTP",
        "expected_indicators": {"CHECK_1_AT_SYMBOL", "CHECK_6_HTTP_SCHEME"},
        "expected_classification": Classification.REVIEW,
    },
    {
        "url": "https://a.b.c.d.e.example.invalid/path",
        "description": "Official Sample 4: Expected many hostname segments",
        "expected_indicators": {"CHECK_4_MANY_SEGMENTS"},
        "expected_classification": Classification.REVIEW,
    },
    {
        "url": "https://xn--example.invalid/",
        "description": "Official Sample 5: Expected Punycode-style hostname",
        "expected_indicators": {"CHECK_5_PUNYCODE"},
        "expected_classification": Classification.REVIEW,
    },
]


def print_banner():
    banner = r"""
=============================================================================
  ____  _     _     _      ____                     _ 
 |  _ \| |__ (_)___| |__  / ___|_   _  __ _ _ __ __| |
 | |_) | '_ \| / __| '_ \| |  _| | | |/ _` | '__/ _` |
 |  __/| | | | \__ \ | | | |_| | |_| | (_| | | | (_| |
 |_|   |_| |_|_|___/_| |_|\____|\__,_|\__,_|_|  \__,_|
 Phishing URL Awareness & Intelligence Platform (EWB Compliant)
=============================================================================
    """
    print(banner)


def render_cli_result(result):
    print("\n" + "-" * 75)
    print(f"ANALYSIS ID     : {result.analysis_id}")
    print(f"TIMESTAMP       : {result.timestamp}")
    print(f"TARGET URL      : {result.url}")
    print(f"CLASSIFICATION  : [{result.classification.value}]")
    print(f"INDICATORS DETECTED : {result.indicator_count} / 6")
    print("-" * 75)

    if not result.findings:
        print(f"NOTE: {result.limitations}")
        print("-" * 75)
        return

    print("DETAILED HEURISTIC FINDINGS:")
    for idx, f in enumerate(result.findings, 1):
        status = "[FLAGGED]" if f.detected else "[CLEAR]"
        print(f"\n  {idx}. {f.name:<28} {status}")
        print(f"     Agent      : {f.agent_name}")
        if f.detected and f.evidence:
            print(f"     Evidence   : {f.evidence}")
        print(f"     Why Matters: {f.why_it_matters}")
        print(f"     Limitation : {f.limitations}")

    print("\nRECOMMENDED SAFE NEXT STEPS:")
    for step in result.safe_next_steps:
        print(f"  * {step}")

    print("\nLIMITATIONS:")
    print(f"  {result.limitations}")
    print("-" * 75 + "\n")


def verify_sample(result, expected_indicators, expected_classification):
    """Verifies whether an analysis result matches expected indicators and classification."""
    detected_indicators = set(f.check_id for f in result.findings if f.detected)
    indicators_match = (detected_indicators == expected_indicators)
    classification_match = (result.classification == expected_classification)
    return indicators_match and classification_match


def calculate_sample_verification_summary(samples=None):
    """Executes analysis for sample definitions and returns calculated verification statistics."""
    if samples is None:
        samples = OFFICIAL_WORKBOOK_SAMPLES

    results_detail = []
    passed = 0
    failed = 0

    for sample in samples:
        result = AnalysisOrchestrator.analyze_url(sample["url"])
        is_pass = verify_sample(
            result,
            sample["expected_indicators"],
            sample["expected_classification"]
        )
        if is_pass:
            passed += 1
        else:
            failed += 1

        results_detail.append({
            "sample": sample,
            "result": result,
            "passed": is_pass
        })

    total = len(samples)
    overall = "PASS" if (failed == 0 and total > 0) else "FAIL"

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "overall": overall,
        "details": results_detail
    }


def run_official_samples():
    """Runs all official workbook samples, renders results, prints genuine summary, and returns exit code."""
    print_banner()
    print("RUNNING 5 OFFICIAL EWB WORKBOOK SAMPLES:\n")

    summary = calculate_sample_verification_summary(OFFICIAL_WORKBOOK_SAMPLES)

    for i, item in enumerate(summary["details"], 1):
        sample = item["sample"]
        result = item["result"]
        print(f">>> [{i}/{summary['total']}] {sample['description']}")
        render_cli_result(result)

    print("=" * 75)
    print("OFFICIAL EWB SAMPLE VERIFICATION")
    print(f"Total Samples: {summary['total']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Overall: {summary['overall']}")
    print("=" * 75 + "\n")

    return 0 if summary["overall"] == "PASS" else 1


def interactive_cli():
    print_banner()
    print("Interactive Mode. Type 'exit' or 'quit' to close. Type 'samples' for workbook test.\n")
    while True:
        try:
            user_input = input("phishguard> ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                print("Exiting PhishGuard. Stay secure!")
                break
            if user_input.lower() == "samples":
                run_official_samples()
                continue
            
            result = AnalysisOrchestrator.analyze_url(user_input)
            render_cli_result(result)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting PhishGuard. Stay secure!")
            break


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard — Educational Phishing URL Awareness & Heuristic Checker"
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Single URL to inspect directly in CLI mode"
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Start the local Neo-Brutalist Web Server (binds strictly to 127.0.0.1:8765)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for local web server (default: 8765)"
    )
    parser.add_argument(
        "--samples",
        action="store_true",
        help="Run analysis on the 5 official EWB workbook samples"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result in pure JSON format (CLI mode)"
    )

    args = parser.parse_args()

    if args.web:
        run_server(port=args.port)
    elif args.samples:
        exit_code = run_official_samples()
        sys.exit(exit_code)
    elif args.url:
        result = AnalysisOrchestrator.analyze_url(args.url)
        if args.json:
            print(ReportGenerator.to_json(result))
        else:
            print_banner()
            render_cli_result(result)
    else:
        interactive_cli()


if __name__ == "__main__":
    main()
