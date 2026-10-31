"""Netlify Serverless Function for PhishGuard API."""

import json
import sys
import os

# Add root directory to path so phishguard package can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from phishguard.orchestrator import AnalysisOrchestrator
from phishguard.reporting import ReportGenerator
from phishguard.audit import AuditManager


def handler(event, context):
    """Standard Netlify Python Function handler."""
    http_method = event.get("httpMethod", "GET").upper()
    path = event.get("path", "")

    # Headers for JSON responses
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    }

    if http_method == "OPTIONS":
        return {
            "statusCode": 204,
            "headers": headers,
            "body": ""
        }

    # GET Endpoints
    if http_method == "GET":
        if path.endswith("/health") or "health" in path:
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps({
                    "status": "online",
                    "mode": "NETLIFY_SERVERLESS",
                    "version": "1.1.0",
                    "checks": 12,
                    "agents": 4
                })
            }

        if path.endswith("/history") or "history" in path:
            history = AuditManager.get_history()
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps(history)
            }

        return {
            "statusCode": 404,
            "headers": headers,
            "body": json.dumps({"error": "Endpoint not found"})
        }

    # POST Endpoints
    if http_method == "POST":
        body_raw = event.get("body", "")
        data = {}
        if body_raw:
            try:
                data = json.loads(body_raw)
            except Exception:
                return {
                    "statusCode": 400,
                    "headers": headers,
                    "body": json.dumps({"error": "Invalid JSON body"})
                }

        if path.endswith("/analyze") or "analyze-batch" not in path and "analyze" in path:
            url_to_analyze = data.get("url", "")
            result = AnalysisOrchestrator.analyze_url(url_to_analyze)
            AuditManager.record(result)
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps(result.to_dict())
            }

        if path.endswith("/analyze-batch") or "analyze-batch" in path:
            urls = data.get("urls", [])
            if not isinstance(urls, list) or len(urls) > 50:
                return {
                    "statusCode": 400,
                    "headers": headers,
                    "body": json.dumps({"error": "urls must be a list with max 50 items"})
                }
            summary = AnalysisOrchestrator.analyze_batch(urls)
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps(summary.to_dict())
            }

        if path.endswith("/export-html") or "export-html" in path:
            url = data.get("url", "")
            result = AnalysisOrchestrator.analyze_url(url)
            html_report = ReportGenerator.to_html(result)
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "text/html; charset=utf-8",
                    "Access-Control-Allow-Origin": "*"
                },
                "body": html_report
            }

        if path.endswith("/clear-history") or "clear-history" in path:
            AuditManager.clear_history()
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps({"status": "cleared"})
            }

    return {
        "statusCode": 404,
        "headers": headers,
        "body": json.dumps({"error": "Endpoint not found"})
    }
