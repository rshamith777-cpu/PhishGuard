"""Netlify Serverless Function for PhishGuard API."""

import json
import sys
import os

# Ensure root directory is on Python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(CURRENT_DIR))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phishguard.orchestrator import AnalysisOrchestrator
from phishguard.reporting import ReportGenerator


def handler(event, context=None):
    """Standard Netlify Python Function handler."""
    try:
        http_method = event.get("httpMethod", "GET").upper()
        raw_path = event.get("path", "")

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

        # Health endpoint
        if "health" in raw_path:
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

        # History endpoint
        if "history" in raw_path:
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps([])
            }

        # Analyze Batch
        if "analyze-batch" in raw_path:
            body_raw = event.get("body", "{}")
            data = json.loads(body_raw) if body_raw else {}
            urls = data.get("urls", [])
            summary = AnalysisOrchestrator.analyze_batch(urls)
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps(summary.to_dict())
            }

        # Export HTML
        if "export-html" in raw_path:
            body_raw = event.get("body", "{}")
            data = json.loads(body_raw) if body_raw else {}
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

        # Analyze Single URL (Primary endpoint)
        if "analyze" in raw_path:
            body_raw = event.get("body", "{}")
            data = json.loads(body_raw) if body_raw else {}
            target_url = data.get("url", "")
            result = AnalysisOrchestrator.analyze_url(target_url)
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps(result.to_dict())
            }

        return {
            "statusCode": 404,
            "headers": headers,
            "body": json.dumps({"error": f"Endpoint not found: {raw_path}"})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({"error": f"Serverless execution error: {str(e)}"})
        }
