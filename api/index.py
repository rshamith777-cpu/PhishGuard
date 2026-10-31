"""Vercel Serverless Function entry point for PhishGuard API."""

import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse
import sys
import os

# Add root directory to path so phishguard package can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from phishguard.orchestrator import AnalysisOrchestrator
from phishguard.reporting import ReportGenerator
from phishguard.audit import AuditManager


class handler(BaseHTTPRequestHandler):
    """Serverless HTTP request handler compatible with Vercel Python runtime."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.endswith("/health") or parsed.path.endswith("/api/health"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "online",
                "mode": "VERCEL_SERVERLESS",
                "version": "1.1.0",
                "checks": 12,
                "agents": 4
            }).encode("utf-8"))
            return

        if parsed.path.endswith("/history") or parsed.path.endswith("/api/history"):
            history = AuditManager.get_history()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(history).encode("utf-8"))
            return

        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 65536:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Payload too large. Max 64KB."}).encode("utf-8"))
            return

        body_raw = self.rfile.read(content_length).decode("utf-8", errors="replace")

        if parsed.path.endswith("/analyze") or parsed.path.endswith("/api/analyze"):
            try:
                data = json.loads(body_raw) if body_raw else {}
                url_to_analyze = data.get("url", "")
            except Exception:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON body"}).encode("utf-8"))
                return

            result = AnalysisOrchestrator.analyze_url(url_to_analyze)
            AuditManager.record(result)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result.to_dict()).encode("utf-8"))
            return

        if parsed.path.endswith("/analyze-batch") or parsed.path.endswith("/api/analyze-batch"):
            try:
                data = json.loads(body_raw) if body_raw else {}
                urls = data.get("urls", [])
                if not isinstance(urls, list) or len(urls) > 50:
                    raise ValueError("urls must be a list with max 50 items")
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Invalid batch request: {str(e)}"}).encode("utf-8"))
                return

            summary = AnalysisOrchestrator.analyze_batch(urls)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(summary.to_dict()).encode("utf-8"))
            return

        if parsed.path.endswith("/export-html") or parsed.path.endswith("/api/export-html"):
            try:
                data = json.loads(body_raw) if body_raw else {}
                url = data.get("url", "")
                result = AnalysisOrchestrator.analyze_url(url)
                html_report = ReportGenerator.to_html(result)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html_report.encode("utf-8"))
                return
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Export failed: {str(e)}"}).encode("utf-8"))
                return

        if parsed.path.endswith("/clear-history") or parsed.path.endswith("/api/clear-history"):
            AuditManager.clear_history()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "cleared"}).encode("utf-8"))
            return

        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode("utf-8"))

