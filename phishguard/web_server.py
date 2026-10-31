"""Local HTTP Server - Bound strictly to 127.0.0.1 for local privacy and safety."""

import os
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
from .orchestrator import AnalysisOrchestrator
from .audit import AuditManager
from .reporting import ReportGenerator

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")


class PhishGuardRequestHandler(SimpleHTTPRequestHandler):
    """Custom request handler serving static assets and local-only REST APIs."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, format, *args):
        # Clean terminal logging without dumping query parameters
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "online",
                "mode": "LOCAL_LOOPBACK_ONLY",
                "version": "1.1.0",
                "checks": 12,
                "agents": 4
            }).encode("utf-8"))
            return

        if parsed.path == "/api/history":
            history = AuditManager.get_history()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(history).encode("utf-8"))
            return

        # Serve static web files
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        
        # Security: Limit maximum payload size (64 KB)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 65536:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Payload too large. Maximum 64KB."}).encode("utf-8"))
            return

        body_raw = self.rfile.read(content_length).decode("utf-8", errors="replace")

        if parsed.path == "/api/analyze":
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

        if parsed.path == "/api/analyze-batch":
            try:
                data = json.loads(body_raw) if body_raw else {}
                urls = data.get("urls", [])
                if not isinstance(urls, list):
                    raise ValueError("urls must be a list")
                if len(urls) > 50:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Batch limit exceeded. Maximum 50 URLs per request."}).encode("utf-8"))
                    return
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Invalid batch request: {str(e)}"}).encode("utf-8"))
                return

            summary = AnalysisOrchestrator.analyze_batch(urls)
            for res in summary.results:
                AuditManager.record(res)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(summary.to_dict()).encode("utf-8"))
            return

        if parsed.path == "/api/export-html":
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

        if parsed.path == "/api/clear-history":
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


def run_server(port: int = 8765):
    """Starts the local-first HTTP server strictly on 127.0.0.1 loopback."""
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, PhishGuardRequestHandler)
    print("============================================================")
    print("PHISHGUARD — LOCAL INTELLIGENCE & AWARENESS PLATFORM")
    print("============================================================")
    print(f"Server running securely on: http://127.0.0.1:{port}")
    print("Bound strictly to loopback interface (offline safe).")
    print("Press CTRL+C to terminate the local server.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down local server safely...")
        httpd.server_close()

