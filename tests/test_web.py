"""Tests for Web Request Handler Logic without Network Socket binding."""

import unittest
import json
import io
from phishguard.web_server import PhishGuardRequestHandler


class DummySocket:
    """Mock socket for testing SimpleHTTPRequestHandler directly in memory."""
    def __init__(self, request_bytes):
        self._rfile = io.BytesIO(request_bytes)
        self._wfile = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if "b" in mode:
            if "r" in mode:
                return self._rfile
            elif "w" in mode:
                return self._wfile
        return None

    def sendall(self, data):
        self._wfile.write(data)

    def close(self):
        pass


class MockPhishGuardHandler(PhishGuardRequestHandler):
    """Subclass that stubs out setup and finish to avoid live socket bindings."""
    def __init__(self, raw_request_bytes):
        self.rfile = io.BytesIO(raw_request_bytes)
        self.wfile = io.BytesIO()
        self.headers = {}
        # Parse minimal HTTP line
        first_line = self.rfile.readline().decode("utf-8")
        self.requestline = first_line.strip()
        self.request_version = "HTTP/1.1"
        parts = self.requestline.split()
        if len(parts) >= 2:
            self.command = parts[0]
            self.path = parts[1]
        
        # Read headers
        while True:
            line = self.rfile.readline().decode("utf-8")
            if not line or line in ("\r\n", "\n"):
                break
            if ":" in line:
                k, v = line.split(":", 1)
                self.headers[k.strip().title()] = v.strip()

    def log_request(self, code='-', size='-'):
        pass


class TestWebLogic(unittest.TestCase):

    def test_health_route(self):
        req_bytes = b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        handler = MockPhishGuardHandler(req_bytes)
        handler.do_GET()
        output = handler.wfile.getvalue().decode("utf-8", errors="replace")
        self.assertIn("200 OK", output)
        self.assertIn("LOCAL_LOOPBACK_ONLY", output)
        self.assertIn('"checks": 12', output)

    def test_analyze_route(self):
        body = json.dumps({"url": "http://192.0.2.10/account"}).encode("utf-8")
        req_bytes = (
            f"POST /api/analyze HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: application/json\r\n\r\n"
        ).encode("utf-8") + body

        handler = MockPhishGuardHandler(req_bytes)
        handler.do_POST()
        output = handler.wfile.getvalue().decode("utf-8", errors="replace")
        self.assertIn("200 OK", output)
        self.assertIn("REVIEW", output)
        self.assertIn("CHECK_3_IPV4_HOST", output)

    def test_invalid_body_route(self):
        body = b"{not_json"
        req_bytes = (
            f"POST /api/analyze HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: application/json\r\n\r\n"
        ).encode("utf-8") + body

        handler = MockPhishGuardHandler(req_bytes)
        handler.do_POST()
        output = handler.wfile.getvalue().decode("utf-8", errors="replace")
        self.assertIn("400 Bad Request", output)


if __name__ == "__main__":
    unittest.main()
