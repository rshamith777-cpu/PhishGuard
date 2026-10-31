"""Tests for Reporting, JSON Serialization, and CSV/HTML Generation."""

import unittest
import json
from phishguard.orchestrator import AnalysisOrchestrator
from phishguard.reporting import ReportGenerator


class TestReporting(unittest.TestCase):

    def setUp(self):
        self.result = AnalysisOrchestrator.analyze_url("http://example.com@sample.invalid/login")

    def test_json_export(self):
        json_str = ReportGenerator.to_json(self.result)
        data = json.loads(json_str)
        self.assertEqual(data["analysis_id"], self.result.analysis_id)
        self.assertEqual(data["indicator_count"], 2)
        self.assertIn("findings", data)
        self.assertEqual(len(data["findings"]), 12)

    def test_csv_export(self):
        csv_str = ReportGenerator.to_csv([self.result])
        self.assertIn("Analysis ID,Timestamp,Sanitized URL", csv_str)
        self.assertIn(self.result.analysis_id, csv_str)
        self.assertIn("REVIEW", csv_str)

    def test_html_export(self):
        html_str = ReportGenerator.to_html(self.result)
        self.assertIn("<!DOCTYPE html>", html_str)
        self.assertIn("PHISHGUARD // AUDIT REPORT", html_str)
        self.assertIn("FLAGGED", html_str)
        self.assertIn(self.result.analysis_id, html_str)


if __name__ == "__main__":
    unittest.main()

