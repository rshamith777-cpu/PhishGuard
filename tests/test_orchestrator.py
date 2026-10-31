"""Tests for PhishGuard Orchestrator & Official EWB Samples."""

import unittest
from phishguard.orchestrator import AnalysisOrchestrator
from phishguard.models import Classification


class TestOrchestrator(unittest.TestCase):

    def test_official_sample_1(self):
        # Sample 1: https://www.example.com/login
        # Expected: No listed warning signs. (0 indicators)
        url = "https://www.example.com/login"
        result = AnalysisOrchestrator.analyze_url(url)

        self.assertEqual(result.indicator_count, 0)
        self.assertEqual(result.classification, Classification.NO_WARNING_SIGNS)
        detected_checks = [f.check_id for f in result.findings if f.detected]
        self.assertEqual(detected_checks, [])

    def test_official_sample_2(self):
        # Sample 2: http://192.0.2.10/account
        # Expected: IP-address hostname and HTTP scheme.
        url = "http://192.0.2.10/account"
        result = AnalysisOrchestrator.analyze_url(url)

        self.assertEqual(result.indicator_count, 2)
        self.assertEqual(result.classification, Classification.REVIEW)
        detected_checks = set(f.check_id for f in result.findings if f.detected)
        self.assertEqual(detected_checks, {"CHECK_3_IPV4_HOST", "CHECK_6_HTTP_SCHEME"})

    def test_official_sample_3(self):
        # Sample 3: http://example.com@sample.invalid/login
        # Expected: @ symbol and HTTP scheme.
        url = "http://example.com@sample.invalid/login"
        result = AnalysisOrchestrator.analyze_url(url)

        self.assertEqual(result.indicator_count, 2)
        self.assertEqual(result.classification, Classification.REVIEW)
        detected_checks = set(f.check_id for f in result.findings if f.detected)
        self.assertEqual(detected_checks, {"CHECK_1_AT_SYMBOL", "CHECK_6_HTTP_SCHEME"})

    def test_official_sample_4(self):
        # Sample 4: https://a.b.c.d.e.example.invalid/path
        # Expected: Many hostname segments.
        url = "https://a.b.c.d.e.example.invalid/path"
        result = AnalysisOrchestrator.analyze_url(url)

        self.assertGreaterEqual(result.indicator_count, 1)
        detected_checks = set(f.check_id for f in result.findings if f.detected)
        self.assertIn("CHECK_4_MANY_SEGMENTS", detected_checks)

    def test_official_sample_5(self):
        # Sample 5: https://xn--example.invalid/
        # Expected: Punycode-style hostname.
        url = "https://xn--example.invalid/"
        result = AnalysisOrchestrator.analyze_url(url)

        self.assertEqual(result.indicator_count, 1)
        self.assertEqual(result.classification, Classification.REVIEW)
        detected_checks = set(f.check_id for f in result.findings if f.detected)
        self.assertEqual(detected_checks, {"CHECK_5_PUNYCODE"})

    def test_elevated_review_composite(self):
        # URL with >=3 indicators: HTTP + IP + @
        url = "http://admin@192.0.2.10/login"
        result = AnalysisOrchestrator.analyze_url(url)
        self.assertGreaterEqual(result.indicator_count, 3)
        self.assertEqual(result.classification, Classification.ELEVATED_REVIEW)

    def test_batch_processing(self):
        urls = [
            "https://www.example.com/login",
            "http://192.0.2.10/account",
            "https://xn--example.invalid/"
        ]
        batch_summary = AnalysisOrchestrator.analyze_batch(urls)
        self.assertEqual(batch_summary.total_inputs, 3)
        self.assertEqual(batch_summary.successful_count, 3)
        self.assertEqual(batch_summary.with_indicators_count, 2)

    def test_sample_verification_summary_calculation(self):
        from phishing_checker import calculate_sample_verification_summary, OFFICIAL_WORKBOOK_SAMPLES

        # Test calculation with the actual official workbook samples
        summary = calculate_sample_verification_summary(OFFICIAL_WORKBOOK_SAMPLES)
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["passed"], 5)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["overall"], "PASS")

        # Test calculation with a failing test case to ensure honest dynamic calculation
        mock_failing_sample = [{
            "url": "https://www.example.com/login",
            "description": "Mock failure test",
            "expected_indicators": {"CHECK_1_AT_SYMBOL"},  # Not present in example.com/login
            "expected_classification": Classification.REVIEW,
        }]
        fail_summary = calculate_sample_verification_summary(mock_failing_sample)
        self.assertEqual(fail_summary["total"], 1)
        self.assertEqual(fail_summary["passed"], 0)
        self.assertEqual(fail_summary["failed"], 1)
        self.assertEqual(fail_summary["overall"], "FAIL")


if __name__ == "__main__":
    unittest.main()

