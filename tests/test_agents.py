"""Tests for PhishGuard Specialized Deterministic Agents."""

import unittest
from phishguard.agents.validation_agent import ValidationAgent
from phishguard.agents.structure_agent import StructureAgent
from phishguard.agents.hostname_agent import HostnameAgent
from phishguard.agents.protocol_agent import ProtocolAgent


class TestAgents(unittest.TestCase):

    def test_validation_agent_empty_and_whitespace(self):
        res1 = ValidationAgent.validate_and_parse("")
        self.assertFalse(res1.is_valid)

        res2 = ValidationAgent.validate_and_parse("   ")
        self.assertFalse(res2.is_valid)

        res3 = ValidationAgent.validate_and_parse(None)
        self.assertFalse(res3.is_valid)

    def test_validation_agent_valid(self):
        parsed = ValidationAgent.validate_and_parse("https://example.com/test?token=123#sec")
        self.assertTrue(parsed.is_valid)
        self.assertEqual(parsed.hostname, "example.com")
        self.assertEqual(parsed.scheme, "https")

        # Sanitization check
        sanitized = ValidationAgent.sanitize_for_audit(parsed)
        self.assertEqual(sanitized, "https://example.com/test")
        self.assertNotIn("token=123", sanitized)

    def test_structure_agent_at_symbol(self):
        # Case with @
        parsed = ValidationAgent.validate_and_parse("http://user@attacker.com/login")
        finding = StructureAgent.check_at_symbol(parsed)
        self.assertTrue(finding.detected)
        self.assertEqual(finding.check_id, "CHECK_1_AT_SYMBOL")

        # Case without @
        clean_parsed = ValidationAgent.validate_and_parse("https://legit.com/login")
        finding_clean = StructureAgent.check_at_symbol(clean_parsed)
        self.assertFalse(finding_clean.detected)

    def test_structure_agent_length(self):
        short_url = "https://example.com/short"
        long_url = "https://example.com/" + "a" * 120

        finding_short = StructureAgent.check_url_length(ValidationAgent.validate_and_parse(short_url))
        self.assertFalse(finding_short.detected)

        finding_long = StructureAgent.check_url_length(ValidationAgent.validate_and_parse(long_url))
        self.assertTrue(finding_long.detected)
        self.assertEqual(finding_long.check_id, "CHECK_2_URL_LENGTH")

    def test_hostname_agent_ipv4(self):
        # Valid IPv4 Host
        parsed_ip = ValidationAgent.validate_and_parse("http://192.0.2.10/account")
        finding = HostnameAgent.check_ipv4_hostname(parsed_ip)
        self.assertTrue(finding.detected)
        self.assertEqual(finding.check_id, "CHECK_3_IPV4_HOST")

        # Domain name
        parsed_domain = ValidationAgent.validate_and_parse("https://example.com/account")
        finding_domain = HostnameAgent.check_ipv4_hostname(parsed_domain)
        self.assertFalse(finding_domain.detected)

    def test_hostname_agent_many_segments(self):
        # 3 segments
        parsed_3 = ValidationAgent.validate_and_parse("https://www.example.com/path")
        finding_3 = HostnameAgent.check_many_hostname_segments(parsed_3)
        self.assertFalse(finding_3.detected)

        # 6 segments: a.b.c.d.e.example.invalid
        parsed_6 = ValidationAgent.validate_and_parse("https://a.b.c.d.e.example.invalid/path")
        finding_6 = HostnameAgent.check_many_hostname_segments(parsed_6)
        self.assertTrue(finding_6.detected)
        self.assertEqual(finding_6.check_id, "CHECK_4_MANY_SEGMENTS")

    def test_hostname_agent_punycode(self):
        # Punycode
        parsed_puny = ValidationAgent.validate_and_parse("https://xn--example.invalid/")
        finding_puny = HostnameAgent.check_punycode(parsed_puny)
        self.assertTrue(finding_puny.detected)
        self.assertEqual(finding_puny.check_id, "CHECK_5_PUNYCODE")

        # Standard ASCII
        parsed_std = ValidationAgent.validate_and_parse("https://example.invalid/")
        finding_std = HostnameAgent.check_punycode(parsed_std)
        self.assertFalse(finding_std.detected)

    def test_protocol_agent_http_vs_https(self):
        parsed_http = ValidationAgent.validate_and_parse("http://example.com/login")
        finding_http = ProtocolAgent.check_http_scheme(parsed_http)
        self.assertTrue(finding_http.detected)
        self.assertEqual(finding_http.check_id, "CHECK_6_HTTP_SCHEME")

        parsed_https = ValidationAgent.validate_and_parse("https://example.com/login")
        finding_https = ProtocolAgent.check_http_scheme(parsed_https)
        self.assertFalse(finding_https.detected)

    # -------------------------------------------------------------
    # ADVANCED HEURISTIC UNIT TESTS
    # -------------------------------------------------------------

    def test_adv_url_shortener(self):
        # Shortener detection
        parsed_short = ValidationAgent.validate_and_parse("https://bit.ly/3Example")
        finding_short = StructureAgent.check_url_shortener(parsed_short)
        self.assertTrue(finding_short.detected)
        self.assertEqual(finding_short.check_id, "ADV_URL_SHORTENER")

        # Standard domain should not trigger shortener
        parsed_reg = ValidationAgent.validate_and_parse("https://www.wikipedia.org/wiki/Phishing")
        finding_reg = StructureAgent.check_url_shortener(parsed_reg)
        self.assertFalse(finding_reg.detected)

    def test_adv_suspicious_parameters(self):
        # Nested URL / redirect
        parsed_redir = ValidationAgent.validate_and_parse("https://example.com/login?redirect=https://evil-site.com")
        finding_redir = StructureAgent.check_suspicious_parameters(parsed_redir)
        self.assertTrue(finding_redir.detected)
        self.assertEqual(finding_redir.check_id, "ADV_SUSPICIOUS_PARAMS")

        # Urgent session expiration
        parsed_urgent = ValidationAgent.validate_and_parse("https://portal.example.com/verify?session=expired")
        finding_urgent = StructureAgent.check_suspicious_parameters(parsed_urgent)
        self.assertTrue(finding_urgent.detected)

        # Benign search query parameters should not trigger
        parsed_search = ValidationAgent.validate_and_parse("https://example.com/search?q=cybersecurity+training&page=2")
        finding_search = StructureAgent.check_suspicious_parameters(parsed_search)
        self.assertFalse(finding_search.detected)

    def test_adv_suspicious_encoding(self):
        # Directory traversal
        parsed_trav = ValidationAgent.validate_and_parse("https://example.com/%2e%2e/%2e%2e/admin")
        finding_trav = StructureAgent.check_suspicious_encoding(parsed_trav)
        self.assertTrue(finding_trav.detected)
        self.assertEqual(finding_trav.check_id, "ADV_SUSPICIOUS_ENCODING")

        # Static XSS script tag inspection
        parsed_xss = ValidationAgent.validate_and_parse("https://example.com/search?q=%3Cscript%3E")
        finding_xss = StructureAgent.check_suspicious_encoding(parsed_xss)
        self.assertTrue(finding_xss.detected)

        # Hex-encoded ASCII path
        parsed_hex = ValidationAgent.validate_and_parse("https://example.com/%61%64%6d%69%6e")
        finding_hex = StructureAgent.check_suspicious_encoding(parsed_hex)
        self.assertTrue(finding_hex.detected)

        # Benign URL encoding (spaces, punctuation)
        parsed_benign = ValidationAgent.validate_and_parse("https://example.com/files/Report%202026.pdf")
        finding_benign = StructureAgent.check_suspicious_encoding(parsed_benign)
        self.assertFalse(finding_benign.detected)

    def test_adv_typosquatting(self):
        # Character transposition (micorsoft -> microsoft)
        parsed_trans = ValidationAgent.validate_and_parse("https://micorsoft.com/auth")
        finding_trans = HostnameAgent.check_typosquatting(parsed_trans)
        self.assertTrue(finding_trans.detected)
        self.assertEqual(finding_trans.check_id, "ADV_TYPOSQUATTING")

        # Leetspeak (paypa1 -> paypal, g00gle -> google)
        parsed_leet = ValidationAgent.validate_and_parse("https://paypa1.com/login")
        finding_leet = HostnameAgent.check_typosquatting(parsed_leet)
        self.assertTrue(finding_leet.detected)

        # Authentic brand domain should NOT be flagged as typosquatting
        parsed_auth = ValidationAgent.validate_and_parse("https://www.microsoft.com/en-us")
        finding_auth = HostnameAgent.check_typosquatting(parsed_auth)
        self.assertFalse(finding_auth.detected)

    def test_adv_misleading_domain_structure(self):
        # Brand in subdomain while registered domain is attacker.com
        parsed_sub = ValidationAgent.validate_and_parse("https://login.microsoft.com.verify-user-access.com")
        finding_sub = HostnameAgent.check_misleading_subdomains_and_hyphenation(parsed_sub)
        self.assertTrue(finding_sub.detected)
        self.assertEqual(finding_sub.check_id, "ADV_MISLEADING_DOMAIN_STRUCTURE")

        # Hyphenated brand compound spoofing
        parsed_hyphen = ValidationAgent.validate_and_parse("https://microsoft-login-verification.com")
        finding_hyphen = HostnameAgent.check_misleading_subdomains_and_hyphenation(parsed_hyphen)
        self.assertTrue(finding_hyphen.detected)

        # Legitimate brand domain with legitimate subdomain should NOT trigger
        parsed_legit_sub = ValidationAgent.validate_and_parse("https://azure.microsoft.com")
        finding_legit_sub = HostnameAgent.check_misleading_subdomains_and_hyphenation(parsed_legit_sub)
        self.assertFalse(finding_legit_sub.detected)

    def test_adv_non_standard_port_or_protocol(self):
        # Non-standard web port (8443)
        parsed_port = ValidationAgent.validate_and_parse("https://example.com:8443/admin")
        finding_port = ProtocolAgent.check_non_standard_port_or_scheme(parsed_port)
        self.assertTrue(finding_port.detected)
        self.assertEqual(finding_port.check_id, "ADV_PROTOCOL_PORT_ANOMALY")

        # Non-web protocol (ftp)
        parsed_proto = ValidationAgent.validate_and_parse("ftp://files.example.com/download.zip")
        finding_proto = ProtocolAgent.check_non_standard_port_or_scheme(parsed_proto)
        self.assertTrue(finding_proto.detected)

        # Standard HTTPS port (443) or default scheme
        parsed_std = ValidationAgent.validate_and_parse("https://example.com/page")
        finding_std = ProtocolAgent.check_non_standard_port_or_scheme(parsed_std)
        self.assertFalse(finding_std.detected)

    # -------------------------------------------------------------
    # BENIGN REAL-WORLD URL FALSE-POSITIVE SUITE
    # -------------------------------------------------------------

    def test_benign_urls_zero_flags(self):
        benign_sample_urls = [
            "https://www.microsoft.com",
            "https://www.github.com",
            "https://www.wikipedia.org",
            "https://www.amazon.com",
            "https://www.stackoverflow.com",
            "https://docs.python.org/3/library/unittest.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP"
        ]

        from phishguard.orchestrator import AnalysisOrchestrator
        from phishguard.models import Classification

        for b_url in benign_sample_urls:
            res = AnalysisOrchestrator.analyze_url(b_url)
            self.assertEqual(res.indicator_count, 0, f"False positive on benign URL: {b_url} ({[f.name for f in res.findings if f.detected]})")
            self.assertEqual(res.classification, Classification.NO_WARNING_SIGNS)


if __name__ == "__main__":
    unittest.main()

