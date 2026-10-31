"""Structure Analysis Agent - Responsible for URL text and syntax anomalies."""

import re
from typing import List
from urllib.parse import unquote
from ..models import Finding, ParsedURL


class StructureAgent:
    """Evaluates macro-level URL text structure, userinfo obfuscation, shortening services, and path/query anomalies."""

    AGENT_NAME = "Structure Analysis Agent"

    # Known popular URL shortener domains (offline list)
    KNOWN_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "goo.gl", "ow.ly",
        "buff.ly", "cutt.ly", "rebrand.ly", "bl.ink", "shorturl.at"
    }

    # Suspicious query parameter patterns commonly used in credential harvesting / open redirects
    SUSPICIOUS_QUERY_KEYS = {
        "redirect", "next", "url", "dest", "destination", "target", "r", "u",
        "token", "session", "pass", "password", "auth", "account", "login",
        "verify", "suspended", "update"
    }

    @classmethod
    def check_at_symbol(cls, parsed: ParsedURL) -> Finding:
        """CHECK 1 (Mandatory EWB): Presence of '@' symbol in URL text."""
        detected = "@" in parsed.raw_url
        evidence = "@ symbol found in authority or URL body" if detected else None
        
        return Finding(
            check_id="CHECK_1_AT_SYMBOL",
            name="@ Symbol in URL",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "The '@' symbol separates user-information authentication syntax from the "
                "actual destination hostname in URI RFC 3986. Attackers often prefix an "
                "apparent brand name before '@' so users mistake the fake prefix for the actual domain."
            ),
            limitations=(
                "Legitimate authentication endpoints, email links, or internal administrative "
                "consoles may occasionally contain '@'. Its presence warrants verification of the "
                "actual hostname occurring strictly after the '@'."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def check_url_length(cls, parsed: ParsedURL, max_length: int = 100) -> Finding:
        """CHECK 2 (Mandatory EWB): Flag URLs exceeding 100 characters."""
        detected = parsed.length > max_length
        evidence = f"URL length is {parsed.length} characters (threshold: {max_length})" if detected else None
        
        return Finding(
            check_id="CHECK_2_URL_LENGTH",
            name="Unusually Long URL",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "Unusually long URLs (exceeding 100 characters) are frequently used in phishing attacks "
                "to push the true destination domain out of view in mobile browsers or email clients, "
                "or to embed obfuscated payload strings."
            ),
            limitations=(
                "Many legitimate web services (such as search queries, OAuth redirect URLs, analytics tracking, "
                "and federated logins) legitimately exceed 100 characters without any malicious intent."
            ),
            agent_name=cls.AGENT_NAME
        )

    # -------------------------------------------------------------
    # ADVANCED HEURISTIC CHECKS (Defensive Intelligence)
    # -------------------------------------------------------------

    @classmethod
    def check_url_shortener(cls, parsed: ParsedURL) -> Finding:
        """ADVANCED CHECK: Detect known URL shortening services."""
        host = (parsed.hostname or "").lower()
        detected = host in cls.KNOWN_SHORTENERS
        evidence = f"Hostname '{host}' is a known public URL shortening service" if detected else None

        return Finding(
            check_id="ADV_URL_SHORTENER",
            name="URL Shortening Service",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "URL shortening services conceal the actual destination web address, making it impossible "
                "for users to preview the genuine domain before clicking. Phishing campaigns heavily abuse "
                "shorteners to evade static email scanners and security filters."
            ),
            limitations=(
                "Shorteners are widely used for legitimate convenience in social media posts, SMS, and character-limited media."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def check_suspicious_parameters(cls, parsed: ParsedURL) -> Finding:
        """ADVANCED CHECK: Identify open redirect indicators or sensitive parameter exposure in query string."""
        detected = False
        evidences = []
        raw_query = parsed.query or ""

        if raw_query:
            # Check for nested URLs or redirect parameters (e.g. redirect=https://evil.com, next=/dashboard, url=...)
            if "http://" in raw_query or "https://" in raw_query or "%3a%2f%2f" in raw_query.lower():
                detected = True
                evidences.append("Potential open redirect: secondary external URL detected inside query parameters")

            # Check for credential / session / verification / redirect query parameters or sensitive endpoints
            full_url_lower = (parsed.raw_url).lower()
            params = [p.split("=")[0].lower() for p in raw_query.split("&") if p]
            sensitive_found = [p for p in params if p in cls.SUSPICIOUS_QUERY_KEYS]
            if sensitive_found or any(k in full_url_lower for k in ["reset-password", "password-reset", "verify-account", "update-billing"]):
                # If it's paired with sensitive auth/reset/redirect keys or path
                if any(k in full_url_lower for k in ["suspend", "expire", "verify", "reset", "password", "token", "auth", "redirect", "next", "admin", "login"]):
                    detected = True
                    triggers = sensitive_found if sensitive_found else ["sensitive auth/reset endpoint"]
                    evidences.append(f"Suspicious security/session/credential parameter triggers: {triggers}")

        return Finding(
            check_id="ADV_SUSPICIOUS_PARAMS",
            name="Suspicious Query / Parameter Syntax",
            detected=detected,
            evidence="; ".join(evidences) if detected else None,
            why_it_matters=(
                "Parameters containing secondary external URLs or urgent session triggers are syntactic indicators "
                "frequently observed in deceptive links. Note: This heuristic performs static text pattern matching "
                "only and does NOT prove that a target server contains an exploitable open redirect or active vulnerability."
            ),
            limitations=(
                "Legitimate Single-Sign-On (SSO) and OAuth workflows legitimately pass callback redirect URLs and authentication tokens."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def check_suspicious_encoding(cls, parsed: ParsedURL) -> Finding:
        """ADVANCED CHECK: Detect mixed hex encoding, directory traversal, or embedded script tags."""
        raw = parsed.raw_url
        detected = False
        evidences = []

        # Directory traversal in path (%2e%2e or ..)
        if "/../" in raw or "/%2e%2e/" in raw.lower() or "%252e%252e" in raw.lower():
            detected = True
            evidences.append("Directory traversal pattern ('../' or encoded dot-dot-slash) detected")

        # Script tags in URL
        if "<script" in raw.lower() or "%3cscript" in raw.lower():
            detected = True
            evidences.append("Embedded HTML/XSS tag ('<script>') detected in URL text")

        # Excessive percentage encoding in path (obfuscating standard ASCII letters like %61%64%6d%69%6e)
        hex_encoded_chars = re.findall(r"%[0-9a-fA-F]{2}", parsed.path)
        if len(hex_encoded_chars) >= 3:
            # Check if decoding reveals standard ASCII word characters
            decoded_path = unquote(parsed.path)
            if decoded_path != parsed.path:
                detected = True
                evidences.append(f"Heavy percent-encoding obfuscating ASCII path ('{parsed.path}' -> '{decoded_path}')")

        return Finding(
            check_id="ADV_SUSPICIOUS_ENCODING",
            name="Obfuscated Encoding & Path Anomalies",
            detected=detected,
            evidence="; ".join(evidences) if detected else None,
            why_it_matters=(
                "Attackers use double-encoding, directory traversal ('..'), and hex-encoded ASCII to bypass web application "
                "firewalls, hide administrative paths, or inject cross-site scripting payloads. "
                "Note: PhishGuard inspects the URL string text statically and does NOT execute any script or payload."
            ),
            limitations=(
                "Standard URL encoding is normal for non-ASCII characters, spaces (%20), and punctuation."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> List[Finding]:
        return [
            cls.check_at_symbol(parsed),
            cls.check_url_length(parsed, max_length=100),
            cls.check_url_shortener(parsed),
            cls.check_suspicious_parameters(parsed),
            cls.check_suspicious_encoding(parsed)
        ]
