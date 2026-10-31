"""Hostname Intelligence Agent - Inspects hostname morphology, IP addresses, encodings, and typosquatting."""

import ipaddress
import re
from typing import List, Set
from ..models import Finding, ParsedURL


class HostnameAgent:
    """Evaluates hostname labels, IPv4 representations, Punycode, misleading brand prefixes, and typosquatting."""

    AGENT_NAME = "Hostname Intelligence Agent"

    # Targeted major brands frequently mimicked in phishing lures
    TOP_BRANDS = {
        "microsoft", "google", "paypal", "apple", "amazon", "netflix",
        "facebook", "instagram", "github", "linkedin", "dropbox", "chase",
        "bankofamerica", "wellsfargo"
    }

    # Common phishing keywords found combined with brand names
    PHISH_KEYWORDS = {
        "login", "signin", "verify", "verification", "security", "secure",
        "account", "billing", "update", "support", "service", "portal",
        "authentication", "auth", "center", "review", "suspended"
    }

    # Levenshtein Distance calculation for offline typosquatting detection
    @classmethod
    def _levenshtein(cls, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return cls._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    @classmethod
    def check_ipv4_hostname(cls, parsed: ParsedURL) -> Finding:
        """CHECK 3 (Mandatory EWB): Identify an IPv4-style hostname."""
        host = parsed.hostname or ""
        detected = False
        evidence = None

        if host:
            clean_host = host.strip("[]")
            try:
                ip = ipaddress.ip_address(clean_host)
                if isinstance(ip, ipaddress.IPv4Address):
                    detected = True
                    evidence = f"Hostname '{clean_host}' is a numeric IPv4 address"
            except ValueError:
                detected = False

        return Finding(
            check_id="CHECK_3_IPV4_HOST",
            name="IP Address Hostname",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "Legitimate institutions use registered domain names. Phishing operators sometimes "
                "use bare IPv4 addresses to bypass domain reputation blocklists and conceal the entity "
                "operating the server."
            ),
            limitations=(
                "Numeric IP addresses are standard in local network development (e.g. 127.0.0.1, 192.168.x.x), "
                "IoT device dashboards, and temporary direct server testing."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def check_many_hostname_segments(cls, parsed: ParsedURL, min_segments: int = 5) -> Finding:
        """CHECK 4 (Mandatory EWB): Flag five or more hostname segments."""
        host = parsed.hostname or ""
        segments = [seg for seg in host.split(".") if seg]
        count = len(segments)
        detected = count >= min_segments
        evidence = f"Hostname contains {count} dot-separated segments: {segments}" if detected else None

        return Finding(
            check_id="CHECK_4_MANY_SEGMENTS",
            name="Multiple Hostname Segments",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "Phishing links often chain excessive subdomains (e.g., 'login.paypal.com.verify.attacker.invalid') "
                "to deceive users into seeing a trusted brand name early in the link while the actual controlling "
                "domain is at the very end."
            ),
            limitations=(
                "Complex content delivery networks (CDNs), multi-tenant enterprise cloud services, and "
                "regional enterprise subdomains often legitimately possess 5 or more segments."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def check_punycode(cls, parsed: ParsedURL) -> Finding:
        """CHECK 5 (Mandatory EWB): Detect the 'xn--' Punycode marker in hostname."""
        host = (parsed.hostname or "").lower()
        segments = host.split(".")
        punycode_labels = [s for s in segments if s.startswith("xn--")]
        detected = len(punycode_labels) > 0
        evidence = f"Punycode encoded label(s) found: {punycode_labels}" if detected else None

        return Finding(
            check_id="CHECK_5_PUNYCODE",
            name="Punycode Encoded Hostname",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "Punycode ('xn--') allows Internationalized Domain Names (IDNs) in ASCII. Attackers exploit "
                "homograph attacks by substituting visually similar characters from other scripts "
                "to spoof reputable company domains."
            ),
            limitations=(
                "Punycode is an open standard designed to enable non-Latin alphabets (Arabic, Chinese, "
                "Cyrillic, Hindi, etc.) for billions of internet users worldwide. Most Punycode domains are entirely legitimate."
            ),
            agent_name=cls.AGENT_NAME
        )

    # -------------------------------------------------------------
    # ADVANCED HEURISTIC CHECKS (Defensive Intelligence)
    # -------------------------------------------------------------

    @classmethod
    def check_typosquatting(cls, parsed: ParsedURL) -> Finding:
        """ADVANCED CHECK: Detect visual character substitutions and edit-distance typosquatting."""
        host = (parsed.hostname or "").lower()
        segments = host.split(".")
        detected = False
        evidence = None

        if len(segments) >= 2:
            # Inspect the primary domain label (second-level domain)
            sld = segments[-2]
            
            # Check character substitutions (leetspeak: 0 -> o, 1 -> l/i, etc.)
            normalized = sld.replace("0", "o").replace("1", "l").replace("vv", "w")
            
            for brand in cls.TOP_BRANDS:
                # Direct character substitution match (e.g. paypa1 -> paypal, g00gle -> google)
                if normalized == brand and sld != brand:
                    detected = True
                    evidence = f"Character substitution / leetspeak spoof of '{brand}': '{sld}'"
                    break

                # Substring imitation with numbers/hyphens (e.g. amaz0n-login -> amazon)
                cleaned_label = re.sub(r"[^a-z0-9]", "", sld).replace("0", "o").replace("1", "l")
                if brand in cleaned_label and brand not in sld:
                    detected = True
                    evidence = f"Lookalike variant of brand '{brand}' in label '{sld}'"
                    break

                # Edit distance <= 2 for strings >= 7 chars, or 1 for shorter strings (e.g. transposition 'micorsoft' is dist 2 from 'microsoft')
                if len(sld) >= 4 and abs(len(sld) - len(brand)) <= 2:
                    dist = cls._levenshtein(sld, brand)
                    if (dist == 1) or (dist == 2 and len(brand) >= 7 and sorted(sld) == sorted(brand)):
                        detected = True
                        evidence = f"Typosquatting variant of '{brand}': '{sld}' (letter transposition / typo)"
                        break

        return Finding(
            check_id="ADV_TYPOSQUATTING",
            name="Typosquatting & Lookalike Domain",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "Typosquatting exploits typographical mistakes or character similarities (e.g., swapping letters, "
                "substituting '0' for 'o', or '1' for 'l') to lure victims to counterfeit pages mimicking established brands."
            ),
            limitations=(
                "Occasionally, distinct legitimate companies or startup brand names legitimately resemble established words."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def check_misleading_subdomains_and_hyphenation(cls, parsed: ParsedURL) -> Finding:
        """ADVANCED CHECK: Detect brand keywords trapped in subdomains or hyphenated compound phishing names."""
        host = (parsed.hostname or "").lower()
        segments = host.split(".")
        detected = False
        evidence = None

        if len(segments) >= 2:
            registered_domain = ".".join(segments[-2:])
            subdomains = segments[:-2]
            sld = segments[-2]

            # Case A: Brand name appears in subdomains while registered domain is something else
            # e.g. login.microsoft.com.verify-user-access.com -> registered is verify-user-access.com
            for sub in subdomains:
                for brand in cls.TOP_BRANDS:
                    if brand == sub or f"{brand}.com" in host or f"{brand}.org" in host or f"{brand}.net" in host:
                        # Make sure the registered domain isn't actually the genuine brand
                        if not registered_domain.startswith(f"{brand}."):
                            detected = True
                            evidence = (
                                f"Deceptive brand subdomain: '{brand}' appears in subdomains, "
                                f"but the actual controlling domain is '{registered_domain}'"
                            )
                            break
                if detected:
                    break

            # Case B: Compound hyphenated brand + phishing keywords in SLD
            # e.g. microsoft-login-verification.com, secure-paypal-authentication.net
            if not detected and "-" in sld:
                for brand in cls.TOP_BRANDS:
                    if brand in sld:
                        # Check if coupled with phishing keywords
                        matched_keywords = [kw for kw in cls.PHISH_KEYWORDS if kw in sld]
                        if matched_keywords:
                            detected = True
                            evidence = f"Hyphenated brand spoof combining '{brand}' with security keywords: {matched_keywords}"
                            break

        return Finding(
            check_id="ADV_MISLEADING_DOMAIN_STRUCTURE",
            name="Misleading Brand Subdomain / Compound Domain",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "Attackers craft deceptive domains by placing a recognizable brand name early in the subdomain "
                "(e.g., 'microsoft.com.security-check.info') or combining the brand with trust words ('microsoft-login-verification.com'). "
                "Users glancing quickly at the beginning of the URL mistake it for the authentic service."
            ),
            limitations=(
                "Third-party partners, marketing campaign microsites, and authorized contractors occasionally use hyphenated domains."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> List[Finding]:
        return [
            cls.check_ipv4_hostname(parsed),
            cls.check_many_hostname_segments(parsed, min_segments=5),
            cls.check_punycode(parsed),
            cls.check_typosquatting(parsed),
            cls.check_misleading_subdomains_and_hyphenation(parsed)
        ]
