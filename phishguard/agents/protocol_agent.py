"""Protocol Analysis Agent - Evaluates transport protocol security and port anomalies."""

from typing import List
from ..models import Finding, ParsedURL


class ProtocolAgent:
    """Evaluates protocol schemes, non-standard web ports, and transport security expectations."""

    AGENT_NAME = "Protocol Analysis Agent"

    # Standard web ports
    STANDARD_PORTS = {80, 443}

    @classmethod
    def check_http_scheme(cls, parsed: ParsedURL) -> Finding:
        """CHECK 6 (Mandatory EWB): Identify unencrypted HTTP scheme."""
        scheme = parsed.scheme.lower()
        detected = (scheme == "http")
        evidence = f"Protocol scheme is '{scheme}' (unencrypted plaintext)" if detected else None

        return Finding(
            check_id="CHECK_6_HTTP_SCHEME",
            name="Unencrypted HTTP Scheme",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "Standard HTTP transmits all data--including credentials, session cookies, and form "
                "submissions--in unencrypted cleartext across the network, making it vulnerable to "
                "eavesdropping and man-in-the-middle manipulation."
            ),
            limitations=(
                "Modern phishing campaigns frequently acquire free, valid SSL/TLS certificates (e.g. Let's Encrypt). "
                "Therefore, the presence of HTTPS does NOT prove a website is legitimate or safe."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def check_non_standard_port_or_scheme(cls, parsed: ParsedURL) -> Finding:
        """ADVANCED CHECK: Identify unusual network ports or non-HTTP protocols."""
        detected = False
        evidence = None

        if parsed.port and parsed.port not in cls.STANDARD_PORTS:
            detected = True
            evidence = f"Non-standard web port detected: {parsed.port} (standard ports: 80, 443)"

        scheme = (parsed.scheme or "").lower()
        if scheme and scheme not in {"http", "https"}:
            detected = True
            evidence = f"Unusual protocol scheme detected: '{scheme}://'"

        return Finding(
            check_id="ADV_PROTOCOL_PORT_ANOMALY",
            name="Non-Standard Port or Protocol Scheme",
            detected=detected,
            evidence=evidence,
            why_it_matters=(
                "Phishing servers and command-and-control instances often operate on non-standard ports "
                "(such as 8080, 8443, 8888, 3000) or unusual protocols to evade standard firewall egress filters "
                "and cloud monitoring rules."
            ),
            limitations=(
                "Development servers, internal enterprise administration panels, and alternative services "
                "routinely use high-numbered alternate ports."
            ),
            agent_name=cls.AGENT_NAME
        )

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> List[Finding]:
        return [
            cls.check_http_scheme(parsed),
            cls.check_non_standard_port_or_scheme(parsed)
        ]
