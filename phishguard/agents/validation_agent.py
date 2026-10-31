"""Validation Agent - Responsible for safe parsing, sanitization and normalization."""

from urllib.parse import urlparse
from typing import Tuple, Optional
from ..models import ParsedURL


class ValidationAgent:
    """Validates and parses raw text inputs strictly offline."""

    AGENT_NAME = "Validation Agent"

    @classmethod
    def validate_and_parse(cls, raw_input: str) -> ParsedURL:
        if raw_input is None:
            return ParsedURL(
                raw_url="",
                scheme="",
                netloc="",
                hostname="",
                port=None,
                path="",
                query="",
                fragment="",
                length=0,
                is_valid=False,
                error_message="Input is empty or null."
            )

        stripped = raw_input.strip()
        if not stripped:
            return ParsedURL(
                raw_url=stripped,
                scheme="",
                netloc="",
                hostname="",
                port=None,
                path="",
                query="",
                fragment="",
                length=0,
                is_valid=False,
                error_message="URL cannot be empty or only whitespace."
            )

        # Standardize for parsing if scheme is missing for heuristic safety
        candidate = stripped
        if "://" not in candidate:
            candidate = "http://" + candidate

        try:
            parsed = urlparse(candidate)
            hostname = parsed.hostname or ""
            port = parsed.port
            netloc = parsed.netloc or ""
            scheme = urlparse(stripped).scheme.lower() if "://" in stripped else ""
            
            return ParsedURL(
                raw_url=stripped,
                scheme=scheme,
                netloc=netloc,
                hostname=hostname.lower(),
                port=port,
                path=parsed.path,
                query=parsed.query,
                fragment=parsed.fragment,
                length=len(stripped),
                is_valid=True,
                error_message=None
            )
        except ValueError as ve:
            return ParsedURL(
                raw_url=stripped,
                scheme="",
                netloc="",
                hostname="",
                port=None,
                path="",
                query="",
                fragment="",
                length=len(stripped),
                is_valid=False,
                error_message=f"Malformed URL structure: {str(ve)}"
            )
        except Exception as e:
            return ParsedURL(
                raw_url=stripped,
                scheme="",
                netloc="",
                hostname="",
                port=None,
                path="",
                query="",
                fragment="",
                length=len(stripped),
                is_valid=False,
                error_message=f"Unable to parse URL: {str(e)}"
            )

    @classmethod
    def sanitize_for_audit(cls, parsed: ParsedURL) -> str:
        """Sanitizes URL to protect privacy: removes credentials, queries, and fragments."""
        if not parsed.is_valid:
            return "[INVALID URL INPUT]"
        scheme_prefix = f"{parsed.scheme}://" if parsed.scheme else ""
        host = parsed.hostname or "unknown-host"
        port_suffix = f":{parsed.port}" if parsed.port else ""
        return f"{scheme_prefix}{host}{port_suffix}{parsed.path or '/'}"

