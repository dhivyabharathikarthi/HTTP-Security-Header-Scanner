"""Analyzer for HTTP response Set-Cookie headers."""

import re
from typing import List
from ..schemas import CookieFinding, FindingStatus, FindingSeverity


def parse_single_cookie_header(cookie_header: str, is_https: bool) -> CookieFinding:
    """
    Parses a single Set-Cookie response header, extracts security attributes,
    and analyzes posture WITHOUT exposing sensitive cookie values.
    """
    parts = [p.strip() for p in cookie_header.split(";") if p.strip()]
    if not parts:
        return CookieFinding(
            name="<empty>",
            secure=False,
            httponly=False,
            notes=["Empty Set-Cookie header encountered."]
        )

    # First part is name=value; we only keep the name
    first_part = parts[0]
    if "=" in first_part:
        cookie_name = first_part.split("=", 1)[0].strip()
    else:
        cookie_name = first_part.strip()

    is_secure = False
    is_httponly = False
    samesite_val = "Omitted"
    path_val = "/"
    domain_val = None
    expires_or_max_age = None
    notes: List[str] = []

    for attr in parts[1:]:
        attr_lower = attr.lower()
        if attr_lower == "secure":
            is_secure = True
        elif attr_lower == "httponly":
            is_httponly = True
        elif attr_lower.startswith("samesite"):
            if "=" in attr:
                samesite_val = attr.split("=", 1)[1].strip()
            else:
                samesite_val = "Present"
        elif attr_lower.startswith("path"):
            if "=" in attr:
                path_val = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain"):
            if "=" in attr:
                domain_val = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("max-age") or attr_lower.startswith("expires"):
            expires_or_max_age = attr.strip()

    # Contextual evaluation
    status = FindingStatus.PASS
    severity = FindingSeverity.INFO

    if is_https and not is_secure:
        status = FindingStatus.WARN
        severity = FindingSeverity.MEDIUM
        notes.append("Missing 'Secure' attribute on HTTPS: cookie may be transmitted over unencrypted HTTP requests or intercepted in downgrade attacks.")

    if not is_httponly:
        # Contextual explanation: for session/auth cookies this is critical, for analytics it's informational
        notes.append("Missing 'HttpOnly' attribute: script access is enabled (accessible via document.cookie, exposing value if XSS occurs).")
        if status != FindingStatus.WARN:
            status = FindingStatus.INFO
            severity = FindingSeverity.LOW

    if samesite_val == "Omitted":
        notes.append("Missing 'SameSite' attribute: modern browsers apply default SameSite=Lax rules, but explicit definition is recommended for predictable CSRF defense.")
    elif samesite_val.lower() == "none" and not is_secure:
        status = FindingStatus.WARN
        severity = FindingSeverity.HIGH
        notes.append("SameSite=None requires the 'Secure' attribute; browsers will reject this cookie.")

    if not notes:
        notes.append("Cookie includes Secure, HttpOnly, and explicit SameSite protections.")

    return CookieFinding(
        name=cookie_name,
        secure=is_secure,
        httponly=is_httponly,
        samesite=samesite_val,
        path=path_val,
        domain=domain_val,
        expires_or_max_age=expires_or_max_age,
        status=status,
        severity=severity,
        notes=notes
    )


def analyze_cookies(cookie_headers: List[str], is_https: bool) -> List[CookieFinding]:
    """Parses and analyzes a list of Set-Cookie header strings."""
    findings = []
    for c_hdr in cookie_headers:
        if c_hdr and isinstance(c_hdr, str):
            findings.append(parse_single_cookie_header(c_hdr, is_https))
    return findings
