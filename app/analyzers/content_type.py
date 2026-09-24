"""Analyzer for X-Content-Type-Options."""

from typing import Dict
from ..schemas import HeaderFinding, FindingStatus, FindingSeverity

HEADER_NAME = "X-Content-Type-Options"
MAX_POINTS = 2


def analyze_content_type_options(headers: Dict[str, str]) -> HeaderFinding:
    """
    Evaluates the X-Content-Type-Options response header.

    Checks:
    - Must be present with the exact value 'nosniff' to prevent MIME type sniffing attacks.
    """
    raw_val = None
    for k, v in headers.items():
        if k.lower() == "x-content-type-options":
            raw_val = v.strip()
            break

    if not raw_val:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.MEDIUM,
            value=None,
            message="X-Content-Type-Options header is missing. Browsers may attempt to sniff MIME types, potentially treating non-executable files as executable scripts.",
            recommendation="Add 'X-Content-Type-Options: nosniff' to all responses.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    if raw_val.lower() == "nosniff":
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.PASS,
            severity=FindingSeverity.INFO,
            value=raw_val,
            message="X-Content-Type-Options is correctly set to 'nosniff', disabling MIME-sniffing.",
            recommendation="Maintain 'nosniff' across all static and dynamic HTTP responses.",
            score_contribution=MAX_POINTS,
            max_score_contribution=MAX_POINTS
        )
    else:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.MEDIUM,
            value=raw_val,
            message=f"X-Content-Type-Options has unexpected value '{raw_val}'. Only 'nosniff' is standard and recognized by browsers.",
            recommendation="Change the header value to 'nosniff'.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )
