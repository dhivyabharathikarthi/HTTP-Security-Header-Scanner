"""Analyzer for Referrer-Policy."""

from typing import Dict
from ..schemas import HeaderFinding, FindingStatus, FindingSeverity

HEADER_NAME = "Referrer-Policy"
MAX_POINTS = 1

SECURE_POLICIES = {
    "no-referrer": "Never sends referrer information (maximum privacy).",
    "strict-origin-when-cross-origin": "Sends full URL to same-origin; sends only origin over HTTPS cross-origin; sends nothing to insecure HTTP (recommended default).",
    "strict-origin": "Sends origin only on HTTPS-to-HTTPS requests; sends nothing to HTTP.",
    "same-origin": "Sends referrer only for same-origin requests; cross-origin requests receive no referrer.",
    "origin": "Always sends only the domain origin (e.g. https://example.com) regardless of destination.",
    "origin-when-cross-origin": "Sends full URL path on same-origin, but only origin on cross-origin.",
}

RISKY_POLICIES = {
    "unsafe-url": "Sends the full URL path and query parameters to all destinations, including third parties and unencrypted HTTP.",
    "no-referrer-when-downgrade": "Sends the full URL to HTTPS origins, but strips referrer when navigating to HTTP (legacy default; may leak sensitive URL parameters)."
}


def analyze_referrer_policy(headers: Dict[str, str]) -> HeaderFinding:
    """
    Evaluates the Referrer-Policy response header.

    Checks:
    - Protection against leakage of path parameters, user IDs, or tokens in Referer headers.
    """
    raw_val = None
    for k, v in headers.items():
        if k.lower() == "referrer-policy":
            raw_val = v.strip()
            break

    if not raw_val:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.LOW,
            value=None,
            message="Referrer-Policy header is missing. Modern browsers default to 'strict-origin-when-cross-origin', but explicit configuration ensures consistent policy across all clients.",
            recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to explicitly control referrer exposure.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    # Values can be comma-separated fallbacks (e.g. "no-referrer-when-downgrade, strict-origin-when-cross-origin")
    tokens = [p.strip().lower() for p in raw_val.split(",") if p.strip()]
    effective_policy = tokens[-1] if tokens else ""

    if effective_policy in SECURE_POLICIES:
        explanation = SECURE_POLICIES[effective_policy]
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.PASS,
            severity=FindingSeverity.INFO,
            value=raw_val,
            message=f"Referrer-Policy is set to '{effective_policy}'. {explanation}",
            recommendation="Maintain this policy to prevent unwanted parameter or path leakage to third parties.",
            score_contribution=MAX_POINTS,
            max_score_contribution=MAX_POINTS
        )
    elif effective_policy in RISKY_POLICIES:
        explanation = RISKY_POLICIES[effective_policy]
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.MEDIUM,
            value=raw_val,
            message=f"Referrer-Policy is set to potentially risky policy '{effective_policy}'. {explanation}",
            recommendation="Upgrade policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )
    else:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.LOW,
            value=raw_val,
            message=f"Referrer-Policy has custom or non-standard token '{effective_policy}'.",
            recommendation="Set to standard 'strict-origin-when-cross-origin'.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )
