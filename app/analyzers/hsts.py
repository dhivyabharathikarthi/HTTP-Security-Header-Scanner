"""Analyzer for HTTP Strict Transport Security (HSTS)."""

import re
from typing import Dict, Optional
from ..schemas import HeaderFinding, FindingStatus, FindingSeverity

HEADER_NAME = "Strict-Transport-Security"
MAX_POINTS = 2
MIN_RECOMMENDED_MAX_AGE = 15552000  # 180 days (approx 6 months)
IDEAL_MAX_AGE = 31536000             # 1 year


def analyze_hsts(headers: Dict[str, str], is_https: bool) -> HeaderFinding:
    """
    Evaluates the Strict-Transport-Security header value and configuration directives.

    Directives checked:
    - max-age (required, numeric, duration)
    - includeSubDomains (protects child domains)
    - preload (submission to browser hardcoded HSTS lists)
    """
    raw_val = None
    for k, v in headers.items():
        if k.lower() == "strict-transport-security":
            raw_val = v.strip()
            break

    if not is_https:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.INFO,
            severity=FindingSeverity.INFO,
            value=raw_val,
            message="Target URL was requested over insecure plaintext HTTP. HSTS is only valid when served over HTTPS.",
            recommendation="Migrate the endpoint to HTTPS and configure Strict-Transport-Security to prevent SSL stripping.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    if not raw_val:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.HIGH,
            value=None,
            message="Strict-Transport-Security header is missing. Browsers may connect over insecure HTTP if links or bookmarks omit HTTPS.",
            recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS and protect against downgrade attacks.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    # Parse directives
    directives = [d.strip() for d in raw_val.split(";") if d.strip()]
    max_age_match = None
    has_include_subdomains = False
    has_preload = False

    for d in directives:
        lower_d = d.lower()
        if lower_d.startswith("max-age"):
            parts = d.split("=", 1)
            if len(parts) == 2:
                max_age_match = parts[1].strip()
        elif lower_d == "include-subdomains" or lower_d == "includesubdomains":
            has_include_subdomains = True
        elif lower_d == "preload":
            has_preload = True

    if max_age_match is None:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.HIGH,
            value=raw_val,
            message="Strict-Transport-Security is present but missing the required 'max-age' directive.",
            recommendation="Specify a valid max-age directive (e.g. 'max-age=31536000').",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    try:
        max_age_seconds = int(max_age_match.strip("'\""))
    except ValueError:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.HIGH,
            value=raw_val,
            message=f"HSTS 'max-age' value '{max_age_match}' is not a valid integer.",
            recommendation="Ensure max-age is a positive integer in seconds, such as 31536000 (1 year).",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    if max_age_seconds == 0:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.MEDIUM,
            value=raw_val,
            message="HSTS max-age is set to 0, which instructs browsers to expire/disable the HSTS cache.",
            recommendation="Set max-age to at least 31536000 (1 year) for production security.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    if max_age_seconds < MIN_RECOMMENDED_MAX_AGE:
        days = max_age_seconds // 86400
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.LOW,
            value=raw_val,
            message=f"HSTS max-age is short ({max_age_seconds}s / ~{days} days). Best practice recommends at least 6 months to 1 year.",
            recommendation="Increase max-age to at least 31536000 (1 year) once you have verified HTTPS stability.",
            score_contribution=1,
            max_score_contribution=MAX_POINTS
        )

    # Valid HSTS
    details = [f"max-age={max_age_seconds} seconds (~{max_age_seconds // 86400} days)"]
    if has_include_subdomains:
        details.append("includeSubDomains enabled (protects all subdomains)")
    else:
        details.append("includeSubDomains omitted")

    if has_preload:
        details.append("preload directive present (eligible for browser preloaded lists)")

    notes = "; ".join(details)

    recommendations = []
    if not has_include_subdomains:
        recommendations.append("Consider adding 'includeSubDomains' if all subdomains support HTTPS.")
    if has_preload and not has_include_subdomains:
        recommendations.append("Preload eligibility requires 'includeSubDomains' and a minimum max-age of 31536000.")
    if not has_preload and has_include_subdomains and max_age_seconds >= IDEAL_MAX_AGE:
        recommendations.append("If appropriate for your domain, you may submit to the HSTS Preload list (https://hstspreload.org).")
    else:
        recommendations.append("HSTS configuration is robust and securely enforcing encrypted transport.")

    return HeaderFinding(
        header=HEADER_NAME,
        status=FindingStatus.PASS,
        severity=FindingSeverity.INFO,
        value=raw_val,
        message=f"HSTS is securely configured: {notes}.",
        recommendation=" ".join(recommendations),
        score_contribution=MAX_POINTS,
        max_score_contribution=MAX_POINTS
    )
