"""Analyzer for Content-Security-Policy (CSP)."""

import re
from typing import Dict, List
from ..schemas import HeaderFinding, FindingStatus, FindingSeverity

HEADER_NAME = "Content-Security-Policy"
MAX_POINTS = 3


def parse_csp_directives(csp_str: str) -> Dict[str, List[str]]:
    """Parses a CSP header string into directive names and token lists."""
    directives = {}
    tokens = [t.strip() for t in csp_str.split(";") if t.strip()]
    for token in tokens:
        parts = token.split()
        if parts:
            name = parts[0].lower()
            sources = parts[1:]
            directives[name] = sources
    return directives


def analyze_csp(headers: Dict[str, str]) -> HeaderFinding:
    """
    Evaluates the Content-Security-Policy header configuration.

    Checks:
    - Presence of CSP header
    - 'unsafe-inline' in script-src / default-src
    - 'unsafe-eval' in script-src / default-src
    - Wildcard sources ('*')
    - Fallback 'default-src' directive
    - 'object-src' restriction (Flash/plugin mitigation)
    - 'frame-ancestors' for modern anti-clickjacking
    """
    raw_val = None
    for k, v in headers.items():
        if k.lower() == "content-security-policy":
            raw_val = v.strip()
            break

    if not raw_val:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.HIGH,
            value=None,
            message="Content-Security-Policy header is missing. The browser will not enforce origin boundaries for scripts, styles, objects, and framing.",
            recommendation="Implement a CSP policy starting with 'default-src \\'self\\'; script-src \\'self\\'; object-src \\'none\\'; frame-ancestors \\'self\\''.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    directives = parse_csp_directives(raw_val)
    issues: List[str] = []
    strengths: List[str] = []
    recommendations: List[str] = []
    score_deduction = 0

    has_default_src = "default-src" in directives
    has_script_src = "script-src" in directives or "script-src-elem" in directives
    has_object_src = "object-src" in directives
    has_frame_ancestors = "frame-ancestors" in directives

    # Check default-src
    if not has_default_src:
        issues.append("Missing 'default-src' fallback directive")
        recommendations.append("Define a conservative 'default-src \\'self\\'' to catch undefined asset categories.")
        score_deduction += 1
    else:
        strengths.append("Configured 'default-src'")

    # Inspect all script sources
    script_sources = directives.get("script-src", directives.get("default-src", []))
    script_sources_str = " ".join(script_sources).lower()

    if "'unsafe-inline'" in script_sources_str:
        issues.append("'unsafe-inline' allowed in script execution (reduces XSS mitigation effectiveness)")
        recommendations.append("Replace 'unsafe-inline' with cryptographic nonces (e.g. 'nonce-random') or hashes (sha256-...).")
        score_deduction += 1
    else:
        if has_script_src or has_default_src:
            strengths.append("Restricts inline script execution (no 'unsafe-inline')")

    if "'unsafe-eval'" in script_sources_str:
        issues.append("'unsafe-eval' permitted (enables string-to-code execution like eval())")
        recommendations.append("Refactor code to eliminate eval(), Function(), or setTimeout with string arguments.")
        score_deduction += 1

    # Check for wildcards in script-src or default-src
    for d_name in ["default-src", "script-src"]:
        sources = directives.get(d_name, [])
        if "*" in sources:
            issues.append(f"Wildcard '*' permitted in '{d_name}', allowing resources from any host")
            recommendations.append(f"Replace '*' in '{d_name}' with explicit trusted domain origins.")
            score_deduction += 1

    # Check object-src
    if not has_object_src and ("*" in directives.get("default-src", [])):
        issues.append("Legacy plugins (Flash/Java) not restricted via 'object-src \\'none\\''")
        recommendations.append("Set 'object-src \\'none\\'' to prevent plugin-based exploits.")
    elif has_object_src and "'none'" in [s.lower() for s in directives.get("object-src", [])]:
        strengths.append("'object-src \\'none\\'' configured")

    if has_frame_ancestors:
        strengths.append(f"Modern anti-clickjacking via 'frame-ancestors {' '.join(directives['frame-ancestors'])}'")

    earned_score = max(1, MAX_POINTS - score_deduction)

    if not issues:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.PASS,
            severity=FindingSeverity.INFO,
            value=raw_val,
            message=f"Content-Security-Policy is well structured. Active safeguards: {', '.join(strengths)}.",
            recommendation="Continue reviewing and tightening source domains as application architecture evolves.",
            score_contribution=MAX_POINTS,
            max_score_contribution=MAX_POINTS
        )
    else:
        status = FindingStatus.WARN
        severity = FindingSeverity.HIGH if score_deduction >= 2 else FindingSeverity.MEDIUM
        msg = f"CSP is present with notable observations: {'; '.join(issues)}."
        rec = " ".join(recommendations)
        return HeaderFinding(
            header=HEADER_NAME,
            status=status,
            severity=severity,
            value=raw_val,
            message=msg,
            recommendation=rec,
            score_contribution=earned_score,
            max_score_contribution=MAX_POINTS
        )
