"""Analyzer for X-Frame-Options."""

from typing import Dict
from ..schemas import HeaderFinding, FindingStatus, FindingSeverity

HEADER_NAME = "X-Frame-Options"
MAX_POINTS = 2


def analyze_frame_options(headers: Dict[str, str], csp_raw: str = None) -> HeaderFinding:
    """
    Evaluates the X-Frame-Options header for anti-clickjacking protection.

    Checks:
    - Values: DENY, SAMEORIGIN
    - Compares with modern Content-Security-Policy 'frame-ancestors' directive.
    """
    raw_val = None
    for k, v in headers.items():
        if k.lower() == "x-frame-options":
            raw_val = v.strip()
            break

    has_csp_frame_ancestors = bool(csp_raw and "frame-ancestors" in csp_raw.lower())

    if not raw_val:
        if has_csp_frame_ancestors:
            return HeaderFinding(
                header=HEADER_NAME,
                status=FindingStatus.PASS,
                severity=FindingSeverity.INFO,
                value=None,
                message="X-Frame-Options is omitted, but anti-clickjacking is modernly enforced via CSP 'frame-ancestors'.",
                recommendation="Optionally provide 'X-Frame-Options: DENY' or 'SAMEORIGIN' for legacy user agents that do not support CSP Level 2.",
                score_contribution=MAX_POINTS,
                max_score_contribution=MAX_POINTS
            )
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.MEDIUM,
            value=None,
            message="X-Frame-Options header is missing and no CSP frame-ancestors directive was detected. The page may be embeddable in foreign iframes (clickjacking risk).",
            recommendation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', and configure CSP 'frame-ancestors \\'self\\''.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    val_upper = raw_val.upper()
    if val_upper in ("DENY", "SAMEORIGIN"):
        extra_note = " (Note: modern browsers also honor CSP 'frame-ancestors' if configured)."
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.PASS,
            severity=FindingSeverity.INFO,
            value=raw_val,
            message=f"X-Frame-Options is set to '{val_upper}', mitigating clickjacking attacks{extra_note}",
            recommendation="Ensure your Content-Security-Policy includes matching 'frame-ancestors' directives for modern standards alignment.",
            score_contribution=MAX_POINTS,
            max_score_contribution=MAX_POINTS
        )
    elif val_upper.startswith("ALLOW-FROM"):
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.LOW,
            value=raw_val,
            message="X-Frame-Options uses deprecated 'ALLOW-FROM' directive, which is unsupported in modern browsers (Chrome, Safari, Edge).",
            recommendation="Migrate to CSP 'frame-ancestors <origin>' which is universally supported by modern engines.",
            score_contribution=1,
            max_score_contribution=MAX_POINTS
        )
    else:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.MEDIUM,
            value=raw_val,
            message=f"X-Frame-Options has unrecognized value '{raw_val}'. Valid values are 'DENY' or 'SAMEORIGIN'.",
            recommendation="Set X-Frame-Options to either 'DENY' or 'SAMEORIGIN'.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )
