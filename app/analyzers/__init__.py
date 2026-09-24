"""Aggregator module for executing all security header analyzers."""

from typing import Dict, List, Tuple
from ..schemas import HeaderFinding, CookieFinding, ScoringRule
from .hsts import analyze_hsts
from .csp import analyze_csp
from .content_type import analyze_content_type_options
from .frame_options import analyze_frame_options
from .referrer_policy import analyze_referrer_policy
from .permissions_policy import analyze_permissions_policy
from .cookies import analyze_cookies

SCORING_RULES = [
    ScoringRule(
        header="Content-Security-Policy",
        allocated_points=3,
        description="Mitigates Cross-Site Scripting (XSS), data injections, and restricts resource execution boundaries."
    ),
    ScoringRule(
        header="Strict-Transport-Security",
        allocated_points=2,
        description="Enforces encrypted HTTPS connections and protects against SSL stripping downgrade attacks."
    ),
    ScoringRule(
        header="X-Content-Type-Options",
        allocated_points=2,
        description="Prevents MIME-type sniffing vulnerabilities by forcing browsers to adhere to declared Content-Type."
    ),
    ScoringRule(
        header="X-Frame-Options",
        allocated_points=2,
        description="Provides anti-clickjacking protection by controlling whether the site can be rendered within frames or iframes."
    ),
    ScoringRule(
        header="Referrer-Policy",
        allocated_points=1,
        description="Controls how much referrer information (paths, parameters, query strings) is leaked to external sites."
    ),
    ScoringRule(
        header="Permissions-Policy",
        allocated_points=1,
        description="Restricts browser hardware access (camera, microphone, geolocation) and sensitive feature usage."
    ),
]


def run_all_analyzers(
    headers: Dict[str, str],
    is_https: bool,
    cookie_headers: List[str]
) -> Tuple[List[HeaderFinding], List[CookieFinding], int, int]:
    """
    Executes all modular security analyzers on the collected HTTP headers.

    Returns:
    - List of HeaderFindings
    - List of CookieFindings
    - Total Earned Score
    - Total Maximum Score (11)
    """
    csp_raw = headers.get("content-security-policy", headers.get("Content-Security-Policy"))

    findings: List[HeaderFinding] = [
        analyze_hsts(headers, is_https),
        analyze_csp(headers),
        analyze_content_type_options(headers),
        analyze_frame_options(headers, csp_raw=csp_raw),
        analyze_referrer_policy(headers),
        analyze_permissions_policy(headers),
    ]

    cookie_findings = analyze_cookies(cookie_headers, is_https)

    earned_score = sum(f.score_contribution for f in findings)
    max_score = sum(f.max_score_contribution for f in findings)

    return findings, cookie_findings, earned_score, max_score


__all__ = [
    "run_all_analyzers",
    "analyze_hsts",
    "analyze_csp",
    "analyze_content_type_options",
    "analyze_frame_options",
    "analyze_referrer_policy",
    "analyze_permissions_policy",
    "analyze_cookies",
    "SCORING_RULES",
]
