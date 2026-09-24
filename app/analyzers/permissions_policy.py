"""Analyzer for Permissions-Policy (formerly Feature-Policy)."""

import re
from typing import Dict, List
from ..schemas import HeaderFinding, FindingStatus, FindingSeverity

HEADER_NAME = "Permissions-Policy"
MAX_POINTS = 1


def analyze_permissions_policy(headers: Dict[str, str]) -> HeaderFinding:
    """
    Evaluates the Permissions-Policy (and legacy Feature-Policy) response headers.

    Checks:
    - Restricts browser APIs such as geolocation, camera, microphone, accelerometer, payments, etc.
    """
    raw_val = None
    header_key = None

    for k, v in headers.items():
        if k.lower() == "permissions-policy":
            raw_val = v.strip()
            header_key = "Permissions-Policy"
            break
        elif k.lower() == "feature-policy" and not raw_val:
            raw_val = v.strip()
            header_key = "Feature-Policy (Legacy)"

    if not raw_val:
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.WARN,
            severity=FindingSeverity.LOW,
            value=None,
            message="Permissions-Policy header is missing. Embedded iframes or scripts could potentially request sensitive hardware APIs (camera, microphone, geolocation) without host restriction.",
            recommendation="Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()' to restrict unused web capabilities.",
            score_contribution=0,
            max_score_contribution=MAX_POINTS
        )

    if header_key == "Feature-Policy (Legacy)":
        return HeaderFinding(
            header=HEADER_NAME,
            status=FindingStatus.PASS,
            severity=FindingSeverity.INFO,
            value=raw_val,
            message="Legacy 'Feature-Policy' header is present. Modern browsers have replaced this with 'Permissions-Policy' structured header syntax.",
            recommendation="Migrate from Feature-Policy to modern Permissions-Policy header syntax (e.g. camera=(), microphone=(), geolocation=()).",
            score_contribution=MAX_POINTS,
            max_score_contribution=MAX_POINTS
        )

    # Parse configured features
    directives = [d.strip() for d in raw_val.split(",") if d.strip()]
    restricted_features = []
    for d in directives:
        match = re.match(r"^([a-zA-Z0-9_-]+)\s*=\s*(.*)$", d)
        if match:
            feature, allowed = match.groups()
            restricted_features.append(f"{feature}={allowed}")
        else:
            restricted_features.append(d)

    summary_str = ", ".join(restricted_features[:5])
    if len(restricted_features) > 5:
        summary_str += f" and {len(restricted_features) - 5} more"

    return HeaderFinding(
        header=HEADER_NAME,
        status=FindingStatus.PASS,
        severity=FindingSeverity.INFO,
        value=raw_val,
        message=f"Permissions-Policy is configured ({summary_str}). Controls execution context access to hardware and browser features.",
        recommendation="Periodically verify that newly introduced browser features (like interest-cohort or web-share) are appropriately governed.",
        score_contribution=MAX_POINTS,
        max_score_contribution=MAX_POINTS
    )
