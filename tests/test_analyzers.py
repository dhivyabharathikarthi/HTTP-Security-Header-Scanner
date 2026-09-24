"""Unit tests for individual HTTP security header analyzers."""

import unittest
from app.analyzers.hsts import analyze_hsts
from app.analyzers.csp import analyze_csp
from app.analyzers.content_type import analyze_content_type_options
from app.analyzers.frame_options import analyze_frame_options
from app.analyzers.referrer_policy import analyze_referrer_policy
from app.analyzers.permissions_policy import analyze_permissions_policy
from app.analyzers.cookies import analyze_cookies, parse_single_cookie_header
from app.schemas import FindingStatus, FindingSeverity


class TestHSTSAnalyzer(unittest.TestCase):
    """Tests for HSTS evaluation logic."""

    def test_hsts_missing_on_https(self):
        finding = analyze_hsts({}, is_https=True)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.severity, FindingSeverity.HIGH)
        self.assertEqual(finding.score_contribution, 0)

    def test_hsts_on_http_gives_info(self):
        finding = analyze_hsts({"Strict-Transport-Security": "max-age=31536000"}, is_https=False)
        self.assertEqual(finding.status, FindingStatus.INFO)
        self.assertEqual(finding.score_contribution, 0)
        self.assertIn("plaintext HTTP", finding.message)

    def test_hsts_valid_with_subdomains_and_preload(self):
        headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}
        finding = analyze_hsts(headers, is_https=True)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 2)
        self.assertIn("includeSubDomains enabled", finding.message)

    def test_hsts_short_max_age(self):
        headers = {"Strict-Transport-Security": "max-age=86400"}
        finding = analyze_hsts(headers, is_https=True)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 1)

    def test_hsts_zero_max_age(self):
        headers = {"Strict-Transport-Security": "max-age=0"}
        finding = analyze_hsts(headers, is_https=True)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 0)


class TestCSPAnalyzer(unittest.TestCase):
    """Tests for Content-Security-Policy evaluation logic."""

    def test_csp_missing(self):
        finding = analyze_csp({})
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 0)

    def test_csp_strict_policy(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; frame-ancestors 'self'"
        }
        finding = analyze_csp(headers)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 3)

    def test_csp_with_unsafe_inline(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"
        }
        finding = analyze_csp(headers)
        self.assertIn("unsafe-inline", finding.message)
        self.assertEqual(finding.score_contribution, 2)

    def test_csp_with_wildcard(self):
        headers = {
            "Content-Security-Policy": "default-src *; script-src *"
        }
        finding = analyze_csp(headers)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 1)


class TestContentTypeOptionsAnalyzer(unittest.TestCase):
    """Tests for X-Content-Type-Options evaluation logic."""

    def test_nosniff_present(self):
        headers = {"X-Content-Type-Options": "nosniff"}
        finding = analyze_content_type_options(headers)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 2)

    def test_missing_nosniff(self):
        finding = analyze_content_type_options({})
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 0)

    def test_invalid_nosniff_value(self):
        headers = {"X-Content-Type-Options": "sniff"}
        finding = analyze_content_type_options(headers)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 0)


class TestFrameOptionsAnalyzer(unittest.TestCase):
    """Tests for X-Frame-Options evaluation logic."""

    def test_deny(self):
        headers = {"X-Frame-Options": "DENY"}
        finding = analyze_frame_options(headers)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 2)

    def test_sameorigin(self):
        headers = {"X-Frame-Options": "SAMEORIGIN"}
        finding = analyze_frame_options(headers)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 2)

    def test_missing_but_csp_frame_ancestors_present(self):
        finding = analyze_frame_options({}, csp_raw="default-src 'self'; frame-ancestors 'self'")
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 2)
        self.assertIn("CSP 'frame-ancestors'", finding.message)

    def test_missing_without_csp(self):
        finding = analyze_frame_options({})
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 0)


class TestReferrerPolicyAnalyzer(unittest.TestCase):
    """Tests for Referrer-Policy evaluation logic."""

    def test_strict_origin_when_cross_origin(self):
        headers = {"Referrer-Policy": "strict-origin-when-cross-origin"}
        finding = analyze_referrer_policy(headers)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 1)

    def test_no_referrer(self):
        headers = {"Referrer-Policy": "no-referrer"}
        finding = analyze_referrer_policy(headers)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 1)

    def test_unsafe_url(self):
        headers = {"Referrer-Policy": "unsafe-url"}
        finding = analyze_referrer_policy(headers)
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 0)

    def test_missing_referrer_policy(self):
        finding = analyze_referrer_policy({})
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 0)


class TestPermissionsPolicyAnalyzer(unittest.TestCase):
    """Tests for Permissions-Policy evaluation logic."""

    def test_configured_permissions_policy(self):
        headers = {"Permissions-Policy": "camera=(), microphone=(), geolocation=(self)"}
        finding = analyze_permissions_policy(headers)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 1)

    def test_legacy_feature_policy(self):
        headers = {"Feature-Policy": "camera 'none'; microphone 'none'"}
        finding = analyze_permissions_policy(headers)
        self.assertEqual(finding.status, FindingStatus.PASS)
        self.assertEqual(finding.score_contribution, 1)

    def test_missing_permissions_policy(self):
        finding = analyze_permissions_policy({})
        self.assertEqual(finding.status, FindingStatus.WARN)
        self.assertEqual(finding.score_contribution, 0)


class TestCookieAnalyzer(unittest.TestCase):
    """Tests for Set-Cookie header parser and security evaluation."""

    def test_secure_httponly_samesite_cookie(self):
        raw = "session_id=SECRET123; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
        cookie = parse_single_cookie_header(raw, is_https=True)
        self.assertEqual(cookie.name, "session_id")
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.httponly)
        self.assertEqual(cookie.samesite, "Strict")
        self.assertEqual(cookie.path, "/")
        self.assertEqual(cookie.domain, ".example.com")
        self.assertEqual(cookie.status, FindingStatus.PASS)
        # Verify SECRET123 value is NOT in the object
        self.assertNotIn("SECRET123", str(cookie.model_dump()))

    def test_insecure_cookie_missing_secure_on_https(self):
        raw = "auth_tok=XYZ; HttpOnly; SameSite=Lax"
        cookie = parse_single_cookie_header(raw, is_https=True)
        self.assertFalse(cookie.secure)
        self.assertEqual(cookie.status, FindingStatus.WARN)
        self.assertTrue(any("Missing 'Secure'" in note for note in cookie.notes))


if __name__ == "__main__":
    unittest.main()
