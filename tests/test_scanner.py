"""Unit tests for the scanner engine, URL validation, scoring, and database persistence."""

import sqlite3
import unittest
from unittest.mock import patch, MagicMock

from app.utils import validate_and_normalize_url
from app.analyzers import run_all_analyzers
from app.scanner import perform_scan, ScannerError
from app.database import init_db


class TestURLValidation(unittest.TestCase):
    """Tests for safe URL validation and normalization."""

    def test_adds_https_scheme_when_omitted(self):
        url = validate_and_normalize_url("example.com")
        self.assertEqual(url, "https://example.com/")

    def test_preserves_existing_https(self):
        url = validate_and_normalize_url("https://sub.domain.org/path?q=1")
        self.assertEqual(url, "https://sub.domain.org/path?q=1")

    def test_preserves_http_scheme(self):
        url = validate_and_normalize_url("http://example.com/test")
        self.assertEqual(url, "http://example.com/test")

    def test_rejects_empty_url(self):
        with self.assertRaises(ValueError):
            validate_and_normalize_url("")

    def test_rejects_unsupported_schemes(self):
        with self.assertRaises(ValueError):
            validate_and_normalize_url("ftp://example.com")
        with self.assertRaises(ValueError):
            validate_and_normalize_url("javascript:alert(1)")

    def test_rejects_loopback_and_private_ips(self):
        with self.assertRaises(ValueError):
            validate_and_normalize_url("http://127.0.0.1")
        with self.assertRaises(ValueError):
            validate_and_normalize_url("http://10.0.0.1")
        with self.assertRaises(ValueError):
            validate_and_normalize_url("http://192.168.1.1")
        with self.assertRaises(ValueError):
            validate_and_normalize_url("http://localhost:8080")


class TestScoringMethodology(unittest.TestCase):
    """Tests for weighted score calculation."""

    def test_perfect_score_calculation(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()"
        }
        findings, cookies, score, max_score = run_all_analyzers(headers, is_https=True, cookie_headers=[])
        self.assertEqual(max_score, 11)
        self.assertEqual(score, 11)

    def test_partial_score_calculation(self):
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
        }
        findings, cookies, score, max_score = run_all_analyzers(headers, is_https=True, cookie_headers=[])
        self.assertEqual(max_score, 11)
        self.assertEqual(score, 4)  # 2 for Content-Type + 2 for Frame-Options


class TestScannerEngineWithMocks(unittest.TestCase):
    """Tests perform_scan with mocked responses and in-memory SQLite DB."""

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                original_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                score INTEGER NOT NULL,
                max_score INTEGER NOT NULL,
                result_json TEXT NOT NULL
            );
        """)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    @patch("app.scanner._scan_with_urllib")
    def test_mock_successful_scan_with_redirect(self, mock_urllib_scan):
        mock_urllib_scan.return_value = (
            "https://example.com/",
            200,
            [
                MagicMock(step=1, url="http://example.com/", status_code=301, location="https://example.com/"),
                MagicMock(step=2, url="https://example.com/", status_code=200, location=None)
            ],
            {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "SAMEORIGIN",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Content-Security-Policy": "default-src 'self'",
            },
            ["sess=SECRET_TOKEN; Path=/; Secure; HttpOnly; SameSite=Lax"]
        )

        result = perform_scan("http://example.com", db=self.conn)

        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.is_https)
        self.assertEqual(result.score, 11)
        self.assertEqual(result.max_score, 11)
        self.assertEqual(len(result.cookies), 1)
        self.assertEqual(result.cookies[0].name, "sess")
        self.assertTrue(result.cookies[0].secure)

        # Verify DB record
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (result.id,))
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["score"], 11)
        # Ensure secret token value is not exposed
        self.assertNotIn("SECRET_TOKEN", row["result_json"])


if __name__ == "__main__":
    unittest.main()
