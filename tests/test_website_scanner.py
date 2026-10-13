import unittest
from email.message import Message

from core.website_scanner import WebsiteScanner


class WebsiteScannerTests(unittest.TestCase):
    def test_rejects_non_http_urls_and_credentials(self):
        scanner = WebsiteScanner()
        for url in ("file:///etc/passwd", "ftp://example.com", "https://user:pass@example.com"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                scanner._validate_url(url)

    def test_secure_headers_pass(self):
        headers = Message()
        headers["Content-Type"] = "text/html; charset=utf-8"
        headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        headers["Strict-Transport-Security"] = "max-age=31536000"
        headers["X-Content-Type-Options"] = "nosniff"
        headers["Referrer-Policy"] = "no-referrer"
        headers["Permissions-Policy"] = "camera=()"
        findings = WebsiteScanner()._analyze_response(
            "https://example.com", "https://example.com", 200, headers, b"<html></html>",
            {"valid": True, "protocol": "TLSv1.3", "expires": "Jan 1 00:00:00 2030 GMT"}, None,
        )
        by_id = {row["id"]: row for row in findings}
        self.assertEqual(by_id["tls"]["status"], "pass")
        self.assertEqual(by_id["csp"]["status"], "pass")
        self.assertEqual(by_id["framing"]["status"], "pass")

    def test_missing_headers_are_actionable(self):
        headers = Message()
        headers["Content-Type"] = "text/html"
        findings = WebsiteScanner()._analyze_response(
            "http://example.test", "http://example.test", 200, headers, b"<html></html>", None, None,
        )
        failed = {row["id"] for row in findings if row["status"] in {"fail", "warn"}}
        self.assertTrue({"https", "csp", "nosniff", "framing", "referrer", "permissions"}.issubset(failed))


if __name__ == "__main__":
    unittest.main()
