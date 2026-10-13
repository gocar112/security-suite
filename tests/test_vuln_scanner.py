import unittest
from unittest.mock import patch

from core.vuln_scanner import VulnerabilityScanner


class VulnerabilityScannerTests(unittest.TestCase):
    def test_port_parser_accepts_lists_and_ranges(self):
        scanner = VulnerabilityScanner()
        self.assertEqual(scanner._parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_port_parser_rejects_invalid_values(self):
        scanner = VulnerabilityScanner()
        for expression in ("0", "443-80", "65536", "abc", "80,"):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                scanner._parse_ports(expression)

    def test_public_target_is_rejected_by_default(self):
        with self.assertRaisesRegex(ValueError, "Public targets are disabled"):
            VulnerabilityScanner()._expand_targets("8.8.8.8")

    def test_cidr_safety_limit_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "safety limit"):
            VulnerabilityScanner(max_hosts=16)._expand_targets("192.168.0.0/24")

    @patch.object(VulnerabilityScanner, "_scan_host", return_value=[23, 80])
    def test_scan_reports_exposure_without_fabricated_cves(self, scan_host):
        report = VulnerabilityScanner().scan("127.0.0.1", quick=True)
        self.assertEqual(scan_host.call_count, 1)
        self.assertEqual(report["open_ports"][0]["port"], 23)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["title"], "Telnet service exposed")
        self.assertIsNone(report["findings"][0]["cve"])


if __name__ == "__main__":
    unittest.main()
