import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.threat_intel import ThreatIntelligence


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, *args):
        return self.payload


class ThreatIntelligenceTests(unittest.TestCase):
    def test_local_cve_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            info = ThreatIntelligence(cache_dir=directory).get_cve_info("cve-2021-44228")
        self.assertTrue(info["found"])
        self.assertEqual(info["severity"], "CRITICAL")
        self.assertTrue(info["known_exploited"])

    def test_kev_only_writeup_has_every_section(self):
        payload = {"vulnerabilities": [{
            "cveID": "CVE-2026-12345",
            "vendorProject": "Vendor",
            "product": "Product",
            "vulnerabilityName": "Test vulnerability",
            "dateAdded": "2026-01-01",
            "dueDate": "2026-01-22",
            "shortDescription": "Defensive test record.",
            "requiredAction": "Apply updates.",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://vendor.example/advisory ; https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        }]}
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "cisa_kev.json").write_text(json.dumps(payload), encoding="utf-8")
            writeup = ThreatIntelligence(cache_dir=directory).format_cve_writeup("CVE-2026-12345")
        for section in ("**What it is**", "**Affected scope**", "**Why it matters**",
                        "**Defensive checks**", "**Remediation**", "**References**"):
            self.assertIn(section, writeup)
        self.assertIn("# CVE-2026-12345 - Test vulnerability", writeup)
        self.assertIn("Vendor Product", writeup)
        self.assertIn("CISA required action: Apply updates.", writeup)
        self.assertIn("ransomware", writeup)
        self.assertIn("https://vendor.example/advisory", writeup)
        self.assertEqual(writeup.count("https://nvd.nist.gov/vuln/detail/CVE-2026-12345"), 1)
        self.assertNotIn("CVSS None", writeup)

    @patch("urllib.request.urlopen")
    def test_live_lookup_drops_exploit_references(self, urlopen):
        urlopen.return_value = FakeResponse({"vulnerabilities": [{"cve": {
            "descriptions": [{"lang": "en", "value": "Test flaw."}],
            "references": [
                {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]},
                {"url": "https://poc.example/exploit", "tags": ["Exploit"]},
                {"url": "http://packetstormsecurity.com/files/1/poc.html"},
            ],
        }}]})
        with tempfile.TemporaryDirectory() as directory:
            info = ThreatIntelligence(cache_dir=directory).get_cve_info("CVE-2026-12345", live=True)
        self.assertEqual(info["references"], ["https://vendor.example/advisory"])

    def test_format_cve_record_matches_writeup(self):
        with tempfile.TemporaryDirectory() as directory:
            intel = ThreatIntelligence(cache_dir=directory)
            record = intel.get_cve_info("CVE-2021-44228")
            self.assertEqual(intel.format_cve_record(record), intel.format_cve_writeup("CVE-2021-44228"))
            missing = intel.format_cve_record({"cve": "CVE-2026-99999", "found": False})
        self.assertIn("No record was available", missing)

    def test_invalid_cve_rejected(self):
        with self.assertRaisesRegex(ValueError, "CVE IDs"):
            ThreatIntelligence().get_cve_info("not-a-cve")

    @patch("urllib.request.urlopen")
    def test_kev_sync_validates_and_caches_feed(self, urlopen):
        payload = {
            "catalogVersion": "test",
            "dateReleased": "2026-01-01",
            "vulnerabilities": [{
                "cveID": "CVE-2026-12345",
                "vendorProject": "Vendor",
                "product": "Product",
                "vulnerabilityName": "Test vulnerability",
                "dateAdded": "2026-01-01",
                "dueDate": "2026-01-22",
                "shortDescription": "Defensive test record.",
                "requiredAction": "Apply updates.",
            }],
        }
        urlopen.return_value = FakeResponse(payload)
        with tempfile.TemporaryDirectory() as directory:
            intel = ThreatIntelligence(cache_dir=directory)
            result = intel.sync_kev()
            cache = Path(directory) / "cisa_kev.json"
            self.assertTrue(cache.exists())
            self.assertEqual(result["count"], 1)
            self.assertEqual(intel.search("Vendor")[0]["cve"], "CVE-2026-12345")


if __name__ == "__main__":
    unittest.main()
