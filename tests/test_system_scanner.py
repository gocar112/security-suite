import unittest

from core.system_scanner import SystemScanner


def probe(data=None, error=None):
    return {"ok": error is None, "data": [] if data is None else data, "error": error}


class FakeRunner:
    def run_json(self, script, timeout=300):
        self.script = script
        return {
            "computerName": "TEST-PC",
            "os": probe([{"Caption": "Windows Test", "Version": "10", "BuildNumber": "1"}]),
            "defender": probe([{"AntivirusEnabled": False, "RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 65535, "PUAProtection": 0}]),
            "antivirus": probe([{"displayName": "Example AV", "ProtectionState": "10", "SignatureState": "00"}]),
            "firewall": probe([{"Name": "Domain", "Enabled": True}, {"Name": "Private", "Enabled": True}, {"Name": "Public", "Enabled": False}]),
            "smb": probe([{"State": "Disabled"}]),
            "settings": probe([{"EnableLUA": 1, "fDenyTSConnections": 1, "UserAuthentication": 1, "EnableMulticast": 0, "NoDriveTypeAutoRun": 255}]),
            "secureBoot": probe([True]),
            "bitlocker": probe([{"ProtectionStatus": "On", "VolumeStatus": "FullyEncrypted"}]),
            "services": probe([{"Name": "RemoteRegistry", "Status": "Stopped", "StartType": "Disabled"}]),
            "listeners": probe([]),
            "pendingReboot": probe([False]),
            "software": probe([]),
            "updates": probe([]),
        }


class FakeMalware:
    def status(self):
        return {"malwarebytes": {"installed": False}, "defender_available": True}


class SystemScannerTests(unittest.TestCase):
    def test_active_alternative_av_avoids_defender_false_positive(self):
        report = SystemScanner(runner=FakeRunner(), malware_scanner=FakeMalware(), platform_name="Windows").scan("quick")
        by_id = {row["id"]: row for row in report["checks"]}
        self.assertEqual(by_id["defender-status"]["status"], "pass")
        self.assertEqual(by_id["defender-signatures"]["status"], "info")
        self.assertEqual(by_id["firewall"]["severity"], "HIGH")
        self.assertEqual(by_id["remote-registry"]["status"], "pass")

    def test_invalid_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            SystemScanner(runner=FakeRunner(), malware_scanner=FakeMalware(), platform_name="Windows").scan("deepest")


if __name__ == "__main__":
    unittest.main()
