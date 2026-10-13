import unittest
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.patch_manager import PATCHES, build_patch_script


class PatchManagerTests(unittest.TestCase):
    def test_builds_allowlisted_script(self):
        script = build_patch_script(["disable_llmnr", "enable_firewall"])
        self.assertIn("EnableMulticast", script)
        self.assertIn("Set-NetFirewallProfile", script)
        self.assertIn("Run this script from an elevated PowerShell window", script)
        self.assertNotIn("Invoke-Expression", script)

    def test_rejects_unknown_patch(self):
        with self.assertRaisesRegex(ValueError, "Unknown patch ID"):
            build_patch_script(["arbitrary-command"])

    def test_rejects_empty_bundle(self):
        with self.assertRaisesRegex(ValueError, "Select at least one"):
            build_patch_script([])

    @unittest.skipUnless(shutil.which("powershell"), "Windows PowerShell required")
    def test_all_patch_types_parse_and_default_to_preview(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "patch.ps1"
            path.write_text(build_patch_script(PATCHES), encoding="utf-8")
            result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", str(path)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PREVIEW ONLY", result.stdout)
            self.assertFalse((Path(directory) / "SecuritySuite-Backups").exists())

    @unittest.skipUnless(shutil.which("powershell"), "Windows PowerShell required")
    def test_failed_verification_never_reports_success(self):
        # Replace only the privilege check and Defender commands in the test copy.
        # No Windows settings are changed by either success or failure scenario.
        for healthy in [False, True]:
            with self.subTest(healthy=healthy), tempfile.TemporaryDirectory() as directory:
                script = build_patch_script(["enable_defender_realtime"])
                script = script.replace("$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)", "$isAdmin = $true")
                mocks = "function Set-MpPreference { param($DisableRealtimeMonitoring) }\nfunction Get-MpComputerStatus { [pscustomobject]@{ RealTimeProtectionEnabled = $" + str(healthy).lower() + " } }\n"
                script = script.replace("$ErrorActionPreference = 'Stop'", mocks + "$ErrorActionPreference = 'Stop'")
                path = Path(directory) / "mock-patch.ps1"
                path.write_text(script, encoding="utf-8")
                result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", str(path), "-Apply"], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode == 0, healthy, result.stderr)
                self.assertEqual("Patch bundle complete" in result.stdout, healthy)
                if not healthy:
                    self.assertIn("Verification failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
