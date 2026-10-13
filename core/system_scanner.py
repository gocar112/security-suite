"""Read-only Windows posture scanner for the local computer."""

from __future__ import annotations

import json
import platform
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

from .malware_scanner import MalwareScanner
from .patch_manager import PATCHES


class PowerShellRunner:
    """Run fixed read-only PowerShell probes and parse their JSON output."""

    def run_json(self, script: str, timeout: int = 300) -> Dict[str, Any]:
        wrapped = (
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
            "$ProgressPreference = 'SilentlyContinue'; "
            "& {" + script + "} | ConvertTo-Json -Depth 8 -Compress"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", wrapped],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "PowerShell probe failed.").strip()
            raise RuntimeError(detail[:2000])
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("PowerShell returned invalid JSON.") from exc


class SystemScanner:
    """Assess Windows controls, local exposure, updates, and scan readiness."""

    RISKY_PORTS = {
        21: "FTP",
        23: "Telnet",
        135: "Windows RPC",
        139: "NetBIOS",
        445: "SMB",
        1433: "Microsoft SQL Server",
        3306: "MySQL",
        3389: "Remote Desktop",
        5432: "PostgreSQL",
        5900: "VNC",
        5985: "WinRM over HTTP",
        6379: "Redis",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }

    def __init__(
        self,
        runner: PowerShellRunner | None = None,
        malware_scanner: MalwareScanner | None = None,
        platform_name: str | None = None,
    ) -> None:
        self.runner = runner or PowerShellRunner()
        self.malware_scanner = malware_scanner or MalwareScanner()
        self.platform_name = platform_name or platform.system()

    def scan(self, profile: str = "quick") -> Dict[str, Any]:
        if profile not in {"quick", "full"}:
            raise ValueError("System scan profile must be quick or full.")
        started = datetime.now(timezone.utc)
        if self.platform_name != "Windows":
            return {
                "scan_type": "system_posture",
                "profile": profile,
                "timestamp": started.isoformat(),
                "status": "unsupported",
                "score": None,
                "checks": [],
                "summary": {"error": 1, "total": 0},
                "errors": ["Whole-PC posture scanning currently supports Windows only."],
            }

        raw = self.runner.run_json(self._probe_script(include_updates=profile == "full"))
        malware = self.malware_scanner.status()
        checks = self._analyze(raw, malware, include_updates=profile == "full")
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "NONE": 5}
        checks.sort(key=lambda item: (rank.get(item["severity"], 9), item["category"], item["title"]))
        summary = self._summarize(checks)
        score = max(0, 100 - (
            summary["critical"] * 25
            + summary["high"] * 15
            + summary["medium"] * 7
            + summary["low"] * 2
        ))
        completed = datetime.now(timezone.utc)
        os_info = self._first(raw, "os") or {}
        return {
            "scan_type": "system_posture",
            "profile": profile,
            "timestamp": started.isoformat(),
            "completed_at": completed.isoformat(),
            "duration_seconds": round((completed - started).total_seconds(), 3),
            "status": "completed",
            "score": score,
            "summary": summary,
            "machine": {
                "name": raw.get("computerName"),
                "os": os_info.get("Caption"),
                "version": os_info.get("Version"),
                "build": os_info.get("BuildNumber"),
                "last_boot": os_info.get("LastBootUpTime"),
            },
            "checks": checks,
            "inventory": {
                "antivirus_products": self._rows(raw, "antivirus"),
                "malware_scanners": malware,
                "listening_ports": self._rows(raw, "listeners"),
                "installed_software_count": len(self._rows(raw, "software")),
            },
            "coverage": [
                "Microsoft Defender health and signature age",
                "Windows Firewall profiles",
                "SMBv1, UAC, RDP/NLA, LLMNR, AutoRun, Secure Boot, and BitLocker",
                "Remote management services and externally bound listening ports",
                "Pending restart state" + (" and pending Windows software updates" if profile == "full" else ""),
                "Installed Malwarebytes detection and Microsoft Defender scan readiness",
            ],
            "limitations": [
                "This posture scan does not read every file; use Defender or a licensed Malwarebytes scan for malware inspection.",
                "Configuration findings are evidence-based, but application CVEs require product/version matching against vendor data.",
                "Checks blocked by permissions are reported as errors instead of guessed results.",
            ],
        }

    def _analyze(self, raw: Dict[str, Any], malware: Dict[str, Any], include_updates: bool) -> List[Dict[str, Any]]:
        checks: List[Dict[str, Any]] = []

        def add(
            check_id: str,
            title: str,
            category: str,
            status: str,
            severity: str,
            evidence: str,
            remediation: str,
            patch_id: str | None = None,
            reference: str | None = None,
        ) -> None:
            row = {
                "id": check_id,
                "title": title,
                "category": category,
                "status": status,
                "severity": severity,
                "evidence": evidence,
                "remediation": remediation,
                "patch_id": patch_id,
                "reference": reference,
            }
            if patch_id and patch_id in PATCHES:
                row["patch"] = {
                    "title": PATCHES[patch_id]["title"],
                    "requires_admin": True,
                    "restart": PATCHES[patch_id]["restart"],
                }
            checks.append(row)

        antivirus_rows = self._rows(raw, "antivirus")
        alternative_av = [
            str(row.get("displayName")) for row in antivirus_rows
            if row.get("displayName") and "defender" not in str(row.get("displayName")).lower()
        ]
        active_alternative_av = [
            str(row.get("displayName")) for row in antivirus_rows
            if row.get("displayName")
            and "defender" not in str(row.get("displayName")).lower()
            and str(row.get("ProtectionState", "")).upper() == "10"
        ]
        defender = self._first(raw, "defender")
        if defender is None:
            add("defender-status", "Microsoft Defender status readable", "malware defense", "error", "INFO", self._error(raw, "defender"), "Open Windows Security and verify an active antivirus provider.")
        else:
            realtime = self._truthy(defender.get("RealTimeProtectionEnabled"))
            antivirus_enabled = self._truthy(defender.get("AntivirusEnabled"))
            if realtime and antivirus_enabled:
                add("defender-status", "Real-time malware protection", "malware defense", "pass", "NONE", "Microsoft Defender antivirus and real-time protection are enabled.", "No action required.")
            elif active_alternative_av:
                add("defender-status", "Real-time malware protection", "malware defense", "pass", "NONE", "Microsoft Defender is inactive because another provider is active: " + ", ".join(active_alternative_av), "Keep the active provider licensed, updated, and monitored.")
            elif alternative_av:
                add("defender-status", "Real-time malware protection", "malware defense", "warn", "LOW", "Microsoft Defender is inactive; registered alternative with unconfirmed state: " + ", ".join(alternative_av), "Open Windows Security and verify the alternative product is actively protecting the device.")
            else:
                add("defender-status", "Real-time malware protection", "malware defense", "fail", "HIGH", "Microsoft Defender antivirus or real-time protection is disabled, and no alternative provider was identified.", "Enable real-time protection before browsing or opening untrusted files.", "enable_defender_realtime")

            signature_age = self._as_int(defender.get("AntivirusSignatureAge"))
            if not realtime and active_alternative_av:
                add("defender-signatures", "Microsoft Defender signatures current", "malware defense", "info", "INFO", "Defender signature age is not scored while another antivirus provider is active.", "Keep the active antivirus provider's definitions current.")
            elif signature_age is None:
                add("defender-signatures", "Malware signatures current", "malware defense", "error", "INFO", "Defender did not report a signature age.", "Update signatures in Windows Security.")
            elif signature_age <= 3:
                add("defender-signatures", "Malware signatures current", "malware defense", "pass", "NONE", f"Defender signatures are {signature_age} day(s) old.", "No action required.")
            else:
                add("defender-signatures", "Malware signatures current", "malware defense", "fail", "HIGH", f"Defender signatures are {signature_age} day(s) old.", "Update Defender signatures before running a malware scan.", "update_defender_signatures")

            pua = self._as_int(defender.get("PUAProtection"))
            if not realtime and active_alternative_av:
                add("defender-pua", "Microsoft Defender PUA protection", "malware defense", "info", "INFO", "Defender PUA policy is not scored while another antivirus provider is active.", "Verify potentially unwanted application blocking in the active antivirus product.")
            elif pua in {1, 2}:
                add("defender-pua", "Potentially unwanted app blocking", "malware defense", "pass", "NONE", "Defender PUA protection is enabled.", "No action required.")
            elif pua is not None:
                add("defender-pua", "Potentially unwanted app blocking", "malware defense", "warn", "MEDIUM", "Defender PUA protection is not enabled.", "Enable PUA protection to block common adware and bundlers.", "enable_defender_pua")

        firewall_rows = self._rows(raw, "firewall")
        if not firewall_rows:
            add("firewall", "Windows Firewall profiles", "network defense", "error", "INFO", self._error(raw, "firewall"), "Verify Domain, Private, and Public firewall profiles manually.")
        else:
            disabled = [str(row.get("Name")) for row in firewall_rows if not self._truthy(row.get("Enabled"))]
            if disabled:
                add("firewall", "Windows Firewall profiles", "network defense", "fail", "HIGH", "Disabled profiles: " + ", ".join(disabled), "Enable all firewall profiles and then review required inbound exceptions.", "enable_firewall")
            else:
                add("firewall", "Windows Firewall profiles", "network defense", "pass", "NONE", "Domain, Private, and Public profiles are enabled.", "No action required.")

        smb = self._first(raw, "smb")
        if smb is None:
            add("smb1", "SMBv1 disabled", "network defense", "error", "INFO", self._error(raw, "smb"), "Check the SMB1Protocol optional feature from an elevated PowerShell window.")
        else:
            state = str(smb.get("State", "Unknown"))
            if state.lower().startswith("disabled"):
                add("smb1", "SMBv1 disabled", "network defense", "pass", "NONE", f"SMB1Protocol feature state: {state}.", "No action required.")
            else:
                add("smb1", "SMBv1 disabled", "network defense", "fail", "CRITICAL", f"SMB1Protocol feature state: {state}.", "Disable SMBv1 after confirming no legacy dependency remains.", "disable_smb1", "CVE-2017-0144")

        settings = self._first(raw, "settings") or {}
        uac = self._as_int(settings.get("EnableLUA"))
        if uac == 1:
            add("uac", "User Account Control enabled", "identity", "pass", "NONE", "EnableLUA is set to 1.", "No action required.")
        elif uac is None:
            add("uac", "User Account Control enabled", "identity", "error", "INFO", "The UAC policy value could not be read.", "Verify UAC is enabled in Windows Security settings.")
        else:
            add("uac", "User Account Control enabled", "identity", "fail", "HIGH", f"EnableLUA is set to {uac}.", "Enable UAC; Windows must restart to complete this change.", "enable_uac")

        rdp_disabled = self._as_int(settings.get("fDenyTSConnections"))
        nla = self._as_int(settings.get("UserAuthentication"))
        if rdp_disabled == 1:
            add("rdp-nla", "Remote Desktop hardened", "remote access", "pass", "NONE", "Remote Desktop connections are disabled.", "No action required.")
        elif rdp_disabled == 0 and nla == 1:
            add("rdp-nla", "Remote Desktop hardened", "remote access", "warn", "MEDIUM", "Remote Desktop is enabled and requires NLA.", "Restrict RDP to a VPN or trusted firewall allowlist.")
        elif rdp_disabled == 0:
            add("rdp-nla", "Remote Desktop hardened", "remote access", "fail", "HIGH", "Remote Desktop is enabled without confirmed Network Level Authentication.", "Require NLA and restrict source networks.", "enable_rdp_nla")
        else:
            add("rdp-nla", "Remote Desktop hardened", "remote access", "error", "INFO", "Remote Desktop policy values could not be read.", "Review Remote Desktop and NLA settings manually.")

        llmnr = self._as_int(settings.get("EnableMulticast"))
        if llmnr == 0:
            add("llmnr", "LLMNR disabled", "name resolution", "pass", "NONE", "LLMNR is disabled by policy.", "No action required.")
        else:
            evidence = "No policy disables LLMNR, so Windows may answer multicast name-resolution requests." if llmnr is None else f"EnableMulticast is set to {llmnr}."
            add("llmnr", "LLMNR disabled", "name resolution", "warn", "MEDIUM", evidence, "Disable LLMNR to reduce local credential-capture and spoofing risk.", "disable_llmnr")

        autorun = self._as_int(settings.get("NoDriveTypeAutoRun"))
        if autorun == 255:
            add("autorun", "AutoRun disabled for all drives", "device control", "pass", "NONE", "NoDriveTypeAutoRun is set to 255.", "No action required.")
        else:
            evidence = "No machine-wide all-drives AutoRun policy was found." if autorun is None else f"NoDriveTypeAutoRun is set to {autorun}."
            add("autorun", "AutoRun disabled for all drives", "device control", "warn", "LOW", evidence, "Disable AutoRun for removable and network drives.", "disable_autorun")

        secure_boot = self._first_value(raw, "secureBoot")
        if secure_boot is True:
            add("secure-boot", "Secure Boot enabled", "boot integrity", "pass", "NONE", "UEFI Secure Boot is enabled.", "No action required.")
        elif secure_boot is False:
            add("secure-boot", "Secure Boot enabled", "boot integrity", "fail", "HIGH", "UEFI Secure Boot is disabled.", "Enable Secure Boot in firmware after confirming disk and boot compatibility.")
        else:
            add("secure-boot", "Secure Boot enabled", "boot integrity", "error", "INFO", self._error(raw, "secureBoot"), "Confirm firmware mode and Secure Boot status manually.")

        bitlocker = self._first(raw, "bitlocker")
        if bitlocker is None:
            add("bitlocker", "System drive encrypted", "data protection", "error", "INFO", self._error(raw, "bitlocker"), "Check BitLocker status and retain the recovery key before enabling encryption.")
        else:
            protection = str(bitlocker.get("ProtectionStatus", "")).lower()
            encrypted = str(bitlocker.get("VolumeStatus", "")).lower()
            if protection in {"on", "1"} and "fullyencrypted" in encrypted.replace(" ", ""):
                add("bitlocker", "System drive encrypted", "data protection", "pass", "NONE", "BitLocker protection is on and the system volume is fully encrypted.", "No action required.")
            else:
                add("bitlocker", "System drive encrypted", "data protection", "fail", "HIGH", f"ProtectionStatus={bitlocker.get('ProtectionStatus')}; VolumeStatus={bitlocker.get('VolumeStatus')}.", "Back up the recovery key, confirm TPM readiness, and enable BitLocker interactively.")

        services = {str(row.get("Name")): row for row in self._rows(raw, "services")}
        remote_registry = services.get("RemoteRegistry")
        if remote_registry:
            status = str(remote_registry.get("Status", ""))
            start_type = str(remote_registry.get("StartType", ""))
            if status.lower() == "stopped" and start_type.lower() == "disabled":
                add("remote-registry", "Remote Registry disabled", "remote access", "pass", "NONE", "RemoteRegistry is stopped and disabled.", "No action required.")
            elif status.lower() == "running":
                add("remote-registry", "Remote Registry disabled", "remote access", "fail", "HIGH", f"RemoteRegistry is {status} with startup type {start_type}.", "Disable the service unless a documented management dependency requires it.", "disable_remote_registry")
            else:
                add("remote-registry", "Remote Registry disabled", "remote access", "warn", "LOW", f"RemoteRegistry is {status} with startup type {start_type}.", "Consider disabling the service if it is not required.", "disable_remote_registry")

        listeners = self._rows(raw, "listeners")
        exposed = []
        for row in listeners:
            port = self._as_int(row.get("LocalPort"))
            address = str(row.get("LocalAddress", ""))
            if port in self.RISKY_PORTS and address in {"0.0.0.0", "::", "*"}:
                exposed.append(f"{self.RISKY_PORTS[port]} TCP/{port} ({row.get('ProcessName') or 'unknown process'})")
        exposed = list(dict.fromkeys(exposed))
        if exposed:
            add("risky-listeners", "Sensitive services limited to trusted interfaces", "network exposure", "warn", "MEDIUM", "Externally bound listeners: " + "; ".join(exposed[:12]), "Confirm each service is required and restrict its Windows Firewall rule to trusted profiles and addresses.")
        else:
            add("risky-listeners", "Sensitive services limited to trusted interfaces", "network exposure", "pass", "NONE", "No sensitive service in the built-in watchlist was bound to every local interface.", "No action required.")

        pending = self._first_value(raw, "pendingReboot")
        if pending is True:
            add("pending-reboot", "Security changes fully applied", "maintenance", "warn", "LOW", "Windows reports a pending restart.", "Restart Windows during an approved maintenance window.")
        elif pending is False:
            add("pending-reboot", "Security changes fully applied", "maintenance", "pass", "NONE", "No standard pending-restart marker was found.", "No action required.")
        else:
            add("pending-reboot", "Security changes fully applied", "maintenance", "error", "INFO", self._error(raw, "pendingReboot"), "Check Windows Update for a pending restart.")

        if include_updates:
            updates = self._first(raw, "updates")
            if updates is None:
                add("windows-updates", "Windows software updates installed", "patching", "error", "INFO", self._error(raw, "updates"), "Open Windows Update and check for updates.")
            else:
                count = self._as_int(updates.get("Count")) or 0
                if count == 0:
                    add("windows-updates", "Windows software updates installed", "patching", "pass", "NONE", "Windows Update reported no pending software updates.", "No action required.")
                else:
                    titles = updates.get("Titles") or []
                    if isinstance(titles, str):
                        titles = [titles]
                    add("windows-updates", "Windows software updates installed", "patching", "fail", "HIGH", f"Windows Update reported {count} pending software update(s): " + "; ".join(titles[:8]), "Review and install updates through Windows Update, then restart if required.")
        else:
            add("windows-updates", "Windows software updates installed", "patching", "info", "INFO", "Pending-update enumeration is part of the full scan profile.", "Run a full system scan when network access and additional scan time are available.")

        mb = malware.get("malwarebytes", {})
        if mb.get("installed"):
            add("malwarebytes", "Malwarebytes integration ready", "malware defense", "pass", "NONE", f"Detected {mb.get('name')} at {mb.get('path')}.", "Use your licensed Malwarebytes app for a threat or deep scan.")
        else:
            add("malwarebytes", "Malwarebytes integration ready", "malware defense", "info", "INFO", "Malwarebytes was not found in the supported install locations.", "Optionally install and license Malwarebytes from the official site; Microsoft Defender scanning remains available.")
        return checks

    @staticmethod
    def _summarize(checks: List[Dict[str, Any]]) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "pass": 0, "error": 0, "info": 0, "total": len(checks), "actionable": 0, "patchable": 0}
        for row in checks:
            status = row["status"]
            severity = row["severity"].lower()
            if status == "pass":
                summary["pass"] += 1
            elif status == "error":
                summary["error"] += 1
            elif status == "info":
                summary["info"] += 1
            elif severity in summary:
                summary[severity] += 1
                summary["actionable"] += 1
            if row.get("patch_id"):
                summary["patchable"] += 1
        return summary

    @staticmethod
    def _probe_script(include_updates: bool) -> str:
        update_probe = """
$results.updates = Invoke-Probe {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    [pscustomobject]@{ Count = $result.Updates.Count; Titles = @($result.Updates | ForEach-Object { $_.Title }) }
}
""" if include_updates else "$results.updates = [pscustomobject]@{ ok = $true; data = @(); error = $null }"
        return r"""
$ErrorActionPreference = 'Stop'
function Invoke-Probe {
    param([scriptblock]$Script)
    try { [pscustomobject]@{ ok = $true; data = @(& $Script); error = $null } }
    catch { [pscustomobject]@{ ok = $false; data = @(); error = $_.Exception.Message } }
}
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop }
    catch { $null }
}
$results = [ordered]@{ computerName = $env:COMPUTERNAME }
$results.os = Invoke-Probe {
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime
}
$results.defender = Invoke-Probe {
    Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, AntivirusSignatureLastUpdated, PUAProtection, BehaviorMonitorEnabled, IoavProtectionEnabled, IsTamperProtected, QuickScanAge, FullScanAge
}
$results.firewall = Invoke-Probe {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
}
$results.antivirus = Invoke-Probe {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
        $stateHex = '{0:X6}' -f $_.productState
        [pscustomobject]@{
            displayName = $_.displayName
            productState = $_.productState
            ProtectionState = $stateHex.Substring(2, 2)
            SignatureState = $stateHex.Substring(4, 2)
            pathToSignedProductExe = $_.pathToSignedProductExe
        }
    }
}
$results.smb = Invoke-Probe {
    Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State
}
$results.secureBoot = Invoke-Probe {
    try { [bool](Confirm-SecureBootUEFI) }
    catch {
        $registryState = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
        if ($registryState -eq $null) { throw }
        [bool]$registryState
    }
}
$results.bitlocker = Invoke-Probe {
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive
    if ($volume) {
        $volume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod
    } else {
        $escapedDrive = $env:SystemDrive.Replace('\\', '\\\\')
        $cimVolume = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$escapedDrive'"
        if (-not $cimVolume) { throw 'The operating-system volume did not report BitLocker state.' }
        $conversion = switch ($cimVolume.ConversionStatus) { 0 { 'FullyDecrypted' } 1 { 'FullyEncrypted' } default { [string]$cimVolume.ConversionStatus } }
        $protection = switch ($cimVolume.ProtectionStatus) { 0 { 'Off' } 1 { 'On' } default { 'Unknown' } }
        [pscustomobject]@{ MountPoint = $env:SystemDrive; VolumeStatus = $conversion; ProtectionStatus = $protection; EncryptionMethod = $cimVolume.EncryptionMethod }
    }
}
$results.settings = Invoke-Probe {
    [pscustomobject]@{
        EnableLUA = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
        fDenyTSConnections = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        UserAuthentication = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        EnableMulticast = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
        NoDriveTypeAutoRun = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    }
}
$results.services = Invoke-Probe {
    Get-Service -Name RemoteRegistry, WinRM -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Status = $_.Status.ToString(); StartType = $_.StartType.ToString() }
    }
}
$results.listeners = Invoke-Probe {
    Get-NetTCPConnection -State Listen | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; OwningProcess = $_.OwningProcess; ProcessName = $process.ProcessName }
    }
}
$results.pendingReboot = Invoke-Probe {
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations') -ne $null)
    [bool]$pending
}
$results.software = Invoke-Probe {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Sort-Object DisplayName -Unique
}
""" + update_probe + "\n$results\n"

    @staticmethod
    def _probe(raw: Dict[str, Any], name: str) -> Dict[str, Any]:
        value = raw.get(name)
        return value if isinstance(value, dict) else {}

    @classmethod
    def _rows(cls, raw: Dict[str, Any], name: str) -> List[Dict[str, Any]]:
        data = cls._probe(raw, name).get("data", [])
        if data is None:
            return []
        if isinstance(data, dict):
            return [data]
        if not isinstance(data, list):
            return []
        return [row for row in data if isinstance(row, dict)]

    @classmethod
    def _first(cls, raw: Dict[str, Any], name: str) -> Dict[str, Any] | None:
        rows = cls._rows(raw, name)
        return rows[0] if rows else None

    @classmethod
    def _first_value(cls, raw: Dict[str, Any], name: str) -> Any:
        data = cls._probe(raw, name).get("data", [])
        if isinstance(data, list):
            return data[0] if data else None
        return data

    @classmethod
    def _error(cls, raw: Dict[str, Any], name: str) -> str:
        return str(cls._probe(raw, name).get("error") or "The check returned no data.")

    @staticmethod
    def _as_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _truthy(value: Any) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "on"}
        return bool(value)
