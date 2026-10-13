"""Generate reviewed PowerShell remediation bundles from known finding IDs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


PATCHES: Dict[str, Dict[str, Any]] = {
    "enable_defender_realtime": {
        "title": "Enable Microsoft Defender real-time protection",
        "restart": False,
        "commands": [
            "Set-MpPreference -DisableRealtimeMonitoring $false",
        ],
        "verify": "(Get-MpComputerStatus).RealTimeProtectionEnabled",
        "test": "(Get-MpComputerStatus).RealTimeProtectionEnabled -eq $true",
    },
    "update_defender_signatures": {
        "title": "Update Microsoft Defender signatures",
        "restart": False,
        "commands": [
            "Update-MpSignature",
        ],
        "verify": "(Get-MpComputerStatus).AntivirusSignatureLastUpdated",
        "test": "(Get-MpComputerStatus).AntivirusSignatureAge -le 1",
    },
    "enable_defender_pua": {
        "title": "Enable Microsoft Defender PUA protection",
        "restart": False,
        "commands": [
            "Set-MpPreference -PUAProtection Enabled",
        ],
        "verify": "(Get-MpPreference).PUAProtection",
        "test": "(Get-MpPreference).PUAProtection -eq 1",
    },
    "enable_firewall": {
        "title": "Enable every Windows Firewall profile",
        "restart": False,
        "commands": [
            "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
        ],
        "verify": "Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize",
        "test": "(@(Get-NetFirewallProfile).Count -eq 3) -and (@(Get-NetFirewallProfile | Where-Object { $_.Enabled -ne $true }).Count -eq 0)",
    },
    "disable_smb1": {
        "title": "Disable the SMBv1 optional feature",
        "restart": True,
        "commands": [
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
        ],
        "verify": "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State",
        "test": "[string](Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State -in @('Disabled', 'DisabledWithPayloadRemoved', 'DisablePending')",
    },
    "enable_uac": {
        "title": "Enable User Account Control",
        "restart": True,
        "commands": [
            "Set-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Type DWord -Value 1",
        ],
        "verify": "Get-ItemPropertyValue -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA",
        "test": "(Get-ItemPropertyValue -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA) -eq 1",
    },
    "enable_rdp_nla": {
        "title": "Require Network Level Authentication for Remote Desktop",
        "restart": False,
        "commands": [
            "Set-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Type DWord -Value 1",
        ],
        "verify": "Get-ItemPropertyValue -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication",
        "test": "(Get-ItemPropertyValue -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication) -eq 1",
    },
    "disable_llmnr": {
        "title": "Disable LLMNR with policy",
        "restart": False,
        "commands": [
            "if (-not (Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient')) { New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT' -Name DNSClient | Out-Null }",
            "Set-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Type DWord -Value 0",
        ],
        "verify": "Get-ItemPropertyValue -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast",
        "test": "(Get-ItemPropertyValue -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast) -eq 0",
        "registry": (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"),
    },
    "disable_autorun": {
        "title": "Disable AutoRun on all drive types",
        "restart": False,
        "commands": [
            "if (-not (Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer')) { New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies' -Name Explorer | Out-Null }",
            "Set-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 255",
        ],
        "verify": "Get-ItemPropertyValue -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun",
        "test": "(Get-ItemPropertyValue -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun) -eq 255",
        "registry": (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"),
    },
    "disable_remote_registry": {
        "title": "Stop and disable the Remote Registry service",
        "restart": False,
        "commands": [
            "Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue",
            "Set-Service -Name RemoteRegistry -StartupType Disabled",
        ],
        "verify": "Get-Service -Name RemoteRegistry | Select-Object Name, Status, StartType",
        "test": "((Get-Service RemoteRegistry).Status -eq 'Stopped') -and ((Get-Service RemoteRegistry).StartType -eq 'Disabled')",
    },
}


def list_patches() -> List[Dict[str, Any]]:
    """Return public metadata without exposing an arbitrary command surface."""
    return [
        {
            "id": patch_id,
            "title": patch["title"],
            "requires_admin": True,
            "restart": patch["restart"],
        }
        for patch_id, patch in PATCHES.items()
    ]


def build_patch_script(patch_ids: Iterable[str]) -> str:
    """Build a PowerShell script from a strict allowlist of patch IDs."""
    selected = list(dict.fromkeys(str(item) for item in patch_ids))
    if not selected:
        raise ValueError("Select at least one patchable finding.")
    unknown = [item for item in selected if item not in PATCHES]
    if unknown:
        raise ValueError("Unknown patch ID: " + ", ".join(unknown))

    generated = datetime.now(timezone.utc).isoformat()
    restart_required = any(PATCHES[item]["restart"] for item in selected)
    lines = [
        "#requires -Version 5.1",
        "# Generated by Security Suite from reviewed, allowlisted remediations.",
        f"# Generated: {generated}",
        "[CmdletBinding()]",
        "param([switch]$Apply, [string]$RollbackFrom)",
        "",
        "# Without -Apply this file only displays the planned changes.",
        "if (-not $Apply) {",
        "    Write-Host 'PREVIEW ONLY. No Windows settings have been changed.'",
        "    if ($RollbackFrom) { Write-Host ('Would restore saved registry policies from: ' + $RollbackFrom); return }",
        *[f"    Write-Host '{PATCHES[item]['title']}'" for item in selected],
        "    Write-Host 'After review, run this script with -Apply from an elevated PowerShell window.'",
        "    return",
        "}",
        "",
        "$ErrorActionPreference = 'Stop'",
        "$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())",
        "$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        "if (-not $isAdmin) { throw 'Run this script from an elevated PowerShell window.' }",
        "",
        "$registryTargets = @{",
        *[f"    '{item}' = @{{ Path = '{PATCHES[item]['registry'][0]}'; Name = '{PATCHES[item]['registry'][1]}' }}"
          for item in selected if PATCHES[item].get("registry")],
        "}",
        REGISTRY_BACKUP_HELPERS,
        "$runDirectory = Join-Path $PSScriptRoot ('SecuritySuite-Backups\\' + [guid]::NewGuid().ToString('N'))",
        "New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null",
        "$logPath = Join-Path $runDirectory 'patch.log'",
        "Start-Transcript -LiteralPath $logPath -Force | Out-Null",
        "try {",
        "    if ($RollbackFrom) { Restore-PolicyBackup $RollbackFrom; return }",
        "    $saved = @(foreach ($id in $registryTargets.Keys) { Read-Policy $id })",
        "    $backupPath = Join-Path $runDirectory 'registry.json'",
        "    @{ Computer = $env:COMPUTERNAME; Entries = $saved } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding UTF8",
        "    Write-Host ('Registry backup: ' + $backupPath)",
        "    Write-Host 'Rollback support covers LLMNR and AutoRun policies only. Other changes need manual recovery.'",
    ]
    for patch_id in selected:
        patch = PATCHES[patch_id]
        lines.extend([
            "",
            f"    Write-Host 'Applying: {patch['title']}' -ForegroundColor Cyan",
        ])
        lines.extend(f"    {command}" for command in patch["commands"])
        lines.extend([
            f"    Write-Host 'Verify: {patch['title']}' -ForegroundColor DarkCyan",
            f"    {patch['verify']}",
            f"    if (-not ({patch['test']})) {{ throw 'Verification failed: {patch['title']}. Review the log and backup before continuing.' }}",
        ])
    lines.extend([
        "",
        f"    $restartRequired = ${str(restart_required).lower()}",
        "    Write-Host ('Patch bundle complete. Log: ' + $logPath) -ForegroundColor Green",
        "    if ($restartRequired) { Write-Warning 'Restart Windows to finish one or more changes.' }",
        "} finally {",
        "    Stop-Transcript | Out-Null",
        "}",
        "",
    ])
    return "\n".join(lines)


REGISTRY_BACKUP_HELPERS = r"""
function Read-Policy {
    param([string]$Id)
    $target = $registryTargets[$Id]
    $present = $false
    $value = $null
    if (Test-Path -LiteralPath $target.Path -ErrorAction Stop) {
        $key = Get-Item -LiteralPath $target.Path -ErrorAction Stop
        $present = $key.GetValueNames() -contains $target.Name
        if ($present) {
            if ($key.GetValueKind($target.Name).ToString() -ne 'DWord') { throw 'Unexpected registry type; no policies were changed.' }
            $value = $key.GetValue($target.Name)
        }
    }
    @{ Id = $Id; Present = [bool]$present; Value = $value }
}

function Restore-PolicyBackup {
    param([string]$BackupPath)
    $backup = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
    if ($backup.Computer -ne $env:COMPUTERNAME) { throw 'Backup belongs to a different computer.' }
    $entries = @($backup.Entries)
    if ($entries.Count -eq 0) { throw 'This backup contains no restorable registry policies.' }
    $seen = @{}
    foreach ($entry in $entries) {
        if (-not $registryTargets.ContainsKey([string]$entry.Id) -or $seen.ContainsKey([string]$entry.Id)) { throw 'Backup contains unsupported or duplicate policies.' }
        $seen[[string]$entry.Id] = $true
        if ($entry.Present -isnot [bool]) { throw 'Invalid registry backup.' }
        if ($entry.Present -and (($entry.Value -isnot [int] -and $entry.Value -isnot [long]) -or $entry.Value -lt -2147483648 -or $entry.Value -gt 2147483647)) { throw 'Invalid registry value in backup.' }
    }
    # Save the current values before rollback so this operation is recoverable too.
    $before = @(foreach ($entry in $entries) { Read-Policy $entry.Id })
    @{ Computer = $env:COMPUTERNAME; Entries = $before } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runDirectory 'before-rollback.json') -Encoding UTF8
    foreach ($entry in $entries) {
        $target = $registryTargets[[string]$entry.Id]
        if ($entry.Present) {
            if (-not (Test-Path -LiteralPath $target.Path)) { New-Item -Path $target.Path -Force | Out-Null }
            New-ItemProperty -LiteralPath $target.Path -Name $target.Name -PropertyType DWord -Value ([int]$entry.Value) -Force | Out-Null
        } elseif ((Read-Policy $entry.Id).Present) {
            Remove-ItemProperty -LiteralPath $target.Path -Name $target.Name
        }
        $restored = Read-Policy $entry.Id
        if ($restored.Present -ne $entry.Present -or ($entry.Present -and $restored.Value -ne $entry.Value)) { throw ('Rollback verification failed for ' + $entry.Id) }
        Write-Host ('Restored: ' + $entry.Id)
    }
    Write-Host 'Registry policies restored. Run a fresh PC scan.'
}
"""
