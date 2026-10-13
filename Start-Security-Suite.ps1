# Start the loopback-only Security Suite dashboard.
[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8766,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$python = Get-Command python -ErrorAction Stop
Push-Location -LiteralPath $PSScriptRoot
try {
    $suiteArguments = @('.\security_suite.py', 'launch', '--port', "$Port")
    if ($NoBrowser) { $suiteArguments += '--no-browser' }
    & $python.Source @suiteArguments
    if ($LASTEXITCODE -ne 0) { throw 'Security Suite could not start. Review runtime\dashboard.log.' }
} finally {
    Pop-Location
}
