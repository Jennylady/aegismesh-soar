# Run in an elevated PowerShell session on each Windows Wazuh agent.
param([switch]$RestartWazuhAgent, [switch]$EnableCollection)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator' }
$base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $base)) { $base = Join-Path $env:ProgramFiles 'ossec-agent' }
$dir = Join-Path $base 'active-response\bin'
if (-not (Test-Path -LiteralPath $dir)) { throw 'Wazuh agent directory missing' }
foreach ($name in @('aegismesh-soar-proof.cmd','aegismesh-soar-proof.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $dir $name) -Force
}
$ar = Join-Path $base 'active-response'
$logfile = Join-Path $ar 'aegismesh-soar-evidence.log'
if (-not (Test-Path -LiteralPath $logfile)) {
    [System.IO.File]::WriteAllText($logfile, '', (New-Object System.Text.UTF8Encoding($false)))
}
$needsRestart = [bool]$RestartWazuhAgent
if ($EnableCollection) {
    $cfg = Join-Path $base 'ossec.conf'
    if (-not (Test-Path -LiteralPath $cfg)) { throw 'Wazuh ossec.conf missing' }
    $content = [System.IO.File]::ReadAllText($cfg)
    if (-not $content.Contains('aegismesh-soar-evidence.log')) {
        $backup = "$cfg.aegismesh-soar.$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')).bak"
        Copy-Item -LiteralPath $cfg -Destination $backup -Force
        $fragment = @'

<!-- AEGISMESH SOAR - evidence collection only -->
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>C:\Program Files (x86)\ossec-agent\active-response\aegismesh-soar-evidence.log</location>
  </localfile>
</ossec_config>
'@
        # Use the actual installed base in the localfile path, not an assumed Program Files location.
        $fragment = $fragment.Replace('C:\Program Files (x86)\ossec-agent\', ($base.TrimEnd('\') + '\'))
        [System.IO.File]::AppendAllText($cfg, $fragment + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
        $needsRestart = $true
        Write-Host ('SOAR evidence collector added. Backup: ' + $backup)
    } else {
        Write-Host 'SOAR evidence collector already configured'
    }
}
if ($needsRestart) {
    try { Restart-Service -Name WazuhSvc -ErrorAction Stop }
    catch {
        if ($EnableCollection -and $backup) {
            Copy-Item -LiteralPath $backup -Destination $cfg -Force
            Restart-Service -Name WazuhSvc -ErrorAction SilentlyContinue
        }
        throw
    }
    Write-Host 'Wazuh agent service restarted on this endpoint only'
}
Write-Host 'AEGISMESH SOAR endpoint installed. No AD, firewall or account changes.'
