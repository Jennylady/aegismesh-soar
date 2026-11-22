# Install only a narrowly scoped Windows Firewall Active Response executor.
# Existing Wazuh/Sysmon/Velociraptor/AD services remain untouched.
param([switch]$DomainController)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$isDC = [int]$computer.DomainRole -ge 4
if ($isDC -and -not $DomainController) { throw 'This is a domain controller: use -DomainController after approval' }
if (-not $isDC -and $DomainController) { throw 'This machine is not a domain controller' }
$base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $base)) { $base = Join-Path $env:ProgramFiles 'ossec-agent' }
$dest = Join-Path $base 'active-response\bin'
if (-not (Test-Path -LiteralPath $dest)) { throw 'Wazuh agent Active Response path not found' }
foreach ($name in @('aegismesh-soar-firewall.cmd', 'aegismesh-soar-firewall.ps1',
                    'aegismesh-soar-firewall-cleanup.ps1',
                    'aegismesh-soar-firewall-status.cmd', 'aegismesh-soar-firewall-status.ps1')) {
    $src = Join-Path $PSScriptRoot $name
    if (-not (Test-Path -LiteralPath $src)) { throw "Missing: $name" }
    Copy-Item -LiteralPath $src -Destination (Join-Path $dest $name) -Force -ErrorAction Stop
}
$svc = Get-Service WazuhSvc -ErrorAction Stop
if ($svc.Status -ne 'Running') { throw 'Wazuh agent is not running' }
$firewall = Get-Service MpsSvc -ErrorAction Stop
if ($firewall.Status -ne 'Running') { throw 'Windows Defender Firewall service is not running' }
Write-Host ('SOAR Windows Firewall Active Response installed. DC=' + $isDC)
Write-Host 'No remote block executed. No Windows service restarted. No AD/GPO change.'
