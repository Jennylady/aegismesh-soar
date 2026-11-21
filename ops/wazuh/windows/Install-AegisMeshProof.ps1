# Run in an elevated PowerShell session on WIN-LAB-01 or Windows Server AD.
# Install proof-only AR wrapper; no account, firewall, policy or AD changes.
param([switch]$RestartWazuhAgent)
$ErrorActionPreference = 'Stop'
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($current)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Lancer PowerShell en administrateur'
}
$base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $base)) { $base = Join-Path $env:ProgramFiles 'ossec-agent' }
$dir = Join-Path $base 'active-response\bin'
if (-not (Test-Path -LiteralPath $dir)) { throw 'Agent Wazuh absent : répertoire Active Response introuvable' }
foreach ($name in @('aegismesh-soar-proof.cmd','aegismesh-soar-proof.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $dir $name) -Force
}
Write-Host 'AEGISMESH : exécutable de preuve installé sur ce poste.'
Write-Host 'Aucune action réseau ou AD déclenchée.'
if ($RestartWazuhAgent) {
    $svc = Get-Service -Name WazuhSvc -ErrorAction Stop
    Restart-Service -Name $svc.Name -ErrorAction Stop
    Write-Host 'WazuhSvc redémarré sur cette machine uniquement.'
} else {
    Write-Host 'Si Wazuh ne reconnaît pas le nouvel exécutable, relancer avec -RestartWazuhAgent.'
}
