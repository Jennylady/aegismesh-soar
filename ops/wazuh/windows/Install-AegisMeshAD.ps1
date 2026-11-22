# One-time on actual domain controller in an elevated Windows PowerShell session.
# Creates dedicated opt-in AD group ONLY with -CreateScopeGroup. Never enrolls a user.
param([switch]$CreateScopeGroup)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator' }
if ([int](Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'Domain Controller required' }
Import-Module ActiveDirectory -ErrorAction Stop
$server = [string]$env:COMPUTERNAME
$domain = Get-ADDomain -Server $server -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.ikom.mg') { throw 'Unexpected domain: expected ad.ikom.mg' }
$groupName = 'AEGISMESH-SOAR-Remediable'
$group = Get-ADGroup -Filter { Name -eq $groupName } -SearchBase $domain.DistinguishedName -Server $server -ErrorAction Stop
if (-not $group) {
    if (-not $CreateScopeGroup) { throw 'Dedicated opt-in group absent. Re-run explicitly with -CreateScopeGroup' }
    New-ADGroup -Name $groupName -SamAccountName 'AMSOAR-Remediable' -GroupCategory Security `
        -GroupScope Global -Path $domain.UsersContainer -Server $server -Description 'AEGISMESH SOAR: explicitly enrolled nonprivileged remediation accounts' -ErrorAction Stop
    $group = Get-ADGroup -Filter { Name -eq $groupName } -SearchBase $domain.DistinguishedName -Server $server -ErrorAction Stop
}
if (@($group).Count -ne 1) { throw 'Ambiguous opt-in AD group' }
$group = Get-ADGroup -Identity $group.DistinguishedName -Server $server -Properties GroupCategory,GroupScope -ErrorAction Stop
if ($group.GroupCategory -ne 'Security' -or $group.GroupScope -ne 'Global') { throw 'Wrong group type' }
$base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $base)) { $base = Join-Path $env:ProgramFiles 'ossec-agent' }
$bin = Join-Path $base 'active-response\bin'
$ar = Join-Path $base 'active-response'
if (-not (Test-Path -LiteralPath $bin)) { throw 'Existing Wazuh Active Response agent not found' }
if ((Get-Service WazuhSvc -ErrorAction Stop).Status -ne 'Running') { throw 'Wazuh agent must already be running' }
$serviceAccount = (Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction Stop).StartName
if ($serviceAccount -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) {
    throw 'Wazuh agent must run as LocalSystem for the fixed AD executor'
}
foreach ($name in @('aegismesh-soar-ad.cmd','aegismesh-soar-ad.ps1','aegismesh-soar-ad-lib.ps1')) {
    $src=Join-Path $PSScriptRoot $name
    if (-not (Test-Path -LiteralPath $src)) { throw "Missing installer dependency: $name" }
    $dst=Join-Path $bin $name
    Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
    & icacls.exe $dst /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect AD executor ACL' }
}
$policyPath = Join-Path $ar 'aegismesh-soar-ad-policy.json'
$policy = @{ schema=1; enabled=$true; domain_dns=[string]$domain.DNSRoot; allowed_group_sid=[string]$group.SID.Value }
[IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
# Local policy must not be writable by ordinary domain users.
& icacls.exe $policyPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect endpoint AD policy ACL' }
$ledger=Join-Path $ar 'aegismesh-soar-ad-ledger.jsonl'
if (-not (Test-Path -LiteralPath $ledger)) {
    [IO.File]::WriteAllText($ledger, '', (New-Object System.Text.UTF8Encoding($false)))
}
& icacls.exe $ledger /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect AD audit ledger ACL' }
Write-Host 'AD executor installed on the existing Domain Controller.'
Write-Host ('Domain: ' + $domain.DNSRoot)
Write-Host ('Opt-in group: ' + $group.Name)
Write-Host ('Group SID: ' + $group.SID.Value)
Write-Host 'No user enrolled or disabled. Wazuh/AD services unchanged.'
