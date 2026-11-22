# DC-only non-destructive readiness inspection; NO account modification.
$ErrorActionPreference='Stop'
if ([int](Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'Not a DC' }
Import-Module ActiveDirectory -ErrorAction Stop
$base=Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $base)) { $base=Join-Path $env:ProgramFiles 'ossec-agent' }
$cfg=Join-Path $base 'active-response\aegismesh-soar-ad-policy.json'
if (-not (Test-Path -LiteralPath $cfg)) { throw 'SOAR AD policy not installed' }
$policy=Get-Content -LiteralPath $cfg -Raw | ConvertFrom-Json
$domain=Get-ADDomain -Server $env:COMPUTERNAME -ErrorAction Stop
$g=Get-ADGroup -Identity $policy.allowed_group_sid -Server $env:COMPUTERNAME -ErrorAction Stop
if ($g.Name -cne 'AEGISMESH-SOAR-Remediable' -or $domain.DNSRoot -ine $policy.domain_dns) { throw 'AD policy mismatch' }
$bin=Join-Path $base 'active-response\bin'
foreach($file in @('aegismesh-soar-ad.cmd','aegismesh-soar-ad.ps1','aegismesh-soar-ad-lib.ps1')) {
  if (-not (Test-Path -LiteralPath (Join-Path $bin $file))) { throw ('Missing ' + $file) }
}
[pscustomobject]@{ Domain=$domain.DNSRoot; DomainController=$env:COMPUTERNAME;
  Wazuh=(Get-Service WazuhSvc).Status; ADModuleInstalled=$true;
  EnrolledGroup=$g.Name; GroupSID=$g.SID.Value;
  Enabled=$policy.enabled; AgentExecutorInstalled=$true; AccountModified=$false } | Format-List
