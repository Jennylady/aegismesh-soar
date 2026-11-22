# Emergency manual rollback only. Never reachable from a SOAR decision or Wazuh AR.
param([Parameter(Mandatory=$true)][ValidatePattern('^am-[0-9a-f]{24}$')][string]$DecisionId,
      [switch]$ConfirmRestore)
$ErrorActionPreference='Stop'
if (-not $ConfirmRestore) { throw 'Explicit -ConfirmRestore required' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
if ([int](Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'Domain Controller required' }
Import-Module ActiveDirectory -ErrorAction Stop
$base=Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $base)) { $base=Join-Path $env:ProgramFiles 'ossec-agent' }
$ledger=Join-Path $base 'active-response\aegismesh-soar-ad-ledger.jsonl'
if (-not (Test-Path -LiteralPath $ledger)) { throw 'No AD SOAR ledger' }
$rows=@(Get-Content -LiteralPath $ledger | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -ErrorAction Stop})
$confirmed=@($rows | Where-Object {$_.decision_id -ceq $DecisionId -and $_.phase -ceq 'disabled'})
if ($confirmed.Count -ne 1) { throw 'No unique verified AEGISMESH disable record for that decision' }
$record=$confirmed[0]
if (@($rows | Where-Object {$_.decision_id -ceq $DecisionId -and $_.phase -ceq 'restored'}).Count) {
    throw 'Decision already restored'
}
$domain=Get-ADDomain -Server $env:COMPUTERNAME -ErrorAction Stop
if ($domain.DNSRoot -ine $record.domain_dns) { throw 'Wrong domain' }
$user=Get-ADUser -Identity $record.user_sid -Server $env:COMPUTERNAME -Properties Enabled -ErrorAction Stop
if ($user.Enabled) { throw 'User already enabled; no action performed' }
Enable-ADAccount -Identity $user.DistinguishedName -Server $env:COMPUTERNAME -Confirm:$false -ErrorAction Stop
$check=Get-ADUser -Identity $record.user_sid -Server $env:COMPUTERNAME -Properties Enabled -ErrorAction Stop
if (-not $check.Enabled) { throw 'Readback failed: account still disabled' }
$entry=[ordered]@{decision_id=$DecisionId;user_sid=$record.user_sid;domain_dns=$domain.DNSRoot;
                    phase='restored';utc=[datetime]::UtcNow.ToString('o')}
[IO.File]::AppendAllText($ledger, (($entry | ConvertTo-Json -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))
Write-Host 'Restored one verified SOAR-disabled AD account.'
Write-Host 'Incident handling and password/session review are still required.'
