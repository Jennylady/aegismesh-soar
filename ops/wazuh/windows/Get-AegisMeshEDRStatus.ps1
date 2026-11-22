# Read-only endpoint status: Wazuh + Windows Firewall + open-source Velociraptor.
$base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $base)) { $base=Join-Path $env:ProgramFiles 'ossec-agent' }
$services = Get-Service | Where-Object { $_.Name -match 'Wazuh|WinDefend|MpsSvc|Sysmon|Velociraptor' }
$roles = Get-CimInstance Win32_ComputerSystem
$task = @(Get-ScheduledTask -TaskName 'AEGISMESH-SOAR-UNBLOCK-*' -ErrorAction SilentlyContinue)
$rules = @(Get-NetFirewallRule -Group 'AEGISMESH-SOAR' -ErrorAction SilentlyContinue)
[pscustomobject]@{
    Computer=$env:COMPUTERNAME
    DomainController=([int]$roles.DomainRole -ge 4)
    WazuhProofInstalled=(Test-Path (Join-Path $base 'active-response\bin\aegismesh-soar-proof.cmd'))
    FirewallExecutorInstalled=(Test-Path (Join-Path $base 'active-response\bin\aegismesh-soar-firewall.cmd'))
    Services=@($services | Select-Object Name,Status)
    FirewallRuleCount=$rules.Count
    AutomaticUnblockTasks=$task.Count
    ActiveBlockRules=@($rules | Select-Object Name,Enabled)
} | ConvertTo-Json -Depth 4
