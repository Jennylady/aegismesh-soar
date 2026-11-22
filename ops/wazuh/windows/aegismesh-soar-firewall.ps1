# AEGISMESH-SOAR Wazuh Active Response: time-limited public IPv4 firewall block.
# IMPORTANT: only a remote IP is blocked; no host isolation, AD or service changes.
$ErrorActionPreference = 'Stop'
$created = @()
$taskCreated = $false
$taskName = ''
$phase = 'read_input'
try {
    $line = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) { throw 'Missing Wazuh AR input' }
    $inputObject = $line | ConvertFrom-Json -ErrorAction Stop
    if ($inputObject.command -ne 'add') { throw 'Only Wazuh add accepted' }
    $id = [string]$inputObject.parameters.alert.data.decision_id
    $address = [string]$inputObject.parameters.alert.data.srcip
    if ($id -cnotmatch '^am-[0-9a-f]{24}$') { throw 'Invalid decision identifier' }
    $parsed = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $parsed.ToString() -ne $address) { throw 'Invalid IPv4 address' }
    $b = $parsed.GetAddressBytes()
    # Strict reserved/private exclusion, complementary to manager-side ipcheck.
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or
        $b[0] -ge 224 -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
        ($b[0] -eq 169 -and $b[1] -eq 254) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and $b[1] -eq 168) -or
        ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 0) -or
        ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 2) -or
        ($b[0] -eq 198 -and $b[1] -in @(18,19)) -or
        ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) -or
        ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) {
        throw 'Private, reserved, VPN or test address rejected'
    }
    $phase = 'endpoint_guards'
    $role = [int](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole
    if ($role -ge 4 -and $inputObject.parameters.alert.data.dc_approved -ne $true) {
        throw 'Domain controller requires explicit DC allowlist'
    }
    # Protect current RDP/WinRM/SSH peers on this endpoint, fail closed on query errors.
    $adminPorts = @(22, 3389, 5985, 5986)
    $sessions = @(Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object { $adminPorts -contains [int]$_.LocalPort })
    if ($sessions | Where-Object { $_.RemoteAddress -eq $address -or $_.RemoteAddress -eq ('::ffff:' + $address) }) {
        throw 'Active remote administration peer protected'
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if (-not $profiles -or ($profiles | Where-Object { $_.Enabled -ne $true })) {
        throw 'Windows Firewall profile is disabled'
    }
    $phase = 'schedule_cleanup'
    $taskName = 'AEGISMESH-SOAR-UNBLOCK-' + $id
    $inName = 'AEGISMESH-SOAR-' + $id + '-IN'
    $outName = 'AEGISMESH-SOAR-' + $id + '-OUT'
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw 'Cleanup task already exists'
    }
    foreach ($n in @($inName, $outName)) {
        if (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue) {
            throw 'Rule already exists; no duplicate or overwrite'
        }
    }
    $cleanup = Join-Path $PSScriptRoot 'aegismesh-soar-firewall-cleanup.ps1'
    if (-not (Test-Path -LiteralPath $cleanup)) { throw 'Cleanup component not installed' }
    # The SYSTEM task exists before the first firewall rule, so a process crash
    # cannot turn this 120-second action into a permanent block.
    $executable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $cleanup + '" -DecisionId ' + $id
    $action = New-ScheduledTaskAction -Execute $executable -Argument $arguments
    $deadline = (Get-Date).AddSeconds(120)
    $trigger = New-ScheduledTaskTrigger -Once -At $deadline
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    $taskCreated = $true
    if ((Get-Date) -ge $deadline.AddSeconds(-10)) { throw 'Expiration imminent before firewall action' }
    $phase = 'install_firewall_rules'
    foreach ($item in @(@($inName,'Inbound'), @($outName,'Outbound'))) {
        New-NetFirewallRule -PolicyStore PersistentStore -Name $item[0] -DisplayName $item[0] `
            -Group 'AEGISMESH-SOAR' -Direction $item[1] -Action Block -Enabled True -Profile Any `
            -RemoteAddress $address -Protocol Any -ErrorAction Stop | Out-Null
        $created += $item[0]
    }
    $phase = 'verify_firewall_rules'
    foreach ($n in @($inName, $outName)) {
        $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $n -ErrorAction Stop
        if ($rule.Action -ne 'Block' -or $rule.Enabled -ne 'True') { throw 'Rule not active' }
        $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        if ($address -notin @($filter.RemoteAddress)) { throw 'Rule remote address mismatch' }
    }
    if ((Get-Date) -ge $deadline.AddSeconds(-10)) { throw 'Action expired during firewall verification' }
    # This status means the exact Windows Firewall rules were verified in ActiveStore.
    # It does NOT claim that every network packet was independently observed.
    $phase = 'write_evidence'
    $base = Split-Path -Parent $PSScriptRoot
    $marker = "AEGISMESH-SOAR-WINBLOCK decision_id=$id status=blocked ttl=120`n"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText((Join-Path $base 'aegismesh-soar-evidence.log'), $marker, $utf8)
    [System.IO.File]::AppendAllText((Join-Path $base 'active-responses.log'), $marker, $utf8)
    exit 0
} catch {
    foreach ($n in $created) {
        Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
    }
    if ($taskCreated) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    try {
        $base = Split-Path -Parent $PSScriptRoot
        $reason = $_.Exception.GetType().Name -replace '[^A-Za-z0-9_]', ''
        [System.IO.File]::AppendAllText((Join-Path $base 'aegismesh-soar-errors.log'),
            "$(Get-Date -Format o) WINBLOCK failed phase=$phase type=$reason`n")
    } catch {}
    exit 1
}
