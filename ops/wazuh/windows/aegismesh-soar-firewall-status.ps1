# Read-only validation of the two SOAR-owned Windows Firewall rules.
$ErrorActionPreference = 'Stop'
try {
    $line = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) { throw 'Missing Wazuh input' }
    $payload = $line | ConvertFrom-Json -ErrorAction Stop
    if ($payload.command -cne 'add') { throw 'Invalid command' }
    $data = $payload.parameters.alert.data
    $decision = [string]$data.decision_id
    $check = [string]$data.check_id
    $address = [string]$data.srcip
    if ($decision -cnotmatch '^am-[0-9a-f]{24}$' -or
        $check -cnotmatch '^am-[0-9a-f]{24}$' -or $check -ceq $decision) {
        throw 'Invalid decision or check ID'
    }
    $ip = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($address, [ref]$ip) -or
        $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $ip.ToString() -cne $address) { throw 'Invalid IPv4' }
    $bytes = $ip.GetAddressBytes()
    if ($bytes[0] -eq 0 -or $bytes[0] -eq 10 -or $bytes[0] -eq 127 -or
        $bytes[0] -ge 224 -or ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) -or
        ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 0) -or
        ($bytes[0] -eq 198 -and $bytes[1] -in @(18,19,51)) -or
        ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113)) { throw 'Reserved address' }
    $result = @()
    foreach ($item in @(@('IN','Inbound'), @('OUT','Outbound'))) {
        $name = 'AEGISMESH-SOAR-' + $decision + '-' + $item[0]
        $rules = @(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        if ($rules.Count -eq 0) { $result += 'absent'; continue }
        if ($rules.Count -ne 1) { throw 'Ambiguous SOAR firewall rule' }
        $rule = $rules[0]
        $f = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        if ($rule.Action -cne 'Block' -or $rule.Enabled -cne 'True' -or
            $rule.Direction -cne $item[1] -or $address -notin @($f.RemoteAddress)) {
            throw 'Firewall rule mismatch or incomplete policy'
        }
        $result += 'blocked'
    }
    if (($result -join ',') -eq 'blocked,blocked') { $state = 'blocked' }
    elseif (($result -join ',') -eq 'absent,absent') { $state = 'removed' }
    else { throw 'Partial firewall rollback' }
    $marker = "AEGISMESH-SOAR-WINSTATE decision_id=$decision check_id=$check status=$state ip=$address`n"
    $base = Split-Path -Parent $PSScriptRoot
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText((Join-Path $base 'aegismesh-soar-evidence.log'), $marker, $utf8)
    [System.IO.File]::AppendAllText((Join-Path $base 'active-responses.log'), $marker, $utf8)
    exit 0
} catch {
    Write-Error ('AEGISMESH-WINSTATE: ' + $_.Exception.GetType().Name)
    exit 2
}
