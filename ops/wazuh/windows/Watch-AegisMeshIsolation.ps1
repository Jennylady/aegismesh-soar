# Windows LAB 001 only. READ-ONLY. Does not change firewall, IPsec, AD or services.
# Start in an elevated PowerShell terminal BEFORE triggering EDR lab-quarantine on GCP.
[CmdletBinding()]
param(
    [string]$DomainController = '10.77.77.34',
    [ValidateRange(30,420)][int]$DurationSeconds = 240,
    [ValidateRange(3,30)][int]$IntervalSeconds = 5
)
$ErrorActionPreference = 'Stop'
$hostInfo = Get-CimInstance Win32_ComputerSystem
if ($env:COMPUTERNAME.ToUpperInvariant() -ne 'WIN-LAB-01' -or $hostInfo.DomainRole -ne 1) {
    throw 'Ce moniteur est réservé à WIN-LAB-01, poste membre du domaine. Contrôleur AD refusé.'
}
$start = Get-Date
$end = $start.AddSeconds($DurationSeconds)
$rows = New-Object System.Collections.Generic.List[object]
$out = Join-Path $env:TEMP ("aegismesh-edr-lab-{0}.csv" -f $start.ToString('yyyyMMdd-HHmmss'))
Write-Host "AEGISMESH surveillance réelle LDAP / IPsec jusqu'à $end"
Write-Host "Journal: $out"
while ((Get-Date) -lt $end) {
    $when = Get-Date
    try {
        $ldap = [bool](Test-NetConnection -ComputerName $DomainController -Port 389 -InformationLevel Quiet -WarningAction SilentlyContinue)
    } catch {
        $ldap = $false
    }
    $policyText = (& netsh ipsec static show policy all 2>&1 | Out-String)
    $ipsec = $policyText.Contains('VelociraptorQuarantine')
    $record = [pscustomobject]@{
        Timestamp = $when.ToString('o')
        LDAP_389_Reachable = $ldap
        IPsecPolicyListed = $ipsec
        Device = $env:COMPUTERNAME
    }
    $rows.Add($record)
    $record | ConvertTo-Json -Compress | Write-Host
    Start-Sleep -Seconds $IntervalSeconds
}
$rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
Write-Host '=== OBSERVATIONS ==='
Write-Host ('LDAP joignable au moins une fois: {0}' -f (@($rows | Where-Object LDAP_389_Reachable).Count -gt 0))
Write-Host ('LDAP injoignable au moins une fois: {0}' -f (@($rows | Where-Object { -not $_.LDAP_389_Reachable }).Count -gt 0))
Write-Host ('IPsec Velociraptor listé au moins une fois: {0}' -f (@($rows | Where-Object IPsecPolicyListed).Count -gt 0))
Write-Host 'Ces observations ne garantissent pas, seules, la cause de la coupure. Corréler au label et aux logs EDR.'
Write-Host "CSV: $out"
