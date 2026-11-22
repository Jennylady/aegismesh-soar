# AEGISMESH-SOAR — read-only AD identity exposure after a real containment.
# DC logs are evidence of authentications, NOT a list of live remote sessions.
param(
  [Parameter(Mandatory=$true)]
  [ValidatePattern('^S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}$')][string]$UserSid,
  [ValidateRange(5,180)][int]$LookbackMinutes = 60
)
$ErrorActionPreference='Stop'
if ([int](Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'Domain Controller required' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
Import-Module ActiveDirectory -ErrorAction Stop
$domain=Get-ADDomain -Server $env:COMPUTERNAME
if ($domain.DNSRoot -ine 'ad.ikom.mg') { throw 'Unexpected domain' }
$user=Get-ADUser -Identity $UserSid -Server $env:COMPUTERNAME -Properties Enabled,PasswordLastSet,LastLogonDate,adminCount,ServicePrincipalName -ErrorAction Stop
if ([string]$user.SID.Value -cne $UserSid) { throw 'User SID mismatch' }
$since=(Get-Date).AddMinutes(-$LookbackMinutes)
# 4624 successful logon at THIS DC; 4768 TGT, 4769 service ticket;
# 4771 failed Kerberos, 4776 NTLM validation.
# Events on other members are NOT queried and active remote sessions cannot be inferred.
try {
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4624,4768,4769,4771,4776); StartTime=$since} `
        -MaxEvents 1500 -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events=@() }
    else { throw 'Security event log unavailable; refusal to report an empty audit' }
}
$matched=@()
foreach ($ev in $events) {
    try {
        $xml=[xml]$ev.ToXml()
        $fields=@{}
        foreach ($field in $xml.Event.EventData.Data) {
            $fields[[string]$field.Name]=[string]$field.'#text'
        }
        # Prefer the immutable SID for 4624 and Kerberos events; for older
        # schemas where it is missing, require both the account name and domain.
        $sidValues=@([string]$fields.TargetUserSid, [string]$fields.TargetSid, [string]$fields.UserSid)
        $actualSid=($sidValues | Where-Object { $_ -ceq $UserSid } | Select-Object -First 1)
        $byName=([string]$fields.TargetUserName -ieq [string]$user.SamAccountName) -and
                (([string]$fields.TargetDomainName -ieq [string]$domain.NetBIOSName) -or
                 ([string]$fields.TargetDomainName -ieq [string]$domain.DNSRoot))
        if (-not $actualSid -and -not $byName) { continue }
        $matched += [pscustomobject]@{
            TimeCreated=$ev.TimeCreated.ToUniversalTime().ToString('o')
            EventId=$ev.Id
            Workstation=[string]$fields.WorkstationName
            ClientAddress=[string]$fields.IpAddress
            Status=[string]$fields.Status
            TargetSid=$UserSid
        }
    } catch {
        continue
    }
}
[pscustomobject]@{
    Domain=$domain.DNSRoot
    Account=$user.SamAccountName
    UserSid=$UserSid
    Enabled=[bool]$user.Enabled
    PasswordLastSet=$user.PasswordLastSet
    LookbackMinutes=$LookbackMinutes
    ExaminedDC=$env:COMPUTERNAME
    ExaminedEventCount=$events.Count
    MatchingSecurityEvents=$matched.Count
    Events=@($matched | Select-Object -First 60)
    Limitation='DC authentication events are historical; they do not prove that current Kerberos tickets or sessions have been revoked. Remote member-host and service tokens require separate checks.'
} | ConvertTo-Json -Depth 5
