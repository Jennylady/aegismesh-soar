# Actual AD lab user, no invented telemetry. Run elevated on the genuine DC.
param([string]$SamAccountName='aegis-lab-01',[switch]$ConfirmCreate)
$ErrorActionPreference='Stop'
if (-not $ConfirmCreate) { throw 'Explicit -ConfirmCreate required' }
if ($SamAccountName -cnotmatch '^aegis-lab-[a-z0-9-]{1,12}$') { throw 'Use dedicated aegis-lab-* name only' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated administrator required' }
if ([int](Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'Run only on the DC' }
Import-Module ActiveDirectory -ErrorAction Stop
$domain=Get-ADDomain -Server $env:COMPUTERNAME -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.ikom.mg') { throw 'Wrong AD domain' }
$existing=Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -Server $env:COMPUTERNAME
if ($existing) { throw 'Account already exists; refuse to overwrite or reuse it' }
$group=Get-ADGroup -Identity 'AMSOAR-Remediable' -Server $env:COMPUTERNAME -ErrorAction Stop
if ($group.Name -ne 'AEGISMESH-SOAR-Remediable') { throw 'AD scope group mismatch' }
$password=Read-Host 'Strong password for the NEW lab account' -AsSecureString
$user=New-ADUser -Name $SamAccountName -SamAccountName $SamAccountName `
    -UserPrincipalName ($SamAccountName+'@'+$domain.DNSRoot) -Path $domain.UsersContainer `
    -AccountPassword $password -Enabled $true -PasswordNeverExpires:$false `
    -Server $env:COMPUTERNAME -PassThru -ErrorAction Stop
Add-ADGroupMember -Identity $group -Members $user -Server $env:COMPUTERNAME -ErrorAction Stop
$check=Get-ADUser -Identity $user.DistinguishedName -Properties Enabled,MemberOf,adminCount `
    -Server $env:COMPUTERNAME -ErrorAction Stop
if ($check.Enabled -ne $true -or @($check.MemberOf) -notcontains $group.DistinguishedName) {
    throw 'Account created but enablement or scope group membership is not verified'
}
[pscustomobject]@{User=$check.SamAccountName;SID=$check.SID.Value;
    Enabled=$check.Enabled;ScopeGroup=$group.Name;Domain=$domain.DNSRoot} | Format-List
Write-Host 'REAL AD account created and enrolled; not disabled. Save the real SID above.'
