# Shared AD endpoint safeguards. Domain controller only; no remote LDAP credentials.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AegisADContext {
    $role = [int](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
    if ($role -lt 4) { throw 'AEGISMESH AD executor requires a Domain Controller' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $agentBase = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
    if (-not (Test-Path -LiteralPath $agentBase)) { $agentBase = Join-Path $env:ProgramFiles 'ossec-agent' }
    $responseDir = Join-Path $agentBase 'active-response'
    $policyFile = Join-Path $responseDir 'aegismesh-soar-ad-policy.json'
    if (-not (Test-Path -LiteralPath $policyFile)) { throw 'AD endpoint policy missing' }
    $policy = Get-Content -LiteralPath $policyFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($policy.schema -ne 1 -or $policy.enabled -ne $true -or
        [string]$policy.domain_dns -cnotmatch '^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$' -or
        [string]$policy.allowed_group_sid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') {
        throw 'AD endpoint policy invalid or disabled'
    }
    $server = [string]$env:COMPUTERNAME
    $domain = Get-ADDomain -Server $server -ErrorAction Stop
    if ([string]$domain.DNSRoot -ine [string]$policy.domain_dns) { throw 'Unexpected AD domain' }
    $group = Get-ADGroup -Identity ([string]$policy.allowed_group_sid) -Server $server -Properties GroupCategory,GroupScope -ErrorAction Stop
    if ($group.GroupCategory -ne 'Security' -or $group.GroupScope -ne 'Global' -or
        $group.Name -ne 'AEGISMESH-SOAR-Remediable') { throw 'AD opt-in group no longer matches installed policy' }
    return @{ Domain=$domain; Group=$group; Policy=$policy; Server=$server; Dir=$responseDir }
}

function Assert-AegisEligibleADUser([string]$Sid, $Ctx) {
    if ($Sid -cnotmatch '^S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}$') {
        throw 'Invalid user SID'
    }
    $domainSid = [string]$Ctx.Domain.DomainSID.Value
    if (-not $Sid.StartsWith($domainSid + '-', [StringComparison]::Ordinal)) { throw 'Foreign domain SID refused' }
    $rid = [int64]$Sid.Substring($domainSid.Length + 1)
    if ($rid -le 1000) { throw 'Reserved/builtin user SID refused' }
    $user = Get-ADUser -Identity $Sid -Server $Ctx.Server -Properties Enabled,adminCount,ServicePrincipalName,PasswordNeverExpires,TrustedForDelegation,TrustedToAuthForDelegation,PrimaryGroupID,UserAccountControl,DistinguishedName -ErrorAction Stop
    if ([string]$user.SID.Value -cne $Sid) { throw 'AD SID readback mismatch' }
    if (-not $user.Enabled) { throw 'Account is already disabled' }
    if ($user.adminCount -eq 1 -or $user.PasswordNeverExpires -eq $true -or
        $user.TrustedForDelegation -eq $true -or $user.TrustedToAuthForDelegation -eq $true -or
        @($user.ServicePrincipalName | Where-Object { $_ }).Count -gt 0 -or [int]$user.PrimaryGroupID -ne 513 -or
        $user.SamAccountName.EndsWith('$')) { throw 'Protected, privileged or service account refused' }
    # LDAP matching rule in chain enumerates nested group memberships.
    # Escape all LDAP filter metacharacters in the trusted DN returned by AD.
    $dn = [string]$user.DistinguishedName
    $safeDn = $dn.Replace('\', '\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29')
    $ldap = '(member:1.2.840.113556.1.4.1941:=' + $safeDn + ')'
    $groups = @(Get-ADGroup -LDAPFilter $ldap -SearchBase $Ctx.Domain.DistinguishedName -Server $Ctx.Server -Properties adminCount -ErrorAction Stop)
    if (-not $groups.Count) { throw 'User not enrolled in AEGISMESH AD opt-in group' }
    $allowed = $false
    foreach ($g in $groups) {
        $groupSid = [string]$g.SID.Value
        if ($groupSid -eq [string]$Ctx.Group.SID.Value) { $allowed = $true }
        if ($g.adminCount -eq 1 -or $g.Name -match '^(DnsAdmins|Key Admins|Enterprise Key Admins)$' -or
            $groupSid -match '-(512|518|519|520|526|527|544|548|549|550|551|552)$') {
            throw 'Protected or privileged transitive AD group refused'
        }
    }
    if (-not $allowed) { throw 'User outside AEGISMESH AD opt-in group' }
    return $user
}

function Write-AegisADLine([string]$Path, [string]$Line) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText($Path, $Line + "`n", $encoding)
}
