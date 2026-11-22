# Wazuh Active Response AD user disable. Real AD action; only on enrolled nonprivileged users.
# JSON is received via stdin and is never evaluated as PowerShell code.
$ErrorActionPreference = 'Stop'
$phase = 'input'
$id = $null
$sid = $null
try {
    $line = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line) -or $line.Length -gt 8192) { throw 'Empty or oversized Wazuh AR input' }
    $request = $line | ConvertFrom-Json -ErrorAction Stop
    if ($request.command -cne 'add') { throw 'Only Wazuh add action supported' }
    $data = $request.parameters.alert.data
    if ($null -eq $data) { throw 'Missing AD payload' }
    if ($data.action -ceq 'check_ready') {
        $id = [string]$data.decision_id
        if ($id -cnotmatch '^am-[0-9a-f]{24}$') { throw 'Invalid readiness probe ID' }
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
            throw 'Readiness probe must run under Wazuh LocalSystem'
        }
        . (Join-Path $PSScriptRoot 'aegismesh-soar-ad-lib.ps1')
        $ctx = Get-AegisADContext
        if ([string]$data.domain_dns -ine [string]$ctx.Policy.domain_dns) { throw 'Unexpected readiness probe domain' }
        $marker = "AEGISMESH-SOAR-ADREADY decision_id=$id status=ready"
        Write-AegisADLine -Path (Join-Path $ctx.Dir 'aegismesh-soar-evidence.log') -Line $marker
        Write-AegisADLine -Path (Join-Path $ctx.Dir 'active-responses.log') -Line $marker
        exit 0
    }
    $isLab = ($data.action -ceq 'lab_disable_account')
    if ($data.action -cne 'disable_account' -and -not $isLab) { throw 'Unsupported AD action' }
    $id = [string]$data.decision_id
    $sid = [string]$data.user_sid
    if ($id -cnotmatch '^am-[0-9a-f]{24}$' -or
        $sid -cnotmatch '^S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}$') { throw 'Invalid decision or user SID' }
    if ($data.approved -cne $true -or
        [string]$data.incident_id -notmatch '^[A-Za-z0-9_.:-]{4,120}$') {
        throw 'Incident ID or approval invalid'
    }
    if ($isLab) {
        if ([string]$data.incident_id -cnotmatch '^AD-LAB-[0-9a-f]{24}$' -or
            [double]$data.confidence -ne 0 -or @($data.evidence_ids).Count -ne 0) {
            throw 'LAB must not impersonate a scored incident'
        }
    } elseif ([double]$data.confidence -lt 0.98 -or
              @($data.evidence_ids | Select-Object -Unique).Count -lt 2) {
        throw 'Incident evidence and confidence invalid'
    }
    $expiry = [datetimeoffset]::MinValue
    $maxExpiry = if ($isLab) { [datetimeoffset]::UtcNow.AddMinutes(5) } else { [datetimeoffset]::UtcNow.AddHours(2) }
    if (-not [datetimeoffset]::TryParse([string]$data.expires_at, [ref]$expiry) -or
        $expiry -le [datetimeoffset]::UtcNow -or
        $expiry -gt $maxExpiry) { throw 'Decision expired or excessive' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
        throw 'AD executor only callable as Wazuh LocalSystem service'
    }
    $phase = 'domain_and_policy'
    . (Join-Path $PSScriptRoot 'aegismesh-soar-ad-lib.ps1')
    $ctx = Get-AegisADContext
    if ([string]$data.domain_dns -ine [string]$ctx.Policy.domain_dns) { throw 'Wrong AD domain requested' }
    $phase = 'eligibility'
    $user = Assert-AegisEligibleADUser -Sid $sid -Ctx $ctx
    if ($isLab -and [string]$user.SamAccountName -cnotmatch '^aegis-lab-[a-z0-9-]{1,12}$') {
        throw 'LAB test may only target a dedicated aegis-lab-* account'
    }
    $ledger = Join-Path $ctx.Dir 'aegismesh-soar-ad-ledger.jsonl'
    # Evidence and ledger are local to the DC; SOAR never receives any password or token.
    $prior = @()
    if (Test-Path -LiteralPath $ledger) {
        $prior = @(Get-Content -LiteralPath $ledger -ErrorAction Stop | Where-Object { $_ } |
            ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
    }
    if (@($prior | Where-Object { $_.decision_id -ceq $id }).Count -gt 0) {
        throw 'Decision ID already processed on this domain controller'
    }
    $entry = [ordered]@{
        decision_id=$id; user_sid=$sid; domain_dns=[string]$ctx.Domain.DNSRoot;
        incident_id=[string]$data.incident_id; lab_test=[bool]$isLab; phase='prepared';
        utc=[datetime]::UtcNow.ToString('o')
    }
    $phase = 'pre_action_audit'
    Write-AegisADLine -Path $ledger -Line ($entry | ConvertTo-Json -Compress)
    $phase = 'disable_account'
    Disable-ADAccount -Identity $user.DistinguishedName -Server $ctx.Server -Confirm:$false -ErrorAction Stop
    $phase = 'verify_ad_readback'
    $again = Get-ADUser -Identity $sid -Server $ctx.Server -Properties Enabled -ErrorAction Stop
    if ([string]$again.SID.Value -cne $sid -or $again.Enabled -ne $false) {
        throw 'AD readback does not confirm account disabled'
    }
    $entry.phase = 'disabled'
    $entry.utc = [datetime]::UtcNow.ToString('o')
    Write-AegisADLine -Path $ledger -Line ($entry | ConvertTo-Json -Compress)
    $phase = 'publish_evidence'
    $marker = "AEGISMESH-SOAR-ADACCOUNT decision_id=$id status=disabled sid=$sid"
    Write-AegisADLine -Path (Join-Path $ctx.Dir 'aegismesh-soar-evidence.log') -Line $marker
    Write-AegisADLine -Path (Join-Path $ctx.Dir 'active-responses.log') -Line $marker
    exit 0
} catch {
    # A failed action is NOT success. Do not auto-enable a possibly compromised account.
    # Audit only the phase and exception type, never the raw request or AD attributes.
    try {
        $base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
        if (-not (Test-Path -LiteralPath $base)) { $base = Join-Path $env:ProgramFiles 'ossec-agent' }
        $errorLog = Join-Path $base 'active-response\aegismesh-soar-errors.log'
        $errorType = $_.Exception.GetType().Name -replace '[^A-Za-z0-9_]', ''
        Write-AegisADLine -Path $errorLog -Line ("AEGISMESH-SOAR-ADERROR phase=$phase type=$errorType")
        if ($id -match '^am-[0-9a-f]{24}$' -and $sid -match '^S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}$') {
            $marker = "AEGISMESH-SOAR-ADFAIL decision_id=$id status=failed sid=$sid phase=$phase"
            Write-AegisADLine -Path (Join-Path $base 'active-response\aegismesh-soar-evidence.log') -Line $marker
        }
    } catch {}
    exit 1
}
