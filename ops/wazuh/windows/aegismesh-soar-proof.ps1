# AEGISMESH Wazuh AR Windows proof - no firewall, user or service changes.
$ErrorActionPreference = 'Stop'
try {
    $line = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) { throw 'Empty AR input' }
    $obj = $line | ConvertFrom-Json -ErrorAction Stop
    if ($obj.command -ne 'add') { throw 'Unsupported Wazuh action' }
    $id = [string]$obj.parameters.extra_args[0]
    if ($id -notmatch '^[A-Za-z0-9_-]{8,64}$') { throw 'Invalid decision ID' }
    $base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
    if (-not (Test-Path -LiteralPath $base)) {
        $base = Join-Path $env:ProgramFiles 'ossec-agent'
    }
    $ar = Join-Path $base 'active-response'
    if (-not (Test-Path -LiteralPath $ar)) { throw 'Wazuh AR directory missing' }
    $rec = [ordered]@{
        event = 'wazuh-active-response-executed'
        proof_id = $id
        command = 'add'
        host = $env:COMPUTERNAME
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
        success = $true
    }
    $record = $rec | ConvertTo-Json -Compress
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText((Join-Path $ar 'aegismesh-soar-proof.jsonl'), ($record + "`n"), $utf8)
    # Default Windows Wazuh agent collects this file; no ossec.conf modification.
    [System.IO.File]::AppendAllText((Join-Path $ar 'active-responses.log'),
        ("AEGISMESH-SOAR-PROOF decision_id=$id status=executed`n"), $utf8)
    exit 0
} catch {
    # Do not log raw payload or secrets.
    try {
        $base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
        $errlog = Join-Path $base 'active-response\aegismesh-soar-errors.log'
        [System.IO.File]::AppendAllText($errlog, "AEGISMESH-SOAR-PROOF failed`n")
    } catch {}
    exit 1
}
