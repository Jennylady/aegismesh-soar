# Invoked by a SYSTEM scheduled task 120 seconds after the AR command.
param([Parameter(Mandatory=$true)][string]$DecisionId)
$ErrorActionPreference = 'Stop'
if ($DecisionId -cnotmatch '^am-[0-9a-f]{24}$') { exit 2 }
$inName = 'AEGISMESH-SOAR-' + $DecisionId + '-IN'
$outName = 'AEGISMESH-SOAR-' + $DecisionId + '-OUT'
try {
    foreach ($n in @($inName, $outName)) {
        $rule = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
        if ($rule) { Remove-NetFirewallRule -Name $n -ErrorAction Stop }
        if (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue) { throw 'Cleanup did not remove rule' }
    }
    $base = Split-Path -Parent $PSScriptRoot
    $line = "AEGISMESH-SOAR-WINUNBLOCK decision_id=$DecisionId status=removed`n"
    [System.IO.File]::AppendAllText((Join-Path $base 'aegismesh-soar-evidence.log'),
        $line, (New-Object System.Text.UTF8Encoding($false)))
    exit 0
} catch {
    exit 1
}
