# Read-only AEGISMESH SOAR endpoint evidence diagnostic. Run elevated for full logs.
param(
    [string]$DecisionId = ''
)
$ErrorActionPreference = 'Stop'
if ($DecisionId -and $DecisionId -notmatch '^am-[A-Za-z0-9_-]{8,64}$') { throw 'Invalid decision ID' }
$base = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Test-Path -LiteralPath $base)) {
    $base = Join-Path $env:ProgramFiles 'ossec-agent'
}
Write-Host ('Machine: ' + $env:COMPUTERNAME)
if (-not (Test-Path -LiteralPath $base)) { throw 'Agent Wazuh introuvable' }
$svc = Get-Service -Name WazuhSvc -ErrorAction Stop
Write-Host ('Service Wazuh: ' + $svc.Status)
$ar = Join-Path $base 'active-response'
$files = @(
    (Join-Path $ar 'bin\aegismesh-soar-proof.cmd'),
    (Join-Path $ar 'bin\aegismesh-soar-proof.ps1'),
    (Join-Path $ar 'aegismesh-soar-evidence.log'),
    (Join-Path $ar 'aegismesh-soar-proof.jsonl'),
    (Join-Path $ar 'aegismesh-soar-errors.log'),
    (Join-Path $ar 'active-responses.log'),
    (Join-Path $base 'ossec.log')
)
foreach ($f in $files) {
    $exists = Test-Path -LiteralPath $f
    $bytes = if ($exists) { (Get-Item -LiteralPath $f).Length } else { 0 }
    Write-Host ('FILE ' + $exists + ' bytes=' + $bytes + ' ' + $f)
}
$cfg = Join-Path $base 'ossec.conf'
$configured = $false
if (Test-Path -LiteralPath $cfg) {
    $configured = (Select-String -LiteralPath $cfg -Pattern 'aegismesh-soar-evidence.log' -SimpleMatch -Quiet)
}
Write-Host ('Collector evidence configure: ' + $configured)
$proofLog = Join-Path $ar 'aegismesh-soar-evidence.log'
$standardLog = Join-Path $ar 'active-responses.log'
$errorsLog = Join-Path $ar 'aegismesh-soar-errors.log'
$executed = $false
if (Test-Path -LiteralPath $proofLog) {
    Write-Host '--- Dernieres preuves locales ---'
    $recent = @(Get-Content -LiteralPath $proofLog -Tail 80 -ErrorAction Stop)
    $recent | Select-Object -Last 12
    if ($DecisionId) {
        $literal = 'AEGISMESH-SOAR-PROOF decision_id=' + $DecisionId + ' status=executed'
        $executed = (@($recent | Where-Object { $_.Contains($literal) }).Count -gt 0)
    }
}
if ($DecisionId -and -not $executed -and (Test-Path -LiteralPath $standardLog)) {
    $literal = 'AEGISMESH-SOAR-PROOF decision_id=' + $DecisionId + ' status=executed'
    $executed = (@(Get-Content -LiteralPath $standardLog -Tail 100 | Where-Object { $_.Contains($literal) }).Count -gt 0)
    if ($executed) { Write-Host 'Preuve uniquement dans active-responses.log : verifier la collecte du journal dedie.' }
}
if ($DecisionId) { Write-Host ('Preuve locale pour decision ' + $DecisionId + ': ' + $executed) }
if (Test-Path -LiteralPath $errorsLog) {
    Write-Host '--- Erreurs du lanceur, sans charge utile ---'
    Get-Content -LiteralPath $errorsLog -Tail 12
}
$ossec = Join-Path $base 'ossec.log'
if (Test-Path -LiteralPath $ossec) {
    Write-Host '--- Wazuh agent : lignes pertinentes ---'
    Get-Content -LiteralPath $ossec -Tail 300 |
      Where-Object { $_ -match 'execd|active.response|invalid command|aegismesh|error|critical' } |
      Select-Object -Last 20
}
if ($DecisionId -and $executed) {
    Write-Host 'DIAGNOSTIC: action executee localement. Verifier la collecte et le rapprochement sur GCP.'
} elseif ($DecisionId) {
    Write-Host 'DIAGNOSTIC: aucune preuve locale trouvee dans les 80 dernieres lignes. Examiner les erreurs et ossec.log ci-dessus.'
} else {
    Write-Host 'DIAGNOSTIC: preciser -DecisionId pour verifier une decision reelle, sans generer de fausse preuve.'
}
