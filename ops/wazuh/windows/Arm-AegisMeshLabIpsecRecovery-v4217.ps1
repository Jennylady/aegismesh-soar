# One-time locally run per test on WIN-LAB-01 ONLY, in elevated PowerShell.
# Creates a SYSTEM scheduled task for independent IPsec restoration in 5 minutes.
[CmdletBinding()]
param([ValidateRange(240,480)][int]$RecoveryAfterSeconds = 300)
$ErrorActionPreference = 'Stop'
$computer = Get-CimInstance Win32_ComputerSystem
if ($computer.Name -ne 'WIN-LAB-01' -or $computer.DomainRole -ne 1) {
    throw 'Secours interdit sur cette machine. Uniquement WIN-LAB-01, membre AD.'
}
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'PowerShell administrateur requis.'
}
$task = 'AEGISMESH-LAB-IPSEC-RESTORE'
$now = Get-Date
if ((netsh ipsec static show policy all | Out-String) -match 'VelociraptorQuarantine') {
    throw 'Une politique VelociraptorQuarantine existe deja : armement refuse.'
}
$existing = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
if ($existing) {
    $oldAction = @($existing.Actions)[0]
    $oldInfo = Get-ScheduledTaskInfo -TaskName $task
    $expected = 'Restore-LabIpsec-v4217.ps1'
    if (-not $oldAction.Arguments.Contains($expected) -or
        $existing.State -eq 'Running' -or
        $oldInfo.LastRunTime -le [datetime]'2000-01-01') {
        throw 'Tache de secours existante inconnue, non terminee ou en cours : refus de rearmement.'
    }
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop
}
$root = Join-Path $env:ProgramData 'AEGISMESH-SOAR'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$script = Join-Path $root 'Restore-LabIpsec-v4217.ps1'
@'
$ErrorActionPreference = "Continue"
$hostInfo = Get-CimInstance Win32_ComputerSystem
if ($hostInfo.Name -ne "WIN-LAB-01" -or $hostInfo.DomainRole -ne 1) { exit 5 }
& netsh.exe ipsec static delete policy name=VelociraptorQuarantine | Out-Null
$log = Join-Path $env:ProgramData "AEGISMESH-SOAR\lab-ipsec-recovery.log"
"$(Get-Date -Format o) local recovery attempted, exit=$LASTEXITCODE" | Add-Content $log
'@ | Set-Content -LiteralPath $script -Encoding UTF8 -Force
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $script)
$trigger = New-ScheduledTaskTrigger -Once -At $now.AddSeconds($RecoveryAfterSeconds)
$who = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $who -Description 'AEGISMESH LAB 001 emergency IPsec recovery, one-shot' -ErrorAction Stop | Out-Null
$actual = Get-ScheduledTask -TaskName $task -ErrorAction Stop
if ($actual.State -eq 'Disabled') { throw 'Tache de recuperation desactivee.' }
[PSCustomObject]@{
    Agent = '001'
    Host = $env:COMPUTERNAME
    RecoveryTask = $task
    TaskState = $actual.State.ToString()
    RecoveryAt = $now.AddSeconds($RecoveryAfterSeconds).ToString('o')
    LocalFallbackArmed = $true
    Instructions = 'Sur GCP, direct-start avec --recovery-task-armed; verifiez le retour LDAP apres test.'
} | Format-List
