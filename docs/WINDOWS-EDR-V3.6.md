# AEGISMESH-SOAR V3.6 — Windows LAB / Windows Server AD (Wazuh + Windows Firewall)

## Scope

Use existing Shuffle webhook -> bridge -> Wazuh API 4.14 -> Windows agent AR.
The firewall implementation does not replace Velociraptor (open-source DFIR/EDR),
Sysmon or Microsoft Defender. It never disables an AD account or isolates the DC.
Both inbound and outbound rules concern **one public remote IPv4** and are removed
automatically after 120 seconds by a SYSTEM scheduled task, created before rules.

Proof marker: `AEGISMESH-SOAR-WINBLOCK decision_id=am-... status=blocked ttl=120`.
It is written only after verifying both rule directions in Windows Firewall ActiveStore.
Manager Wazuh rules `119872` (block) and `119873` (release) + the already configured evidence logcollector transmit it
with the **correct Wazuh agent ID**. SOAR initially returns `dispatched_unverified`
and switches to `executed` only after manager collection.

Safety gates: actual incident ID, >=2 distinct references, confidence >= .90,
`approved=true`, unexpired decision, verified API TLS, enabled production, explicit
agent allowlist, **public** IPv4, no protected management CIDR or active manager SSH
peer. On endpoint, fail closed for reserved/private IP, current RDP/WinRM/SSH peer,
disabled firewall, unexpected domain controller, missing cleanup task or bad firewall rule.
The incoming incident cannot choose a Windows command, shell script or TTL.

## Publish from Windows PC (`F:\SOUTENANCE\Lady\aegismesh-soar`)

Use PowerShell (not the old Kali `/home/lady/...` paths):

```powershell
Set-Location 'F:\SOUTENANCE\Lady\aegismesh-soar'
Expand-Archive -LiteralPath 'C:\Users\raph\Downloads\AEGISMESH-SOAR-PATCH-V3.6.zip' -DestinationPath . -Force
py -3 bin/aegismesh-soar test
if ($LASTEXITCODE -ne 0) { throw 'Tests failed; do not push' }
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'git diff check failed' }
git add -A
git commit -m 'feat: bounded Windows Wazuh Firewall response and endpoint EDR checks'
git push origin main
```

## Windows endpoint install (run in elevated PowerShell on EACH host)

Download **only** these five files from the same committed GitHub revision
under `ops/wazuh/windows/` into a temp directory; review before executing.

- `Install-AegisMeshFirewall.ps1`
- `aegismesh-soar-firewall.cmd`
- `aegismesh-soar-firewall.ps1`
- `aegismesh-soar-firewall-cleanup.ps1`
- `Get-AegisMeshEDRStatus.ps1` (read-only status)

On WIN-LAB-01: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AegisMeshFirewall.ps1`.
On AD-aws (Domain Controller): `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AegisMeshFirewall.ps1 -DomainController`.
Check `.\Get-AegisMeshEDRStatus.ps1` locally for Wazuh, Windows Firewall, and
Velociraptor services. This does **not** restart or reconfigure Velociraptor.
Wazuh proof collection from V3.5 remains in place; no agent restart needed.

## GCP existing manager

```
aegismesh-soar update
aegismesh-soar fleet evidence install --apply --confirm
aegismesh-soar configure windows-agent 001
aegismesh-soar configure windows-dc-agent 006    # extra interactive approval
aegismesh-soar chain windows-status
aegismesh-soar fleet status
```

`fleet evidence install --apply --confirm` adds only rule `119872`, validates Wazuh,
and restarts the manager to load the new rule (short collection interruption).

Send a real authorized incident with source public IP (illustrative placeholders):

```
aegismesh-soar chain block-windows --agent-id 001 \
  --ip PUBLIC_ATTACK_SOURCE --incident REAL_INCIDENT_ID \
  --evidence REAL_WAZUH_ALERT_ID --evidence DISTINCT_CORRELATED_EVIDENCE_ID \
  --confidence ACTUAL_SCORE_0_TO_1 --confirm
```

Do not execute with fake evidence or production administrator IPs. For a DC, the same
command targets `006` only after both DC opt-ins and a verified noncritical source.

For the resulting decision ID:

```
aegismesh-soar fleet evidence reconcile
aegismesh-soar fleet firewall-status --agent-id 001 --decision-id am-DECISIONID
aegismesh-soar fleet evidence diagnose --agent-id 001 --decision-id am-DECISIONID
```

On the Windows endpoint, confirm `Get-NetFirewallRule -Group AEGISMESH-SOAR`
and the scheduled task `AEGISMESH-SOAR-UNBLOCK-am-...`. Wait over 120s to confirm
removal of that exact rule without touching existing policies. Use the endpoint
`aegismesh-soar-evidence.log` to confirm both block and unblock events.

## Important limitations

- This is a targeted temporary Windows Firewall response, **not host isolation**.
- A Wazuh API 200 only confirms dispatch. A Wazuh-collected matching `WINBLOCK` marker confirms the rule was verified
  locally at creation; a later `WINUNBLOCK` marker confirms removal. Neither
  independently proves packet drops on the wire.
- No Velociraptor API integration is claimed until authenticated Velociraptor
  client/server and API credentials are verified on the existing infrastructure.
- A domain controller is not an appropriate first target for destructive actions.
