# AEGISMESH-SOAR V4.2.18 — Identification de collecte Velociraptor

## État observé
V4.2.17 a envoyé `collect_client()` sans identifier de `flow_id`. Le bail de ce test a ensuite été supprimé par `direct-clear`, sans preuve réseau. **Ne pas présenter cet essai comme un isolement validé.**

## Corrections
- Parse `flow_id`, `FlowId`, `session_id`, `SessionId` dans la réponse directe de `collect_client()` et en valide la cohérence, le format et l'identité du client si cette dernière est présente.
- Les commandes `direct-doctor` et `direct-status` ajoutent une liste de collectes `Windows.Remediation.Quarantine` en lecture seule. Ce sont des **candidats**, jamais une attribution certaine à l'essai ou une preuve d'effet réseau.
- Le cas sans ID conserve un bail et un diagnostic des noms de champs sans exposer les valeurs de l'API. Aucun renvoi automatique.
- `direct-clear --agent-id 001 --confirm --endpoint-restored` requiert une attestation explicite *après* vérification locale de l'absence de politique et de l'accès réseau. Il conserve le statut non vérifié par le serveur.

## Avant une nouvelle isolation
Sur Windows LAB, en PowerShell administrateur, confirmer `Test-NetConnection 10.77.77.34 -Port 389`, `netsh ipsec static show policy all`, puis `Get-ScheduledTaskInfo -TaskName AEGISMESH-LAB-IPSEC-RESTORE` et le journal local `%ProgramData%\AEGISMESH-SOAR\lab-ipsec-recovery.log`.
Si la tâche a déjà été exécutée, elle doit être armée de nouveau **sur Windows LAB avec accès console indépendant** avant chaque test. Ne pas lancer de nouvelle collecte sur Windows tant que l'état précédent reste incertain.
