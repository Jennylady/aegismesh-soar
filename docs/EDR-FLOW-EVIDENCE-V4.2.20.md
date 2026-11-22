# V4.2.20 — Lecture des résultats de la collecte EDR

## Constat réel

Windows LAB 001 a exécuté `F.DC1KC83C11SSI` (artefact `Windows.Remediation.Quarantine`, état `FINISHED`, `total_collected_rows=16`). La V4.2.19 affichait `results_present=false` parce que la collecte de quarantaine n'était pas incluse dans les artefacts pris en charge par `flow-status`, et non parce qu'une absence de résultats avait été constatée.

## Lecture sûre, sans nouvel isolement

```bash
aegismesh-soar update
aegismesh-soar edr lab-quarantine direct-evidence --agent-id 001 --flow-id F.DC1KC83C11SSI
aegismesh-soar edr flow-status --agent-id 001 --flow-id F.DC1KC83C11SSI
```

Cette commande interroge `flow_results()` via l'API mTLS, avec FlowId et ClientId validés, artefact exact et 100 lignes maximum. Elle refuse tout autre agent/artefact. Elle n'accorde aucun droit `EXECVE`, ne lance aucun flow, ne modifie aucun service ni aucune politique réseau.

`policy_applied_reported`, `frontend_check_success_reported`, `policy_removed_reported` sont des **constats sur les messages de l'artefact** uniquement. `endpoint_network_isolation_verified` reste `false` tant qu'aucune mesure de paquets pendant l'isolement ne le confirme.

## Nettoyage d'un bail SOAR déjà restauré localement

Seulement après vérification sur WIN-LAB-01 que `LDAP_389=True`, `Velociraptor_8000=True`, `QuarantineIPsec=False`, et secours local `RecoveryResult=0` :

```bash
aegismesh-soar edr lab-quarantine direct-clear --agent-id 001 --confirm --endpoint-restored
```

Cette opération supprime uniquement le bail local SOAR, sans agir sur le poste. L'expiration de l'ACL temporaire ne doit pas être confondue avec la preuve de restauration de l'isolation. Ne relancer aucune isolation pendant ce diagnostic.
