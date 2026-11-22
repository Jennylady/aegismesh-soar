# V4.2.9 — Identifier pourquoi l IPsec de quarantaine ne persiste pas

Dans les logs réels, le label et le moniteur ont fonctionné. Le moniteur a indiqué `Setting quarantine policy`, mais la politique `VelociraptorQuarantine` n'était pas visible sur WIN-LAB-01 et la connexion LDAP à 10.77.77.34:389 restait ouverte. Cette ligne de log n'est pas la sortie de `netsh`.

La documentation officielle de l'artefact `Windows.Remediation.Quarantine` précise que la politique est supprimée si la connexion de contrôle HTTPS au serveur Velociraptor échoue après application. Une stratégie IPsec GPO du domaine peut aussi empêcher l'application d'une politique IPsec locale.

Après `aegismesh-soar update` sur GCP, sans modifier aucun service :

```bash
aegismesh-soar edr lab-quarantine results --agent-id 001
aegismesh-soar edr lab-quarantine logs --agent-id 001
aegismesh-soar edr lab-quarantine status --agent-id 001
```

Les résultats de `monitoring()` montrent les sorties de l'artefact et les éventuels messages d'erreur `netsh`, alors que `monitoring_logs()` montre le journal du moniteur. Une sortie `IPsec policy applied` sans contrôle de flux réseau n'atteste toujours pas l'isolation. Si `failed connection test. Removing IPsec policy` apparaît, ne modifiez pas les protections du domaine : examinez la configuration du canal frontend et le test HTTPS de l'agent. Ne modifiez rien sur Windows Server AD `006`.

Vérifier également que le bail a expiré et que le label `Quarantine` a été retiré ; un retrait de label ne suffit pas à garantir la restauration réelle du réseau.

Documentation Velociraptor :
- https://docs.velociraptor.app/artifact_references/pages/windows.remediation.quarantine/
- https://docs.velociraptor.app/vql_reference/server/monitoring/
