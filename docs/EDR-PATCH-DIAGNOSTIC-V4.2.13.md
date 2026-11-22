# AEGISMESH SOAR V4.2.13 — Diagnostic exact de persistance Velociraptor

La V4.2.12 ne persiste pas `RuleLookupTable` dans `get_client_monitoring()` : le code ne vérifiait pas que `patch(...)` produisait la configuration attendue AVANT `set_client_monitoring()`.

## Déploiement
Depuis Windows, extraire le ZIP à la racine `F:\SOUTENANCE\Lady\aegismesh-soar`, commit/push, puis `aegismesh-soar update` sur GCP.

## Contrôle sans changer le serveur
```bash
aegismesh-soar edr lab-quarantine transport-diagnose --agent-id 001
aegismesh-soar edr lab-quarantine transport-status --agent-id 001
```

- `patch_preview_valid: false` : ne pas relancer `transport-ensure` ; la transformation VQL échoue en amont et l’écriture ne résoudra pas le problème.
- `patch_preview_valid: true` : si le dernier `set_client_monitoring()` n’a rien persisté, investiguer la valeur de retour et les logs API, en gardant le monitoring intact.
- `wg_exception_configured: true` : seule la configuration serveur est vérifiée. Il faudra encore prouver le trafic réseau Windows LAB en conditions réelles.

## Sécurité
Les diagnostics ne modifient aucun artefact, label, règle IPsec ni bail. Le script n'autorise que l’agent Windows LAB `001`, ne divulgue aucune valeur des artefacts tiers et maintient l’interdiction d’isoler le DC `006`. `transport-ensure` prévisualise avant l’écriture et échoue fermé si le serveur ne transforme pas exactement les paramètres souhaités.
