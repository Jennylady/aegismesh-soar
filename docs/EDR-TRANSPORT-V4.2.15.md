# AEGISMESH-SOAR V4.2.15 — Réparation du moniteur Quarantine

## Fait observé
V4.2.14: `patch_preview_valid=true` avec RFC6902, mais `set_client_monitoring(...)` retourne `NULL/false`; `wg_exception_configured=false`. La cause précise côté serveur (permission, sérialisation, fonction) n'est pas prouvée; le code ne contourne ni la validation TLS ni le filtrage.

## Remplacement contrôlé, par script (Windows LAB uniquement)

1. `aegismesh-soar update`
2. `aegismesh-soar edr lab-quarantine status --agent-id 001`
3. `aegismesh-soar edr lab-quarantine transport-repair --agent-id 001 --confirm`
4. `aegismesh-soar edr lab-quarantine transport-status --agent-id 001`

La commande `transport-repair` exige le mode root, l'identité LAB 001, le moniteur Quarantine uniquement, l'absence de baux et de labels Quarantine sur **tous les clients**, aucun autre artefact ni paramètre personnalisé dans le groupe, et l'absence d'affectation globale du moniteur. Elle sauvegarde le monitoring dans `/var/lib/aegismesh-soar/edr-quarantine-monitor-backup-v4215.json` (permission 0600), puis retire uniquement le moniteur Quarantine et le recrée avec une exception UDP d'underlay WireGuard (`136.116.89.163:51820`) le frontend EDR `10.77.77.1:8000/tcp`, ainsi que les filtres DNS/DHCP et le blocage des autres flux. Elle vérifie à chaque étape, et remet le moniteur par défaut en cas d'échec.

Si l'API refuse également `rm_client_monitoring` ou `add_client_monitoring`, l'opération s'arrête et la restauration doit être vérifiée avant toute nouvelle tentative. Ne pas lancer `lab-quarantine start` tant que `wg_exception_configured` n'est pas `true`. Même après succès, **TLS/frontend et isolation réseau doivent être validés indépendamment** sur WIN-LAB-01. Aucun changement sur AD 006.
