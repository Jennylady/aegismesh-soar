# AEGISMESH-SOAR V4.2.12 — Correctif d’écriture du monitoring EDR

## Cause confirmée
La version 4.2.11 lit bien le moniteur et ses paramètres par défaut (`artifacts.artifacts` sans `specs`), mais `transport-ensure` utilise `add_client_monitoring` sur le moniteur déjà présent. Velociraptor ne persiste alors pas le changement. `transport-status` reste `wg_exception_configured: false`.

## Modification
La commande `transport-ensure` applique un patch VQL ciblé `get_client_monitoring` → `patch` → `set_client_monitoring` au groupe `Quarantine`, préserve les autres labels/artefacts et vérifie la relecture exacte du paramètre. Pas de remplacement aveugle ni de changement du frontend EDR ou de l’AD.

## Application depuis Windows (un ZIP uniquement)
Extraire à la racine du dépôt F:\SOUTENANCE\Lady\aegismesh-soar, git commit/push, puis sur GCP `aegismesh-soar update`.

## Vérification GCP
```bash
aegismesh-soar edr lab-quarantine status --agent-id 001
aegismesh-soar edr lab-quarantine transport-status --agent-id 001
aegismesh-soar edr lab-quarantine transport-ensure --agent-id 001 --confirm
aegismesh-soar edr lab-quarantine transport-status --agent-id 001
```
Le résultat attendu est `wg_exception_configured: true`, sinon NE PAS isoler. Aucune nouvelle quarantaine n’est créée par le correctif. L’absence de label et de bail SOAR doit être vérifiée avant `transport-ensure`. Lorsque le paramètre est confirmé, un test réseau séparé sur Windows LAB reste nécessaire, avec console de secours et retour arrière.

## Note réseau
La règle IPsec permet l'UDP pour le pair WireGuard `136.116.89.163:51820` et le frontend EDR est autorisé par l'artefact lui-même, mais ceci ne démontre pas l'authentification TLS du frontend. Si le client perd sa connexion, l'artefact peut retirer la politique de quarantaine.
