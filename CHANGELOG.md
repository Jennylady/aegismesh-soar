# Historique

## V2.0.0 — Dépôt SOAR indépendant

- Arborescence `/opt/aegismesh/soar` et commande `aegismesh-soar update`.
- Gestion Git `main`, `fetch`, `ff-only`, tests, rollback et redémarrage de **son** service uniquement.
- Install/bootstrap du bridge sans remplacement des autres services AEGISMESH.
- Diagnostic des installations existantes sans lire les identifiants.
- Interface standard décisions → Shuffle → action du catalogue → traçabilité.
- Wazuh et Fail2ban réutilisés et non réinstallés.
- Aucun confinement Windows/AD activé avant validations réelles.
