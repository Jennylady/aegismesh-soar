# AEGISMESH-SOAR V4.1 — Indicateurs de santé de la chaîne

## Objectif

Corriger les trois mentions de `aegismesh-soar chain status` qui présentaient des vérifications statiques comme des pannes potentielles :

1. `Auth webhook` désigne le **header sortant** vers le déclencheur Shuffle. Le retour `X-Aegismesh-Token` depuis Shuffle vers `/v1/execute` est **indépendant** et reste obligatoire ; aucun jeton n'est créé ou modifié ici.
2. `Retour Shuffle (passé)` lit uniquement la base de décisions pour identifier un **rappel authentifié historiquement exécuté** (`execution_id` présent et `action_status='executed'`). `RÉCENT PROUVÉ` signifie un événement datant de moins de 24 h, **pas** que le worker est actuellement joignable. En cas d'erreur de base : `INCONNU`.
3. `Confiance TLS Wazuh` reflète la présence d'une CA configurée ou du certificat serveur local utilisé par le bridge pour l'API loopback `https://127.0.0.1:55000`. La vérification HTTPS réelle se fait avec `chain wazuh-check`.

## Opérations après déploiement

```bash
aegismesh-soar chain status
aegismesh-soar chain wazuh-check
aegismesh-soar network --check
```

Ces commandes ne déclenchent **aucun blocage**. L'exécution précédente de `WAZUH_AR_PROOF` ou `AD_LAB_DISABLE` n'est pas refaite par la lecture du statut.

Si un déclencheur Shuffle exige un header entrant supplémentaire, le définir **uniquement** après validation de la configuration de ce déclencheur : `aegismesh-soar configure shuffle-auth` (saisie masquée). Ne pas créer de header arbitraire.

La configuration, les secrets, le serveur Wazuh, Shuffle, WireGuard, Fail2ban et Velociraptor ne sont pas modifiés par ce correctif de code.
