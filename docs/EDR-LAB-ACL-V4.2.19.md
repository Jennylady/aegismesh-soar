# EDR LAB V4.2.19 — ACL temporaires Velociraptor

**Permission manquante confirmée :** le compte API `AEGISMESH_SOAR_API` possède `COLLECT_CLIENT` mais pas `EXECVE` ni `NETWORK`. L’artefact intégré `Windows.Remediation.Quarantine` exige explicitement ces deux permissions supplémentaires. Cela explique le refus probable de planification de la collecte directe.

## Mécanisme

- `aegismesh-soar edr lab-acl status` : ACL et fenêtre temporaire, sans modification.
- `aegismesh-soar edr lab-acl grant --confirm --allow-restart` : sauvegarde la politique exacte, installe et active le timer de révocation, accorde **uniquement** les permissions `EXECVE` et `NETWORK` au principal existant et redémarre **uniquement** le conteneur Velociraptor. Vérifie les permissions effectives.
- `aegismesh-soar edr lab-acl restore --confirm --allow-restart` : restitue les ACL originelles avec redémarrage et vérification.
- Le timer `aegismesh-soar-edr-acl-expiry` s'exécute environ toutes les 30 secondes et procède au retrait au bout de **12 minutes**, indépendamment de l'interface SOAR. En cas de redémarrage GCP, la minuterie persistante revalide et restaure.
- `direct-start` refuse la collecte quand la fenêtre temporaire est absente ou expirée.

**AVERTISSEMENT CRITIQUE :** `EXECVE` est un droit puissant sur l'organisation Velociraptor, non limité à l'agent 001 par l'ACL. Il n'est pas accordé à `investigator` ni à d'autres comptes, seulement au principal API existant, pendant la fenêtre de test. Un utilisateur obtenant la clé API pendant cette fenêtre peut potentiellement exécuter des commandes sur d'autres machines. Ne pas utiliser en production sans remplacer cette méthode LAB par un artefact wrapper restreint et un principal dédié.

## Utilisation

Sur Windows, installer le patch dans le dépôt, commit/push. Sur GCP :

```
aegismesh-soar update
aegismesh-soar edr lab-acl status
aegismesh-soar edr lab-acl grant --confirm --allow-restart
aegismesh-soar edr lab-acl status
```

Ne pas lancer `direct-start` tant que le contrôle ACL n'a pas réussi et tant qu'un nouveau secours local n'a pas été armé. Révoquer explicitement après le test et confirmer l'absence de `EXECVE` et `NETWORK`.

```
aegismesh-soar edr lab-acl restore --confirm --allow-restart
aegismesh-soar edr lab-acl status
```

Source : https://docs.velociraptor.app/artifact_references/pages/windows.remediation.quarantine/ ; https://docs.velociraptor.app/docs/cli/commands/acl/
