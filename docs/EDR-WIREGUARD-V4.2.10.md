# V4.2.10 — Préserver le transport WireGuard lors de la quarantaine Velociraptor

Contexte observé: Windows LAB 001 utilise le peer `136.116.89.163:51820/UDP` pour son tunnel `10.77.77.33`; le frontend EDR écoute sur `10.77.77.1:8000/TCP` derrière ce tunnel. La quarantaine Velociraptor a généré `VelociraptorFrontEnd:10.77.77.1:8000/TCP` mais aucune exception de transport WireGuard; elle a échoué au test de frontend HTTPS puis a retiré son IPsec.

La V4.2.10 ajoute **uniquement** une règle IPsec Permit (`me`, UDP, destination `136.116.89.163:51820`, `mirrored=yes`) via le paramètre documenté `RuleLookupTable` de l'artefact client event `Windows.Remediation.QuarantineMonitor` affecté au label `Quarantine`. Les règles DNS, DHCP et Block sont maintenues; pas de règle Permit pour l'ensemble du VPN. Pas d'exclusion du contrôleur AD ou de son LDAP.

Commandes sur GCP après mise à jour :
```
aegismesh-soar edr lab-quarantine transport-status --agent-id 001
aegismesh-soar edr lab-quarantine transport-ensure --agent-id 001 --confirm
aegismesh-soar edr lab-quarantine transport-status --agent-id 001
```

**Attention** : Cette modification est faite sur le groupe de surveillance Velociraptor `Quarantine`. Elle est refusée si un autre hôte est déjà marqué Quarantine, si le moniteur est global ou si une règle différente est personnalisée. Elle ne change aucun label et n'isole personne. La configuration reste durable pour ce groupe ; ne pas utiliser ce groupe pour d'autres hôtes sans audit du transport. La commande peut retourner erreur si le serveur VQL ne remplace pas les paramètres d'un artefact déjà présent ; dans ce cas, ne pas lancer un nouveau test d'isolation avant vérification des paramètres relus. La validation IPsec en local n'est pas l'équivalent de la validation du trafic.

Une fois l'exception confirmée et avec console de secours indépendente du réseau, refaire une quarantaine LAB en observant LDAP `10.77.77.34:389`. Le test de connexion `/server.pem` peut continuer d'échouer si le frontend demande une authentification TLS particulière (mTLS). **Ne jamais contourner la vérification TLS ni la vérification post-isolation**, consulter les logs et la configuration Velociraptor si besoin.

Références officielles:
- https://docs.velociraptor.app/artifact_references/pages/windows.remediation.quarantinemonitor/
- https://docs.velociraptor.app/vql_reference/server/add_client_monitoring/
- https://docs.velociraptor.app/artifact_references/pages/windows.remediation.quarantine/
