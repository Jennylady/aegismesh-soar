# V4.2.17 — Quarantaine ciblée, sans réécriture du moniteur

## Pourquoi
La table de monitoring Velociraptor contient `compiled_collector_args` et `max_upload_bytes` non vides. Ne pas supprimer ni recréer ce groupe.

L'artefact officiel `Windows.Remediation.Quarantine` peut être lancé comme une **collecte sur un seul client** avec `RuleLookupTable` personnalisé. Cela ne change aucun moniteur et ne pose pas le label `Quarantine`.

## Procédure contrôlée
1. Depuis une console ADMINISTRATEUR **locale** de Windows LAB `WIN-LAB-01`, exécuter `Arm-AegisMeshLabIpsecRecovery-v4217.ps1`. Un planificateur Windows SYSTEM indépendant de WireGuard est armé à +300 s, avant toute modification de la politique.
2. Sur GCP, exécuter `aegismesh-soar edr lab-quarantine direct-doctor --agent-id 001`. Il ne peut pas constater la tâche locale; l'armement est attesté par l'opérateur.
3. Sur GCP, `aegismesh-soar edr lab-quarantine direct-start --agent-id 001 --confirm --console-access --recovery-task-armed`.
4. Mesurer en continu LDAP `10.77.77.34:389` et vérifier l'IPsec sur Windows LAB, ainsi que le flow Velociraptor (aucune preuve d'isolation sur simple ACK).
5. `direct-release --agent-id 001 --confirm` déclenche la suppression anticipée; sinon timer SOAR après 180 s tente le retrait. Le secours Windows force une tentative après +300 s si le canal EDR a été coupé.
6. Après **preuve de retour LDAP=True et absence de politique IPsec** et vérification du flow, `direct-clear --agent-id 001 --confirm` efface seulement le bail SOAR.
7. Pour un nouvel essai, relancer le script Windows : il ne remplace une ancienne tâche que si son action correspond au script AEGISMESH connu, qu'elle n'est plus en cours et qu'elle a déjà été exécutée. Une tâche inconnue ou non exécutée provoque un refus.

## Précautions
- Ne jamais exécuter sur le DC 006. Sans accès console locale indépendante et tâche de reprise vérifiée, ne pas utiliser le mode direct.
- Le secours doit rester activé même si le flow de retrait est expédié; un `flow_id` n'est pas une preuve d'effet réseau.
- Ne jamais interpréter un test curl HTTPS mTLS depuis Windows comme une preuve de défaillance du vrai client.
