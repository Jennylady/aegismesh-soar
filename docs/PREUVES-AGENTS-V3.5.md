# AEGISMESH-SOAR 3.5 — preuves d’exécution réelles des agents

## Pourquoi les décisions restent `dispatched_unverified`

Wazuh 4.14 a bien distribué l’action et, sur Kali, `am-f13a42cd31f500eebd3234f7` a été exécutée localement. Mais le SOAR ne peut pas consulter le disque de Kali depuis GCP. La preuve doit remonter par Wazuh Logcollector, être décodée par des règles locales et apparaître dans `/var/ossec/logs/alerts/alerts.json` avec `agent.id` et `full_log`. Les journaux de l’agent isolés ne suffisent pas.

## Flux déployé

`Shuffle -> Bridge -> API Wazuh -> agent AR -> aegismesh-soar-evidence.log -> Wazuh Logcollector -> règle 119870/119871 -> alerts.json -> réconciliation SOAR -> executed`

Une règle de preuve a un niveau 5 ; une preuve de blocage a un niveau 6. Les règles ne déclenchent **aucune** Active Response par elles-mêmes.

## Installation côté manager GCP

Après `aegismesh-soar update` :

```
aegismesh-soar fleet evidence status
aegismesh-soar fleet evidence install --apply --confirm
```

La commande installe uniquement le fichier `/var/ossec/etc/rules/aegismesh-soar-evidence.xml`, vérifie l'absence de collisions d'ID, lance `wazuh-analysisd -t`, redémarre **uniquement wazuh-manager** si modification, vérifie la disponibilité, et restaure le fichier précédent en cas d’échec. Ce redémarrage provoque une interruption temporaire de la collecte ; préférer une fenêtre maîtrisée.

## Linux — Kali, agent 002

Depuis le dépôt Git de Kali (après `git pull` si nécessaire) :

```
sudo bash ops/wazuh/install_agent_proof.sh --enable-collection
```

Cette commande installe le script et crée le collecteur dédié dans `/var/ossec/etc/ossec.conf` s’il n’existe pas. Elle sauvegarde puis vérifie la configuration et ne redémarre que `wazuh-agent` en cas de modification. Elle ne bloque aucune IP. Si le bloqueur Linux est déjà installé, son exécutable est également actualisé.

## Windows et Windows Server — agents 001, 006

Récupérer les fichiers .cmd, .ps1 et l’installateur du commit Git approuvé. Exécuter dans PowerShell élevé :

```
.\Install-AegisMeshProof.ps1 -EnableCollection
```

Le script installe l'exécutable et son collecteur local (fichier de config sauvegardé), puis redémarre **seulement WazuhSvc** sur la machine concernée. Il ne change ni AD, ni comptes, ni pare-feu, ni stratégies GPO. Faire l'installation séparément sur 001 et 006. Un agent Windows peut apparaître temporairement déconnecté durant le redémarrage.

## États

- `dispatched_unverified`: acceptation API mais pas de preuve remontée au manager.
- `executed`: événement remonté et associé au **même** agent et à la **même** décision.
- `failed` ou `denied`: action refusée ou échouée.

Le SOAR réconcilie automatiquement toutes les sept secondes. Les opérations de lecture/actualisation manuelle sont :

```
aegismesh-soar fleet evidence status
aegismesh-soar fleet evidence reconcile
```

Ne pas rejouer une action dont la commande apparaît sur l’agent dans le seul but de changer le statut : l’ancienne preuve peut avoir été perdue avant activation de la collecte. Une nouvelle décision légitime donnera une preuve de bout en bout.

## Actions de sécurité

L’action `F2B_BAN_SERVER` existe et exige l’IP publique réellement impliquée, des références de preuves et une décision approuvée. `WAZUH_BLOCK_AGENT` est limité aux agents **Linux** approuvés et à une durée temporaire. Aucune action de confinement Windows ni désactivation AD n’a été ajoutée dans V3.5. Il faut de vrais exécuteurs EDR/AD avec validation et rollback pour ces actes.
