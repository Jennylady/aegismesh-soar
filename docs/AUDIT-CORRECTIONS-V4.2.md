# AEGISMESH-SOAR V4.2 — Corrections et validation sur preuves

## Objectif

Corriger uniquement les états réellement dégradés et distinguer :

- **Configuré/actif** (processus ou configuration)
- **Observé** (workflow, sonde, collecte, timer exécuté)
- **Vérifié sur cible** (blocage et levée visibles sur le pare-feu de l'agent)

Le dépôt ne contient pas la stack Shuffle Docker. `update` installe le **code de diagnostic**, mais ne change ni la configuration Shuffle ni celle de Wazuh/Velociraptor et ne lance aucune action SOAR de sécurité.

## Déploiement (depuis Windows/Kali, pas de ZIP sur GCP)

1. Extraire **le contenu de ce ZIP de patch** à la racine du dépôt local `aegismesh-soar` (pas dans un sous-dossier).
2. Sur Windows, Python n’est **pas requis** pour appliquer ce ZIP. Les tests s’exécutent automatiquement sur GCP via `aegismesh-soar update` (ou localement avec `py -3 tests/test_audit_v42.py` si Python est installé).
3. Vérifier `git diff --check`, puis ajouter les fichiers : `git add VERSION CHANGELOG.md bin/aegismesh-soar ops/audit_v42.py tests/test_audit_v42.py docs/AUDIT-CORRECTIONS-V4.2.md`. Enfin garantir le mode exécutable dans Git : `git update-index --chmod=+x bin/aegismesh-soar`.
4. `git commit -m "SOAR V4.2 proof-first recovery and E2E audit"`, puis `git push origin main`.
5. Sur GCP: `aegismesh-soar update` et `aegismesh-soar audit status`.

La mise à jour réutilise le bridge existant et ne remplace pas les secrets.

## Étape 1 — Tenzir (erreur prouvée)

```bash
aegismesh-soar audit tenzir
# Uniquement si `broken_missing_network`, conteneur Tenzir contrôlé et aucun port wildcard :
aegismesh-soar audit tenzir --repair --confirm
aegismesh-soar audit tenzir
docker logs --since 3m --tail 60 shuffle-orborus
```

Réparation : création **uniquement** de `tenzir-network` en bridge si inexistant, puis `docker start tenzir-node`. Refus si image/mode réseau inattendus, root absent, état non pris en charge ou port publié sur toutes interfaces. Pas de suppression Docker, pas de restart de Shuffle/Orborus, pas de modification du pare-feu. Si l'ancien nœud conserve une référence réseau obsolète, la réparation s'arrête en erreur et exige un examen de sa stack propriétaire; **ne jamais supprimer le conteneur ou volumes arbitrairement**.

## Étape 2 — Callback réel Shuffle / worker

```bash
aegismesh-soar audit worker --confirm --timeout 90
```

Une **nouvelle décision OBSERVE** est envoyée au bridge puis à son webhook Shuffle. Réussite = `action_status=executed`, `execution_id` non vide et résultat `record_only` avec `external_action=false`. Le script échantillonne l'apparition de conteneurs worker, mais **n'attribue pas automatiquement un worker observé à cette seule exécution**. Vérifier le détail du workflow dans Shuffle.

Le workflow correspondant dans Shuffle doit être configuré pour appeler le bridge et ne pas lancer d'action externe en dehors de ce contrat. La commande exige `--confirm` et ne soumet jamais de tag de blocage.

## Étape 3 — Blocages GCP/Windows/Linux

```bash
aegismesh-soar audit blocks
aegismesh-soar audit blocks --probe --confirm
```

`blocks` parcourt les vraies décisions de production. La variante `--probe` sonde **au plus la décision la plus récente par type** avec les sondes existantes en lecture seule; elle ne crée ni ne renouvelle de blocage. Une action `executed` ne constitue **pas** une preuve sur l'endpoint. L'absence de décisions de blocage autorisées doit rester `not_verified`, pas `OK`.

Pour examiner une décision particulière : `aegismesh-soar response verify-block --decision-id am-... --confirm`, puis `aegismesh-soar response audit --decision-id am-...`.

## Étape 4 — Timers, TTL, levée automatique

```bash
aegismesh-soar audit timers
# Ne créer que les timers SOAR manquants (unités marquées gérées) :
aegismesh-soar audit timers --ensure --confirm
systemctl list-timers --all 'aegismesh-soar-*'
aegismesh-soar response audit
```

Un timer actif n'est pas une preuve de suppression des règles : utiliser les statuts `removed` issus des sondes réelles. Une vérification effectuée il y a plusieurs heures n'est pas l'état présent.

## Étape 5 — EDR, quarantaine et garde-fou

```bash
aegismesh-soar audit edr
aegismesh-soar edr quarantine-doctor --agent-id 001
aegismesh-soar response progressive-status
aegismesh-soar edr flows --agent-id 001
```

Par défaut, `ENABLE_EDR_ISOLATION=false` et l'agent `006` (contrôleur de domaine) est exclu. Le label `Quarantine` **n'est pas** une preuve de filtrage réseau. L'isolement ne doit être activé que lorsqu'un artefact de monitoring et une vérification endpoint du pare-feu existent et que les commandes de restauration fonctionnent. Une vérification côté poste Windows est nécessaire (règles WFP/Windows Firewall ou télémétrie EDR attestée), suivie d'une vérification de restitution réseau au TTL.

Le script ne crée aucune règle ni ne bascule l'isolement sans validation de laboratoire. Le moteur de détection IA (Personne 1) reste responsable des scores et preuves envoyées à `/v1/decisions`.

## Limites

- La réussite des tests hors production ne démontre pas l'état sur GCP.
- Aucun changement de sécurité de production n'est exécuté automatiquement par `audit status` ou `update`.
- La validation de l'isolation endpoint exige un capteur/artefact réel et un scénario contrôlé.
- Ne pas ajouter l'agent 006 à la liste d'isolation et ne pas bloquer d'IP de gestion.


## Mise à jour corrective 4.2.1 (réseau Tenzir obsolète)

Le diagnostic réel a montré `HostConfig.NetworkMode=bridge` alors que Docker conserve
`tenzir-network` dans ses réseaux associés. V4.2.1 détecte et autorise **seulement**
cette configuration explicitement observable (sans supposer la topologie).

Après `aegismesh-soar update` :

```bash
aegismesh-soar audit tenzir
aegismesh-soar audit tenzir --repair --confirm
aegismesh-soar audit tenzir
docker ps -a --filter name=tenzir-node --format 'table {{.Names}}\t{{.Status}}\t{{.Networks}}'
docker logs --since 2m --tail 30 shuffle-orborus
```

La réparation crée seulement le réseau Docker dédié si manquant, puis tente de
démarrer le conteneur existant. Un démarrage `running` ne prouve pas la santé
de l’API de Tenzir ou de ses pipelines. Si Docker indique qu'un ancien ID de
réseau n'existe toujours pas, **ne pas** supprimer le conteneur ou ses volumes
sur la base de ces seuls journaux. Examiner d'abord sa stack de création.

Le worker Shuffle `OBSERVE` a déjà été validé indépendamment de Tenzir : ne pas
relancer le test simplement pour faire disparaître l'erreur Tenzir.
