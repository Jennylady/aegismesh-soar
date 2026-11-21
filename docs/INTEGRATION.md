# Intégration aux installations AEGISMESH existantes

## Principe de séparation

- **Personne 1** fournit une décision structurée et autorisée avec `decision_id`, `incident_id`, `tag`, `target`, `confidence`, `evidence_ids`, `approved`, `expires_at`.
- **Personne 2** reçoit les décisions sur un port local, les stocke, les remet au webhook Shuffle, puis exécute uniquement une action du catalogue prédéfini après rappel authentifié de Shuffle.
- Réutilisation d'installations **déjà en place** : Wazuh manager/API 4.14.10, 7 agents enregistrés, Shuffle backend/frontend/OpenSearch/Orborus, fail2ban jails `aegismesh-soar-gcp` et `sshd`.
- `aegismesh-shuffle-relay.service` existe déjà : **jamais arrêté, modifié ni remplacé automatiquement**. Définir un seul chemin de décision actif pour éviter les doubles déclenchements.

## Vérifications de déploiement

1. `aegismesh-soar doctor` doit reconnaître les services existants ; aucun service n'est installé en double.
2. `aegismesh-soar health` doit retourner `OK` après installation du bridge.
3. Créer un workflow Shuffle de test sans remédiation. Configurer le webhook sur le bridge.
4. `aegismesh-soar submit --tag OBSERVE --wait 15` doit produire un `decision_id`.
5. Contrôler dans Shuffle **Executions** l'exécution et le rappel HTTP, pas seulement le `HTTP 200` du webhook.
6. `aegismesh-soar decision <id>` doit indiquer `action_status=executed` ET `execution_id` défini ; sinon le workflow n'a pas atteint l'exécuteur.

## Tokens & ports

`/etc/aegismesh-soar/soar.env` créé avec permissions 0600. Ne pas publier les valeurs sur GitHub, Slack, les captures d'écran, ni l'interface publique AEGISMESH.

- `DECISION_TOKEN`: consommateur `POST /v1/decisions` et `GET /v1/decisions/{id}` (emetteur confiance).
- `SHUFFLE_ACTION_TOKEN`: action HTTP Shuffle → `POST /v1/execute`. **Ne pas mettre ce secret dans la charge utile du webhook**.
- `SHUFFLE_WEBHOOK_URL`: URL du webhook réel, par défaut vide.
- `SOAR_BIND_HOST=127.0.0.1` / `SOAR_PORT=19081`: loopback uniquement initialement.
- Réseau Docker : les workers Shuffle ne voient pas automatiquement le loopback du serveur. Identifier le réseau du worker réel, et si nécessaire `aegismesh-soar configure bind ADRESSE_PRIVEE_LOCALE`. N'utiliser que l'IP privée affectée à l'hôte et restreindre le port 19081 au réseau Docker attendu au niveau du pare-feu; **pas de 0.0.0.0 / pas de règle firewall automatiquement ajoutée**.

## Wazuh Active Response

L'inventaire observé montrait 7 commandes `<command>` et 0 liaison `<active-response>` : **ce n'est pas une panne**, mais aucune réponse automatique par règle n'était déclarée dans les fichiers inspectés. Le bridge utilise la route API Wazuh `PUT /active-response`, séparée d'un déclencheur par règle XML.

- Activer la preuve agent uniquement après tests Shuffle/OBSERVE : `sudo bash ops/wazuh/install_ar_proof.sh` ajoute un script de preuve sur manager local, sans changer XML ni redémarrer Wazuh.
- Configure ensuite l'API avec `aegismesh-soar configure wazuh`; prévoir la vérification TLS du certificat de l'API dans `WAZUH_CA_FILE` (ne pas désactiver TLS en production).
- Le tag `WAZUH_AR_PROOF` exige une autorisation explicite de l'agent dans `WAZUH_TEST_AGENTS` et `ENABLE_TEST_ACTIONS=true`. Attention : l'agent 000 peut ne pas accepter cette API selon le comportement local; préférer un agent Linux de test où le script est installé.
- `dispatched_unverified` signifie *ordre accepté par l'API*, pas exécution prouvée; la preuve agent se trouve dans `/var/ossec/logs/aegismesh-soar-proof.jsonl` **sur l'agent exécutant**.
- Aucune commande dangereuse `disable-account`, `restart-wazuh`, `route-null`, ou `netsh` n'est exécutée automatiquement.

## Fail2ban

- Utiliser **exclusivement** la jail existante `aegismesh-soar-gcp` (ne pas toucher `sshd`).
- Test : `aegismesh-soar configure enable-tests` puis `aegismesh-soar submit --tag F2B_TEST_BAN --ip 198.51.100.42 --approved --confidence 0.99 --evidence test-A --evidence test-B --wait 15`.
- Le script vérifie l'apparition dans la jail puis l'unban. Ne pas confondre présence dans Fail2ban avec blocage effectif de paquets par nftables. Faire une validation séparée du pare-feu et du trafic pour prouver l'enforcement.
- `F2B_BAN_SERVER` reste désactivé (`ENABLE_PROD_ACTIONS=false`). Une activation de production implique validation formelle des CIDR de gestion, du rollback et des flux autorisés. Ce package ne fournit **pas** de raccourci CLI pour activer cela par inadvertance.

## Machine Windows / AD

`EDR_ISOLATE`, `WAZUH_BLOCK_AGENT` et `AD_DISABLE_ACCOUNT` sont **refusés** en V2, et non simulés comme exécutés. Ils nécessiteront un canal de gestion de récupération sûr, un inventaire d'agents, des politiques anti-faux positifs, un contrôle de retour d'état, et une gestion Tier 0 dédiée pour AD.

## Limites

Les tests livrés utilisent un faux webhook local et ne prouvent pas le fonctionnement réel de Shuffle, Wazuh Active Response ou Fail2ban avant raccordement et essais sur le serveur. Aucun accès aux fichiers locaux réels du serveur n'a été possible pendant la génération de ce ZIP. Le pont n'infère pas les identifiants depuis les configurations AEGISMESH existantes : les secrets ne sont pas partagés implicitement entre applications.
