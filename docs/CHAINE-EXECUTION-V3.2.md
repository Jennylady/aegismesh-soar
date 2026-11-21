# AEGISMESH SOAR V3.2 — raccordement réel Shuffle / Wazuh AR / Fail2ban

## Flux de travail obligatoire

Kali (code) → GitHub (push) → GCP (`aegismesh-soar update`).

Le bridge est déjà actif sur GCP ; **ne pas réinstaller** ni copier de ZIP sur GCP.

**Chaîne opérationnelle :**

1. AEGISMESH reçoit `POST /v1/decisions` avec le `DECISION_TOKEN` et valide la décision, son expiration, son tag et sa cible.
2. Le bridge place la décision en base puis envoie le JSON au `SHUFFLE_WEBHOOK_URL` local.
3. Le Webhook déclenche le workflow `AEGISMESH - Decision Dispatcher` : `Webhook → HTTP POST`.
4. L'action HTTP du worker appelle `POST /v1/execute` du bridge, avec `X-Aegismesh-Token` configuré **dans l'authentification de l'application HTTP**.
5. Le bridge récupère la décision **originale enregistrée en base**, et non des commandes externes du webhook. Il applique sa politique de tag et cible et exécute l'outil choisi.
6. Le bridge écrit le résultat en SQLite ; `GET /v1/decisions/<id>` donne `delivery`, `action_status`, `detail` et `execution_id`.
7. Pour `OBSERVE` : `executed` après rappel Shuffle. Pour Wazuh agent externe : `dispatched_unverified` jusqu'à preuve sur l'agent ; ne pas affirmer que le script a exécuté.

## 1. Contrôles sur GCP

```bash
sudo aegismesh-soar chain status
sudo aegismesh-soar network
sudo aegismesh-soar chain guide
```

Le premier montre si `SHUFFLE_WEBHOOK_URL` et Wazuh sont configurés. `network` affiche les IP de passerelles, **mais pas forcément le réseau des workers éphémères** : valider depuis la véritable action HTTP Shuffle. Si le bridge écoute uniquement sur `127.0.0.1`, le worker Docker ne peut pas y accéder via son propre loopback.

Choisir une IP de passerelle Docker **réellement attribuée à l’hôte et accessible au réseau du worker**, puis, uniquement après avoir vérifié le pare-feu, exécuter :

```bash
sudo aegismesh-soar configure bind IP_PASSERELLE_DOCKER
sudo aegismesh-soar health --verbose
```

**Ne pas** utiliser `0.0.0.0`, une IP publique ou ouvrir le port `19081` sur Internet. Limiter les sources entrantes au réseau du worker; le jeton `SHUFFLE_ACTION_TOKEN` reste requis.

## 2. Le vrai workflow Shuffle

Dans l'interface **Shuffle existante** (ne pas réinstaller) :

- Créer un nouveau workflow : `AEGISMESH - Decision Dispatcher`.
- Ajouter un déclencheur **Webhook** ; le démarrer et copier son URL (forme `/api/v1/hooks/webhook_<id>` ou `/api/v1/webhooks/webhook_<id>` selon la version).
- Activer **l'authentification par en-tête requis** sur le webhook si disponible. Le bridge doit utiliser la même paire nom/secret : `aegismesh-soar configure shuffle-auth` (saisie masquée).
- Ajouter une seule action **HTTP POST** connectée au Webhook (environnement servi par Orborus / worker local).
- URL de l'action : `http://IP_PASSERELLE_DOCKER:19081/v1/execute`.
- Header : `Content-Type: application/json`. Dans **Authentication** de l'app HTTP, configurer `X-Aegismesh-Token` avec le `SHUFFLE_ACTION_TOKEN` local, accessible au root du serveur via `/etc/aegismesh-soar/soar.env`. Ne pas l'enregistrer en clair dans un workflow public, une capture ou Git.
- Body JSON de l'action HTTP :

```json
{"decision_id":"$exec.decision_id","execution_id":"$exec.decision_id"}
```

`$exec.decision_id` est la référence Shuffle officiellement documentée pour une valeur du corps Webhook. Sélectionner le champ avec l'autocomplétion dans l'éditeur si nécessaire. Ici `execution_id` est **une clé de corrélation stable liée à la décision**, et non l'identifiant natif d'exécution Shuffle : consulter l'onglet **Executions** pour récupérer cet identifiant réel. Cette substitution évite d'inventer une variable native qui n'est pas confirmée sur la version self-hosted installée.

**Ne pas** inclure de `command`, `script`, `target.ip` ou `tag` modifiable dans le body du callback. La décision est figée côté bridge.

Relier ensuite le Webhook au bridge :

```bash
sudo aegismesh-soar configure webhook 'http://127.0.0.1:15001/api/v1/hooks/webhook_ID_REEL'
sudo aegismesh-soar chain observe
```

Cela utilise le **vrai** Shuffle. Le retour doit afficher `action_status=executed` après le callback, **pas simplement** `accepted_by_shuffle`. Confirmer l'exécution visible dans l'onglet Shuffle **Executions**, avec les résultats du nœud HTTP.

## 3. Wazuh Active Response — preuve sur manager

Le `manager` Wazuh 4.14.10 dispose de `/active-response` et autorise un nom de script précédé de `!`, envoyé à un agent identifié. Les sept commandes installées ne nécessitent **pas** de nouveau bloc XML de déclenchement pour ce mode API. Le script de test ne bloque rien : il écrit un identifiant dans un journal local sur l'agent où il est installé.

Sur GCP :

```bash
sudo aegismesh-soar chain wazuh-install
sudo aegismesh-soar configure wazuh
sudo aegismesh-soar configure wazuh-ca /CHEMIN/VERS/CA-WAZUH.pem
sudo aegismesh-soar chain wazuh-check
```

Après succès du test `OBSERVE` et de l'authentification API (et une fois l’agent `000` confirmé utilisable pour Active Response dans cette installation) :

```bash
sudo aegismesh-soar configure enable-tests
sudo aegismesh-soar chain wazuh-proof --agent-id 000
```

Si l'API n'accepte pas l'agent 000, ne pas contourner l'erreur : choisir un agent Linux **dédié au test**, installer le script sur celui-ci et ajouter son ID dans `WAZUH_TEST_AGENTS` via une configuration protégée. Pour tout agent distant, le statut `dispatched_unverified` est attendu tant que la preuve sur l’agent n’a pas été vérifiée.

Pour inspecter une décision précise sur le manager : `aegismesh-soar chain proof-check ID_DE_DECISION`.

**Note TLS :** privilégier la CA qui signe l’API Wazuh. Ne pas activer `WAZUH_TLS_INSECURE` en production.

## 4. Fail2ban — action contrôlée réelle

Le bridge réutilise exclusivement la jail `aegismesh-soar-gcp` ; il **n'écrit pas** dans la jail `sshd`. D'abord test non destructif d'état, puis bannissement de courte durée d'une adresse de documentation, avec retrait automatique :

```bash
sudo aegismesh-soar chain status
sudo aegismesh-soar configure enable-tests
sudo aegismesh-soar chain f2b-test --confirm
sudo fail2ban-client status aegismesh-soar-gcp
```

Adresse réservée de test : `198.51.100.42`. Le code vérifie la présence du ban dans la jail puis son retrait. Ce test agit **réellement sur Fail2ban/nftables**, mais n'est pas une démonstration de blocage de trafic externe de bout en bout.

Quand les tests sont terminés :

```bash
sudo aegismesh-soar configure disable-tests
```

L'action de production `F2B_BAN_SERVER` reste **désactivée**. Elle nécessitera une autorisation distincte, `PROTECTED_CIDRS` contenant les réseaux de gestion et des tests de non-régression SSH/WireGuard.

## 5. Raccordement à AEGISMESH/personne 1

**Après validation de `OBSERVE`, puis des tags de preuve :** désigner **un seul** émetteur approuvé du moteur de décisions vers `POST /v1/decisions`, avec le `DECISION_TOKEN`. Ne pas brancher simultanément l'ancien relais `aegismesh-shuffle-relay` et cette passerelle au même flux sans examiner la logique de publication des incidents. Les actions sensibles AD/EDR restent désactivées jusqu'à tests spécifiques sur Windows et Windows Server.

## 6. Codes d’état à ne pas confondre

- `queued` : décision enregistrée en local ; Webhook pas encore confirmé.
- `retry` : Webhook échec ; livraison sera retentée avec limite.
- `accepted_by_shuffle + pending` : Shuffle a accepté la requête HTTP, **sans preuve que le workflow a terminé**.
- `action_executed + executed` : exécuteur a terminé (pour `OBSERVE`, pas d'action externe).
- `action_executed + dispatched_unverified` : API Wazuh a accepté la distribution, **sans preuve d'exécution sur agent**.
- `action_executed + failed` / `denied` : problème ou refus de politique, ne pas présenter comme succès.

### Compatibilité webhook /hooks et /webhooks (V3.2.2)

Le CLI accepte les deux chemins Shuffle `/api/v1/hooks/webhook_UUID` et `/api/v1/webhooks/webhook_UUID`.
Lorsque le lien provient du frontend tunnelé `127.0.0.1:18031`, le serveur SOAR peut adresser directement le backend local sur `127.0.0.1:15001`, à condition de vérifier que ce backend sert bien le même chemin.
**Ne pas remplacer le chemin `/hooks/` par `/webhooks/`** si ce n'est pas celui de l'instance.
Dans l'éditeur Shuffle, `Run` exécute manuellement le graphe ; l'état `Webhook: uninitialized` signifie que le déclencheur n'est pas démarré. Faire défiler le panneau du Webhook et utiliser `Start`, puis vérifier son état.
Ne pas envoyer un événement réel avant d'avoir configuré l'action HTTP du workflow et son authentification.
