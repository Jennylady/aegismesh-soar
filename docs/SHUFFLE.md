# Configurer une fois Shuffle avec le bridge AEGISMESH-SOAR

Ce paquet **ne crée pas automatiquement** de workflow dans Shuffle, car la version self-hosted, les identifiants d'API, le réseau de l'agent exécutant et le modèle de workflow réellement en service sont à vérifier. Il inclut toutes les interfaces et le contrat pour le faire sans toucher aux quatre conteneurs existants.

## 1. Créer un workflow dédié

Dans l'interface Shuffle déjà installée :

- Nouveau workflow `AEGISMESH - Decision Dispatcher V2`, séparé des anciens playbooks existants.
- Déclencheur **Webhook** en mode actif. Copier l'URL réelle et configurer éventuellement un header secret côté déclencheur Shuffle.
- Action HTTP finale **POST** vers `http://IP_PRIVEE_HOTE_DOCKER:19081/v1/execute` ; Header `X-Aegismesh-Token: <SHUFFLE_ACTION_TOKEN>` géré par authentification de l'app HTTP, jamais dans le body public.
- Body JSON :

```json
{"decision_id":"<ID du payload du webhook>","execution_id":"<ID de cette exécution Shuffle>"}
```

Remplacer ces placeholders avec les **variables réellement proposées par l'éditeur Shuffle** (`execution_argument`, `execution_id` selon version) ; ne pas envoyer les chaînes `<ID ...>` telles quelles. Le `execution_id` doit être stable, unique et correspondre au pattern `[A-Za-z0-9_-]{8,64}`.

Shuffle permet une authentification de webhook via des headers requis. Pour la configurer sans exposer le secret dans l'historique shell : `aegismesh-soar configure shuffle-auth`. Le CLI demande le nom du header et sa valeur (masquée), conserve les valeurs dans `/etc/aegismesh-soar/soar.env` (mode 0600) et redémarre **seulement** le bridge. Ces champs restent vides par défaut.

## 2. Connectivité Docker

`127.0.0.1` *dans un conteneur* désigne ce conteneur, pas le serveur Linux. Identifier le réseau Docker du **worker d'exécution** (pas uniquement shuffle-backend) et vérifier que l'adresse du bridge est atteignable depuis ce réseau. Pour lier sur une interface privée **déjà présente sur le serveur** :

```bash
aegismesh-soar configure bind 172.17.0.1
```

Cette adresse est seulement un exemple : ne l'utiliser que si elle est effectivement attribuée à une interface de l'hôte et accessible au worker. La commande refuse une adresse qui n'appartient pas au serveur. Ne jamais binder sur `0.0.0.0`, ni exposer 19081 sur Internet. Mettre en place une restriction réseau correspondante avec la politique de pare-feu déjà gérée par l'infrastructure, une fois l'interface identifiée.

## 3. Relier le webhook

```bash
aegismesh-soar configure webhook 'http://127.0.0.1:15001/api/v1/webhooks/webhook_ID_REEL'
aegismesh-soar submit --tag OBSERVE --wait 15
```

Un émetteur doit recevoir `202` pour la décision, le bridge doit obtenir une acceptation HTTP du webhook, puis **le workflow doit rappeler `/v1/execute`**. Le statut `executed` n'apparaît qu'après ce rappel. Contrôler l'historique **Executions** dans Shuffle.

### Interprétation des statuts

- `queued` / `retry` : webhook non configuré, inaccessible ou refusé.
- `accepted_by_shuffle` + `pending` : webhook accepté, action HTTP du workflow absente/échouée, ou worker incapable d'atteindre le bridge.
- `action_executed` + `executed` : action du catalogue exécutée (pour `OBSERVE`, uniquement enregistrée).
- `action_executed` + `dispatched_unverified` : commande Wazuh distribuée, **preuve sur agent encore manquante**.
- `denied` : politique SOAR a refusé le tag ou la cible.

## 4. Point d'intégration avec AEGISMESH principal

Une fois le workflow réellement validé, relier **un seul émetteur** du moteur de décisions au endpoint `POST /v1/decisions` du bridge, au moyen du `DECISION_TOKEN`. Ne pas brancher en parallèle l'ancien `aegismesh-shuffle-relay` et ce nouveau bridge au même flux avant d'avoir inspecté leur logique d'acheminement, sous peine de doubles exécutions.

Exemple de payload: `examples/decision-observe.json` (date d'expiration illustrative; la CLI en calcule une réelle).
