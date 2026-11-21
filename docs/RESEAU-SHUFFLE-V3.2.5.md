# Connectivité privée Shuffle → AEGISMESH SOAR

Le bridge écoute sur la passerelle Docker Shuffle, et l'hôte répond HTTP 200. Cependant les conteneurs adressent l’hôte via INPUT ; si UFW applique une politique par défaut DROP, leur requête peut être bloquée. Ce correctif ajoute **uniquement** `ALLOW IN` sur l'interface de `aegismesh-shuffle_shuffle`, du CIDR exact de ce réseau vers l'adresse IP de sa passerelle sur TCP 19081. Il ne change pas `FORWARD`, `DOCKER-USER`, les ports publiés, SSH, WireGuard ou les règles de Fail2ban.

Commande en production, après `aegismesh-soar update` :

```bash
aegismesh-soar network --check
aegismesh-soar network --repair-shuffle --confirm
aegismesh-soar network --check
```

Le contrôle `--repair-shuffle` est idempotent. Si Orborus reste inaccessible immédiatement après insertion d'une nouvelle règle, le correctif révoque cette règle et signale le problème. Si le test Orborus réussit, vérifiez *encore* l'accès depuis le conteneur du worker HTTP Shuffle.

Pour annuler :

```bash
aegismesh-soar network --undo-shuffle --confirm
```

La passerelle et le nom de l’interface sont vérifiés automatiquement par `docker network inspect` et `ip -j address`, sans valeurs codées en dur. La configuration ne doit pas écouter sur `0.0.0.0`. La mise à jour du dépôt ne déclenche pas la correction pare-feu : celle-ci demande `--confirm`.
