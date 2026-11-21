# AEGISMESH SOAR V3 — Correctif CLI + démarrage + dépôt privé

## Objectif

Le paquet V3 met à jour **uniquement** le dépôt `/opt/aegismesh/soar` et le service dédié `aegismesh-soar-bridge.service`. Il n'altère pas `/opt/aegismesh/source`, le relais principal, Wazuh, les quatre conteneurs Shuffle, Fail2ban ni leurs paramètres.

### Migration depuis la V2 **déjà clonée sur le serveur**

Déposer le ZIP dans `/tmp` puis, avec Git configuré pour pousser le commit :

```bash
cd /opt/aegismesh/soar
unzip -o /tmp/AEGISMESH-SOAR-REPO-V3.zip -d /opt/aegismesh/soar
python3 -m py_compile bin/aegismesh-soar soar/bridge.py ops/health.py
python3 bin/aegismesh-soar test
git status --short
git add -A
git commit -m 'AEGISMESH SOAR V3 - CLI interactif et diagnostic de sante'
git push origin main
# Ne réinstalle QUE le bridge du dépôt SOAR
aegismesh-soar install
```

Le `git push` peut échouer si la configuration locale n'a pas l'accès en écriture ; **le serveur n'envoie jamais les secrets**. Pour le cas où l'accès distant n'est pas encore opérationnel, le commit local suffit pour tester `install`; on peut résoudre la publication ensuite.

### La panne "Service actif mais /health inaccessible"

En V2, le test HTTP s'effectuait immédiatement après systemd. En V3, `install` attend jusqu'à 18 secondes, et contrôle la réponse JSON de `/health`. Si le bridge ne peut pas démarrer à cause d'une mauvaise adresse de bind, d'un port occupé, de permissions, d'une exception Python ou d'une autre panne réelle, la commande **échoue toujours**, mais fournit un diagnostic clair sans changer Wazuh ni Shuffle :

```bash
aegismesh-soar health --verbose
systemctl status aegismesh-soar-bridge.service --no-pager
journalctl -u aegismesh-soar-bridge.service -n 60 --no-pager
ss -lntp | grep ':19081'
```

Supprimer les éventuelles informations sensibles des sorties de journal avant de les partager.

## Menu et couleurs

```bash
aegismesh-soar                   # menu animé dans un terminal interactif
aegismesh-soar configure         # assistant de configuration (pas d'argument obligatoire)
aegismesh-soar configure status  # état sans afficher les secrets
aegismesh-soar health --verbose
aegismesh-soar network           # interfaces hôte et réseaux Shuffle Docker
aegismesh-soar --no-color doctor
```

Couleurs et animation uniquement en terminal, sinon logs lisibles. La variable `NO_COLOR=1` supprime aussi la couleur. Aucune bibliothèque à installer.

## Connecter le vrai Shuffle

1. Vérifier `aegismesh-soar health --verbose`. Le bridge doit répondre avant de créer un workflow.
2. `aegismesh-soar network` permet de **recenser** les réseaux Docker sans en changer les paramètres. Attention : un conteneur de worker peut utiliser une autre interface que `shuffle-orborus`.
3. Dans Shuffle, créer un workflow *AEGISMESH SOAR V3 - Dispatcher*, webhook activé, puis action HTTP POST de rappel vers `http://ADRESSE_PRIVEE_DU_SERVEUR:19081/v1/execute` avec le header `X-Aegismesh-Token` contenant la valeur privée de `SHUFFLE_ACTION_TOKEN`. Les variables `decision_id` et `execution_id` doivent venir du webhook et de l'exécution effective, pas d'un exemple codé en dur. **Ne jamais publier le token dans le dépôt GitHub ni dans une capture.**
4. Après création du webhook Shuffle, saisir son URL depuis `aegismesh-soar configure`, rubrique webhook. Le backend Shuffle actuel répond déjà HTTP 200 à `/api/v1/health`; **cela ne prouve pas encore que ce nouveau workflow fonctionne**.
5. Si le worker ne peut pas accéder au bind `127.0.0.1`, envisager une interface IPv4 privée **réellement assignée** à l'hôte (`configure bind IP`) uniquement après vérification de ses restrictions réseau. Ne jamais binder sur `0.0.0.0` pour corriger aveuglément un problème Docker.
6. Valider d'abord une décision `OBSERVE`, puis vérifier l'identifiant d'exécution et le retour final dans Shuffle et la commande `aegismesh-soar decision ID`.
7. Tester seulement ensuite le tag `F2B_TEST_BAN` avec sa cible TEST-NET réservée, avec accord explicite, puis la commande de preuve Wazuh avec agent de test autorisé. Pas de remédiation de production avant validation réelle.

## Wazuh

L'API Wazuh nécessite un compte autorisé, une URL compatible TLS et un certificat CA de confiance. Configurer avec `aegismesh-soar configure wazuh`, puis au besoin `aegismesh-soar configure wazuh-ca /chemin/ca.pem`. Le certificat doit être lisible par le service; ne pas désactiver la validation TLS pour contourner une erreur. Le pont **n'invente pas** les identifiants ni les récupère automatiquement des secrets de l'installation principale.

## Future transition GitHub vers privé

Tant que GitHub est public, le `git fetch` HTTPS fonctionne. Avant de passer le dépôt en privé :

```bash
aegismesh-soar repo status
aegismesh-soar repo prepare-private
```

La deuxième commande génère sur le serveur une clé SSH dédiée, sous `/etc/aegismesh-soar/keys/`, **sans afficher la clé privée**. Copier seulement la clé publique affichée dans GitHub : `Repository > Settings > Deploy keys > Add deploy key`, sans autoriser l'écriture. Vérifier aussi de manière sûre la clé hôte SSH de `github.com` (documentation officielle GitHub).

```bash
aegismesh-soar repo use-ssh
# Cette commande vérifie d'abord l'accès, puis seulement si OK modifie origin.
aegismesh-soar update --check
```

Tu peux ensuite changer la visibilité du dépôt dans les paramètres GitHub. La clé de déploiement est en lecture seule, suffisante pour `aegismesh-soar update`. Pour **pousser** les modifications, utilise ton compte GitHub/clé développeur disposant des droits d'écriture. Le changement de visibilité lui-même n'est pas effectué par ce package.

## Préservation des données

- Secrets : `/etc/aegismesh-soar/soar.env`, jamais inclus dans Git.
- Historique d'exécution : `/var/lib/aegismesh-soar/decisions.sqlite3`, jamais inclus dans Git.
- `aegismesh-soar update` conserve les deux emplacements et met à jour uniquement le dépôt SOAR.
- Les actions à impact (confinement Windows, désactivation AD, blocage serveur) restent verrouillées tant qu'aucun test bout en bout n'a confirmé le bon chemin de retour.
