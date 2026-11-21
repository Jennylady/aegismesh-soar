# Mises à jour AEGISMESH-SOAR

## Flux de travail

Publier un correctif sur la branche `main` du nouveau dépôt GitHub **aegismesh-soar** (la branche ne doit pas être rebâsée/force-push en production). Puis sur le serveur :

```bash
sudo aegismesh-soar update --check
sudo aegismesh-soar update
```

L'update :

1. vérifie que `/opt/aegismesh/soar` est un dépôt Git, branche `main`, `origin` correspond au dépôt attendu et que les fichiers suivis sont propres ;
2. `git fetch origin main` (sans installer de nouveaux composants externes) ;
3. impose `merge-base --is-ancestor` et `git merge --ff-only` ;
4. lance les tests locaux Python et le fake webhook ;
5. actualise et redémarre **uniquement** l'unité systemd `aegismesh-soar-bridge.service`, quand installée ;
6. contrôle sa disponibilité HTTP, et restaure l'ancien commit si les tests/service échouent.

N'effectue **pas** : `apt install`, `docker compose down/up`, modifications d'agent.conf/ossec.conf, modification de jails, changement WireGuard, modification du service `aegismesh-shuffle-relay` ou des services de la personne 1.

La configuration root-only et la base SQLite persistent dans `/etc/aegismesh-soar` et `/var/lib/aegismesh-soar`. Ne **jamais** placer de secrets ou backups SQLite dans le dépôt public. `git clean -fdx` ou `git reset --hard` manuel sur des données non versionnées ne fait pas partie des procédures recommandées.

En cas de modifications locales de code, l'update s'arrête : committer ou transférer les changements sur la branche maintenue avant de retenter. Un update n'est pas un mécanisme pour écraser du travail local.

Les tests ne prouvent pas un vrai workflow en production; contrôler `aegismesh-soar doctor`, puis une décision `OBSERVE` et l'exécution Shuffle si l'intégration est déjà câblée.
