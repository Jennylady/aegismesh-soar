# AEGISMESH-SOAR — dépôt autonome

Projet d'orchestration SOAR de **la personne 2** (Shuffle, Wazuh Active Response, Fail2ban, puis EDR / AD). La personne 1 conserve la détection, les graphes, le scoring et la production des décisions/incidents.

## Répertoire et dépôt

- **Répertoire serveur :** `/opt/aegismesh/soar`
- **Git :** `https://github.com/Jennylady/aegismesh-soar`
- **CLI :** `/usr/local/bin/aegismesh-soar` → `bin/aegismesh-soar`
- **Unité installée :** `aegismesh-soar-bridge.service`
- **Configuration privée :** `/etc/aegismesh-soar/soar.env` (root, 0600, non versionnée)
- **État :** `/var/lib/aegismesh-soar/decisions.sqlite3` (root, 0600, non versionné)

**Attention :** c'est un dépôt *distinct* du dépôt principal AEGISMESH. Il n'écrase ni `/opt/aegismesh/source`, ni `aegismesh-shuffle-relay`, ni Wazuh, ni Shuffle, ni Fail2ban, ni Nginx. Il utilise les services existants à travers leurs interfaces. Les credentials restent à configurer localement, jamais sur GitHub.

## Installation initiale, dépôt GitHub encore vide

Transférer **une seule fois** l'archive à ton serveur (exemple `/tmp/AEGISMESH-SOAR-REPO-V2.zip`) :

```bash
sudo mkdir -p /opt/aegismesh/soar
sudo unzip -o /tmp/AEGISMESH-SOAR-REPO-V2.zip -d /opt/aegismesh/soar
cd /opt/aegismesh/soar
sudo bash ops/bootstrap.sh
sudo aegismesh-soar doctor
sudo aegismesh-soar health
```

`bootstrap.sh` : vérifie le chemin, initialise un dépôt Git local s'il est absent, configure `origin`, lance les tests, installe **uniquement** notre service et le CLI, génère de nouveaux secrets root-only. Il **n'effectue aucun push** et n'exécute aucune réponse de sécurité.

**Premier envoi vers GitHub** (nécessite identité Git et autorisation de push du compte/clé Git configuré sur le serveur) :

```bash
cd /opt/aegismesh/soar
git status --short
git add -A
git commit -m 'Initialisation AEGISMESH SOAR V2'
git push -u origin main
```

Si Git demande `user.name` ou `user.email`, configure-les **uniquement pour ce dépôt** (`git config --local ...`). GitHub n'accepte pas le mot de passe du compte pour un push HTTPS : utiliser le mécanisme d'authentification Git déjà autorisé sur le serveur (SSH ou un credential helper sûr). Un dépôt public permet le clone, **pas un push anonyme**.

## Mise à jour (plus aucun ZIP à transférer après le premier push)

```bash
sudo aegismesh-soar update --check
sudo aegismesh-soar update
sudo aegismesh-soar doctor
```

`update` vérifie la branche `main`, l'URL GitHub du dépôt, un *working tree* propre et un historique *fast-forward*. Ensuite il exécute les tests puis **redémarre uniquement** `aegismesh-soar-bridge.service`. En cas d'échec du test/du service, retour au commit précédent de **ce dépôt uniquement**. Il n'effectue ni réinstallation Wazuh, ni changement de jail, ni modification du relais Shuffle principal.

## CLI

```bash
aegismesh-soar doctor
aegismesh-soar test
aegismesh-soar health
aegismesh-soar service-status
aegismesh-soar configure webhook 'http://127.0.0.1:15001/api/v1/webhooks/webhook_ID'
aegismesh-soar submit --tag OBSERVE --wait 15
aegismesh-soar decision DECISION_ID
```

**Aucun workflow réel n'est déclenché à l'installation.** Il faut créer une seule fois dans Shuffle le workflow `AEGISMESH - Decision Dispatcher` avec Webhook + action HTTP de rappel vers `/v1/execute` avant que `OBSERVE` soit démontré de bout en bout. Lire [docs/SHUFFLE.md](docs/SHUFFLE.md).

## Tags reçus

| Tag | Exécuteur | Par défaut |
|---|---|---|
| `OBSERVE`, `ENRICH` | Journal de décision sans modification réseau | Permis après rappel Shuffle |
| `F2B_TEST_BAN` | Jail existante `aegismesh-soar-gcp` avec IP TEST-NET fixe et unban | Désactivé |
| `F2B_BAN_SERVER` | Même jail existante, blocage temporaire d'une IPv4 publique hors réseaux protégés | Désactivé |
| `WAZUH_AR_PROOF` | API Wazuh → script de preuve sur agent explicitement autorisé | Désactivé |
| `WAZUH_BLOCK_AGENT`, `EDR_ISOLATE`, `AD_DISABLE_ACCOUNT` | Futurs playbooks après validation machine et AD | Refusés |

Les actions non triviales requièrent `approved=true`, **deux preuves** et `confidence>=0.90`. `approved` ne doit être produit que par un émetteur de confiance : une alerte brute ne peut pas décider elle-même de l'approbation. Des secrets distincts authentifient le producteur des décisions et Shuffle.

## Fichiers

```text
bin/aegismesh-soar                 CLI install/update/doctor/submit
soar/bridge.py                     API décision → Shuffle → exécution autorisée
soar/soarctl.py                    CLI HTTP authentifié
ops/bootstrap.sh                   1er déploiement sans écraser l'existant
ops/doctor.py                      inventaire Wazuh/Shuffle/Fail2ban (lecture seule)
ops/systemd/                       service dédié, sans lien au service AEGISMESH principal
ops/wazuh/                         script de preuve Active Response facultatif
tests/                             tests de politique + mock Shuffle, sans action réelle
docs/                              plan de connexion, tests, limites et sécurité
examples/                          contrat de décision (exemple non destiné à être exécuté tel quel)
```

Consulter [docs/INTEGRATION.md](docs/INTEGRATION.md) et [docs/SHUFFLE.md](docs/SHUFFLE.md) avant de raccorder des actions.
