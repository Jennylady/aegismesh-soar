### Nouveau : remédiation AD/LDAP V3.8.0

L'action `AD_DISABLE_ACCOUNT` est implémentée, mais **désactivée par défaut**. Elle réutilise les vrais rappels Shuffle / Wazuh agent `006`, exécute `Disable-ADAccount` uniquement sur un utilisateur SID du domaine inscrit dans le groupe d'éligibilité et vérifie `Enabled=False` avant de publier une preuve. Pour la procédure Windows DC / GCP et les limites de sécurité, voir `docs/AD-LDAP-REMEDIATION-V3.8.md`. Aucun score ni preuve d'incident n'est généré par le dépôt SOAR.

### Correctif 3.7.4 — schéma des collectes

`edr flows`, `edr flow-status` et `edr investigations` reconnaissent `session_id` tel que retourné par le serveur Velociraptor. Si `state` est absent, l'outil consulte `get_flow()` sans jamais attribuer un état final par déduction. Voir `docs/EDR-FLOWS-V3.7.4.md`.

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

## Développement et publication — uniquement sur Kali

**Flux officiel :** modifications et tests dans `/home/lady/SOUTENANCE/aegismesh-soar` → `git commit` → `git push origin main` → `aegismesh-soar update` sur GCP. **Ne jamais extraire un ZIP ni effectuer de commit sur le serveur GCP.**

Pour appliquer un patch livré par ChatGPT, depuis **Kali** :

```bash
cd /home/lady/SOUTENANCE/aegismesh-soar
unzip -o /chemin/vers/AEGISMESH-SOAR-PATCH-V3.1.zip
python3 bin/aegismesh-soar test
git add -A
git commit -m "fix: synchronize systemd readiness with SOAR update"
git push origin main
```

Puis, sur **le serveur GCP**, uniquement :

```bash
aegismesh-soar update
# Si le service était déjà indisponible avant la mise à jour :
aegismesh-soar health --verbose
```

`update` utilise toujours fast-forward only, valide les tests et redémarre **uniquement** `aegismesh-soar-bridge.service`. Le service systemd inclut désormais `ExecStartPost`, qui attend effectivement `/health` avant que `systemctl restart` se termine. Ce mécanisme est compatible avec l'updater V2 actuellement présent sur GCP (il copie le nouveau fichier unit avant de relancer systemd).

**Limite :** si le service est réellement cassé (erreur Python, port déjà occupé, configuration invalide), le contrôle doit échouer et le rollback est normal. Lire le journal du service pour connaître l'erreur exacte. Aucun patch ne doit masquer cette panne en annonçant un succès fictif.

Les secrets et la base restent hors Git, dans `/etc/aegismesh-soar/` et `/var/lib/aegismesh-soar/`. Le dépôt peut devenir privé : préparer une deploy key SSH en lecture seule sur le serveur avant de modifier sa visibilité.

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

## Nouveautés V3 — déploiement et configuration

Lire [docs/DEPLOIEMENT-V3.md](docs/DEPLOIEMENT-V3.md) pour migrer depuis V2 sans toucher à la configuration existante, diagnostiquer le bridge, utiliser le nouveau menu coloré, préparer le dépôt privé et connecter le vrai workflow Shuffle.

```bash
aegismesh-soar                # menu interactif coloré
aegismesh-soar health --verbose
aegismesh-soar configure      # menu guidé
aegismesh-soar network
aegismesh-soar repo prepare-private
```

## Correctif V3.1 — readiness systemd et mise à jour depuis Kali

Lire [docs/DEPLOIEMENT-V3.1.md](docs/DEPLOIEMENT-V3.1.md). Le patch ne déploie aucun workflow Shuffle ni action Wazuh/Fail2ban réelle.


## Chaîne d’exécution réelle V3.2

Utiliser `aegismesh-soar chain status`, `aegismesh-soar chain guide`, puis `aegismesh-soar chain observe` après création du workflow. Documentation complète : [docs/CHAINE-EXECUTION-V3.2.md](docs/CHAINE-EXECUTION-V3.2.md). Le raccordement au vrai Shuffle nécessite l’URL et les secrets configurés localement ; le code n’invente aucun workflow réel ni identifiant d’exécution.

### Exploitation V3.2.3

Sur le serveur GCP, consulter `aegismesh-soar logs --lines 70` ou renouveler le jeton compromis avec `aegismesh-soar configure rotate-action-token`. Reporter le nouveau secret uniquement dans l'en-tête d'authentification de l'application HTTP de Shuffle. Ne jamais le publier.

### Récupération après perte du droit exécutable (V3.2.4)

Le correctif se publie uniquement depuis Kali avec `git add -A && git update-index --chmod=+x bin/aegismesh-soar`, puis commit/push. Sur GCP, **une seule fois**, lancer `python3 /opt/aegismesh/soar/bin/aegismesh-soar update`. La commande directe `aegismesh-soar update` fonctionne à nouveau après ce fast-forward.

La commande `aegismesh-soar network --check` réalise deux GET /health depuis l’hôte puis depuis le namespace Orborus; elle ne modifie aucun pare-feu. Un échec depuis Orborus nécessite une inspection de la politique INPUT, ainsi qu’un essai depuis le vrai worker Shuffle.

### Réseau Shuffle → bridge (UFW)
Après validation `health`, si `network --check` retourne un timeout depuis Orborus et UFW est actif, utiliser en root `aegismesh-soar network --repair-shuffle --confirm`. La commande détecte passerelle, interface et CIDR de `aegismesh-shuffle_shuffle`, refuse tout bind public, ajoute une règle INPUT ciblée et teste `/health` depuis Orborus. Si le test échoue, elle retire la règle. Pour retour arrière explicite : `aegismesh-soar network --undo-shuffle --confirm`. Il faut ensuite vérifier le réseau du worker HTTP (potentiellement différent).


### Actions opérationnelles V3.3

Consulter `docs/EXECUTION-REELLE-V3.3.md`. Les tags `F2B_BAN_SERVER` et `WAZUH_BLOCK_AGENT` disposent désormais d’exécuteurs réels, mais restent soumis à l’activation explicite, à la protection des IP de gestion, aux preuves et aux listes d’agents autorisés. Le script Active Response `aegismesh-soar-block` doit être installé sur **chaque agent Linux cible**. Une acceptation par l’API Wazuh ne prouve pas à elle seule une action exécutée sur l’agent.


## Fleet V3.4

Sur GCP uniquement: `aegismesh-soar fleet status`, `aegismesh-soar configure wazuh-proof-agents 001,002,006`, `aegismesh-soar configure enable-tests`, puis `aegismesh-soar fleet proof --agent-id 002`.
Sur Kali, installer l'Active Response de preuve avec `sudo bash ops/wazuh/install_agent_proof.sh`. Sur chaque Windows, déployer `ops/wazuh/windows/*` avec l'installateur PowerShell administrateur. Le manager conserve les identifiants et le webhook Shuffle existants. Voir `docs/FLEET-WAZUH-V3.4.md`.

## V3.5 - preuves réelles du parc Wazuh

`aegismesh-soar fleet evidence status`, `fleet evidence install --apply --confirm` et `fleet evidence reconcile` relient les exécutions réelles des agents aux décisions Shuffle (voir `docs/PREUVES-AGENTS-V3.5.md`).

### Diagnostic agent Windows 001 (V3.5.2)

`aegismesh-soar fleet evidence diagnose --agent-id 001 --decision-id am-7cb8f4e2c76e13cda871c0fa` sur GCP vérifie le statut sans envoyer de commande. Sur le poste Windows, `ops/wazuh/windows/Diagnose-AegisMeshProof.ps1 -DecisionId ...` inspecte les journaux et le collecteur sans nouvelle action. Les exécuteurs Windows journalisent désormais les erreurs d'exécution sans inclure les données de la commande.


### Windows Firewall containment V3.6
See `docs/WINDOWS-EDR-V3.6.md`. The Wazuh 4.14 AR executor creates a temporary **remote public IPv4 only** inbound/outbound rule (120s), verifies effective firewall rules and records evidence. This is not full endpoint network isolation. Velociraptor is a separate open-source DFIR/EDR service and remains untouched; existing Wazuh proof collectors are reused.

### V3.7 — Orchestration et Velociraptor

Exécuter sur GCP `aegismesh-soar orchestrate status`, `aegismesh-soar orchestrate catalog`, `aegismesh-soar edr discover`, puis raccorder le certificat API mTLS **existant** de Velociraptor. Les tags EDR prennent leurs identifiants, confiance et preuves des décisions structurées déjà envoyées au bridge — aucune ressaisie interactive par incident. Documentation : `docs/ORCHESTRATION-EDR-V3.7.md`.

### Raccorder le Velociraptor existant (V3.7.1)

`aegismesh-soar edr doctor` affiche le conteneur et les chemins de configuration **sans secrets**. `aegismesh-soar edr setup --confirm` accepte une configuration API mTLS existante après test réel. Si aucune clé API n'est présente et qu'un volume Docker persistant est détecté : `aegismesh-soar edr bootstrap --confirm --allow-restart` crée une identité API limitée aux rôles `api,investigator` et redémarre **le conteneur Velociraptor uniquement**, après accord explicite. Consulter `docs/EDR-DOCKER-V3.7.1.md`.

### Suivi EDR (V3.7.2)

```bash
aegismesh-soar edr flows
aegismesh-soar edr flow-status --agent-id 001 --flow-id F.DC1APVLV8NO1Q
aegismesh-soar edr flow-status --agent-id 002 --flow-id F.DC1B583LF7L32
aegismesh-soar edr investigations
```

L'API Velociraptor est interrogée en lecture seule. Un flow `FINISHED` n'implique pas automatiquement des résultats : `result_rows_sampled`, `sample_sha256` et `results_present` sont renvoyés séparément. Le suivi local est dans `/var/lib/aegismesh-soar/edr-flow-tracker.json` (hors Git).

### Correctif V3.7.3 : schéma Velociraptor des flows

`flows()` peut exposer `FlowId`/`ClientId`/`State` plutôt que les propriétés snake_case de `collect_client()`. Le suivi normalise les deux formats et refuse une attribution incohérente. Les anciens Flow IDs sont conservés, sans nouvelle collecte ni réinstallation.
