## 3.5.2 — Diagnostic ciblé Windows 001 et observabilité Active Response

- Nouveau `aegismesh-soar fleet evidence diagnose --agent-id 001 --decision-id <ID>` : lecture seule, refuse les incohérences agent/décision et ne déclenche aucune action distante.
- Nouveau `ops/wazuh/windows/Diagnose-AegisMeshProof.ps1` : inventaire local, journaux d’exécution, état de la collecte et erreurs Wazuh, sans générer de fausse preuve.
- Le lanceur Windows journalise son code de sortie non nul ; le script PowerShell journalise uniquement le type d’exception, jamais la charge utile ni les secrets.
- Les règles Wazuh, le bridge de production, le pare-feu, les actions de remédiation et les scripts de confinement restent inchangés.

## 3.5.1 — tests isolés de l'inventaire SSH (aucun changement des actions en production)

- Corrige le test `test_live_actions_v33.py` : l'inventaire des sessions SSH est simulé uniquement pendant les tests ; il ne dépend plus du système Kali ni d'un binaire `ss` présent sur l'hôte de test.
- Valide explicitement que la protection refuse une IP de session SSH (1.1.1.1 dans le test) et reste **fail-closed** si l'inventaire SSH échoue.
- Aucun changement du bridge, de Wazuh, de Shuffle, de Fail2ban ou des règles réseau en production.

## 3.5.0 — preuve d’exécution agent → manager

- Journal dédié et collecte explicite sur Kali/Windows/AD sans changement de comportement des services critiques.
- Deux règles d’alerte Wazuh locales, contrôlées et réversibles.
- Réconciliation en lot des décisions par agent et identifiant, sans faux succès sur API ACK.
- Gestion intégrée via `aegismesh-soar fleet evidence`.

## V3.4.0 — Fleet Wazuh Windows / AD / Kali

- Le CLI sur Kali ne requiert pas Wazuh API; les identifiants restent sur GCP.
- `fleet status`, `fleet proof --agent-id`, `fleet verify --agent-id <ID> <decision>` sur GCP.
- Exécutable Windows natif `.cmd` + `.ps1` sans modification des comptes AD, du pare-feu ni du registre.
- Installateur Windows sur les deux postes (administrateur Windows, redémarrage Wazuh optionnel et explicite).
- Installateur de preuve Linux indépendant du script de blocage existant.
- Les deux scripts remontent un marqueur de décision dans active-responses.log standard; preuve rapprochée avec l’agent ID dans alerts.json / archives.json.
- Réconciliation des exécutions `dispatched_unverified` toutes les 5 secondes quand le log collecté est disponible.
- Aucune activation de réponse réseau ou modification de Wazuh ossec.conf pendant update.

## V3.3.0 — Exécution réelle Wazuh et Fail2ban

- Intégration TLS de l’API Wazuh locale via son certificat serveur installé ; messages d’erreur explicites.
- Action WAZUH_BLOCK_AGENT sur agent Linux explicitement autorisé, utilisant un exécuteur nftables agent-side avec TTL 120 s.
- Action F2B_BAN_SERVER exigeant une vérification nftables de la jail SOAR et un bantime borné.
- Configuration production opt-in, liste d’agents, CIDR de gestion et commandes chain pour les actions réelles.
- Scripts d’installation agent Kali/Linux et tests d’adaptateurs et TLS sans effet réseau.
- Statut `dispatched_unverified` conservé tant que l’action agent distante n’est pas vérifiée.

## 3.2.3 — Exploitation et sécurité

- `aegismesh-soar logs --lines 70` : accès direct aux journaux du bridge, sans toucher aux autres services.
- `aegismesh-soar configure rotate-action-token` : rotation explicite et interactive du jeton `SHUFFLE_ACTION_TOKEN`, conservation des autres secrets, redémarrage limité au bridge et vérification HTTP.
- Le jeton n'est affiché qu'une fois dans le terminal à l'issue d'une rotation réussie ; il ne doit pas être mis dans Git ou des captures.
- Test de non-régression : refus de rotation en mode non interactif, aide CLI pour logs et rotation.

# Journal des versions

## 3.2.2 — 21 novembre 2026

- Corrige le rejet des URL de webhook Shuffle émises par l’instance on-prem : accepte `/api/v1/hooks/webhook_...` et `/api/v1/webhooks/webhook_...`.
- Conserve le filtrage des schémas, hôtes HTTP loopback, identifiants, fragments et paramètres.
- Ajoute un test de non-régression exécuté automatiquement avant `aegismesh-soar update`.
- Documente la distinction frontend 18031/backend 15001 et le déclencheur `Start` dans Shuffle.

## 3.1.0 — 21 novembre 2026

- Nouveau `ExecStartPost`: la commande `systemctl restart` attend l’HTTP `/health` (jusqu’à 30 s). Compatible avec la mise à jour depuis la V2; supprime le faux échec de démarrage rapide.
- En cas de véritable panne, diagnostic détaillé avant rollback, au lieu de masquer l’erreur.
- Vérification de santé même si Git est déjà à jour, afin de ne pas confondre « commit synchronisé » avec « service sain ».
- Tests de régression avec démarrage HTTP retardé et échec confirmé en cas d’indisponibilité.
- Mode opératoire Kali → GitHub → serveur : aucun upload ou commit sur GCP.

## 3.0.0 — 21 novembre 2026

- CLI avec bandeau coloré, menu interactif et animations adaptées au terminal.
- `aegismesh-soar configure` ouvre un menu plutôt qu'une erreur de syntaxe.
- Lecture seule `configure status`, `network` et `health --verbose`.
- `install` et `update` attendent la réponse réelle du bridge avant de valider un déploiement (18 secondes), avec diagnostic si échec.
- Réutilisation de l'adresse privée configurée dans `soarctl` (suppression du localhost codé en dur).
- Préparation au dépôt privé : `repo status`, `repo prepare-private`, `repo use-ssh` via clé SSH de déploiement en lecture seule.
- `configure wazuh-ca` pour le certificat d'API Wazuh sans désactiver TLS.
- Aucune activation automatique d'actions de production, aucun remplacement du relais Shuffle existant.

## 2.0.0

- Premier dépôt autonome et CLI SOAR.

## V3.2 — Chaîne d'exécution (21 novembre 2026)

- Ajoute `aegismesh-soar chain` : état des liaisons, guide du vrai workflow Shuffle, installation contrôlée de l'exécutable de preuve Wazuh, vérification TLS/auth de l'API, validation `OBSERVE`, test Fail2ban explicite et preuve Wazuh.
- La commande de soumission attend désormais le **statut d'action terminal** : une acceptation HTTP du webhook Shuffle ne vaut plus succès.
- En cas de preuve `WAZUH_AR_PROOF` sur l'agent local `000`, le bridge recherche une preuve effective dans le journal prévu. Sinon il maintient `dispatched_unverified`.
- Refuse un second identifiant d'exécution différent pour la même décision : prévention des doubles exécutions via deux workflows.
- Aucun déploiement automatique de workflow existant, aucune modification de `ossec.conf`, de Shuffle Docker ni des jails Fail2ban.

## 3.2.4 — Permission CLI et diagnostic Docker

- Restaure et verrouille le mode Git **100755** pour `bin/aegismesh-soar`,
  empêchant le retour de `Permission denied` après mise à jour.
- Ajoute `aegismesh-soar network --check`, une vérification réseau lecture seule
  de l’hôte et du namespace d’Orborus vers `/health`.
- Ne change aucun réseau Docker, nftables, service Wazuh ni Fail2ban.
- Permet une récupération ponctuelle avec `python3 /opt/aegismesh/soar/bin/aegismesh-soar update`
  si le CLI déjà déployé a perdu son bit exécutable.

## 3.2.5 — Shuffle réseau privé
- `aegismesh-soar network --repair-shuffle --confirm` : règle UFW persistante limitée au bridge Docker Shuffle et au bridge SOAR 19081.
- Sonde Orborus post-application ; annulation automatique si échec.
- `aegismesh-soar network --undo-shuffle --confirm` : suppression de la seule règle gérée par SOAR.
- Aucune réinstallation de Shuffle/Wazuh/Fail2ban ; tests locaux de politique.
