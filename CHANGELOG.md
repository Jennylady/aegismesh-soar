## 4.2.8 — Affectation automatique du moniteur Velociraptor (LAB 001)
- Diagnostique précisément `Windows.Remediation.QuarantineMonitor` dans les groupes de surveillance Velociraptor (liste `specs` et liste `artifacts`). Ne confond plus simple présence dans la configuration avec affectation effective.
- `aegismesh-soar edr lab-quarantine monitor-status --agent-id 001`: lecture seule, indique les groupes qui contiennent réellement le moniteur.
- `aegismesh-soar edr lab-quarantine monitor-ensure --agent-id 001 --confirm`: ajoute le moniteur uniquement au groupe `Quarantine`, via l'API mTLS Velociraptor et `add_client_monitoring` ; requiert `COLLECT_CLIENT` et contrôle la configuration après écriture.
- Refus si d'autres clients sont déjà en quarantaine ou si un bail SOAR existe ; ne pose pas le label `Quarantine`, ne redémarre aucun service, ne modifie pas le DC ni les autorisations API.
- Le test d'isolation V4.2.7 reste séparé et protégé (`--console-access`, bail 180 s, retrait, identité 001). Aucune preuve d'isolation réseau n'est annoncée sans mesure sur Windows.

## 4.2.7 — Test scripté de la quarantaine réelle Windows LAB (sans interface Velociraptor)
- Ajoute `edr lab-quarantine start/status/logs/release`, limité à l'agent 001 et au client EDR explicitement vérifié. CLI root seule, confirmation explicite et accès console de secours obligatoires.
- Utilise l'API mTLS Velociraptor existante pour poser le vrai label `Quarantine` et le moniteur `Windows.Remediation.QuarantineMonitor`, avec bail de laboratoire de 180 secondes enregistré avant l'opération, et timer automatique de retrait déjà installé.
- Ne modifie pas `ENABLE_EDR_ISOLATION`, ne simule pas de décision/score IA, ne touche jamais au contrôleur de domaine. Le statut distingue le label et la **preuve réelle** de la coupure réseau Windows.
- Ajoute un accès borné aux logs client du moniteur et des tests isolés (aucune vraie quarantaine créée durant l'update).

## 4.2.6 — Accès Netlink du bridge et diagnostic nftables
- Corrige l'échec `Table nftables SOAR inaccessible` sur GCP malgré une table nftables présente et lisible depuis un terminal root : l'unité systemd du bridge excluait `AF_NETLINK` de `RestrictAddressFamilies`.
- Ajoute uniquement `AF_NETLINK` aux trois familles déjà autorisées (`AF_INET`, `AF_INET6`, `AF_UNIX`) ; conserve `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`, et les protections des IP.
- Retourne un message d'erreur classifié (famille socket interdite, refus de permission, table absente, inconnu), sans divulguer les sorties brutes de nft dans le callback.
- Ajoute un test de non-régression de l'unité systemd et des diagnostics. Aucune règle nftables, jail, IP, Wazuh, Shuffle ou politique EDR n'est modifiée.

## 4.2.5 — Vérification de la chaîne Fail2ban/nftables GCP
- Reconnaissance exacte de `inet aegismesh_soar_gcp`, set `aegismesh_block_v4`, chaîne d’entrée et règle `tcp dport 443 ... drop` via `nft -j`.
- Bannissement de test `198.51.100.42` : preuve de présence dans nftables pendant le ban, absence après l’unban ; aucune IP réelle testée.
- Erreur explicite en cas de règles absentes, inattendues ou JSON illisible ; impossibilité de déclarer `removed` sur simple absence du set.
- Retour arrière du ban de production nouvellement posé si la vérification nftables échoue ou lève une exception.
- Aucun changement Wazuh, Docker, Tenzir, Nginx, IP de gestion, ni règle nftables statique.

## V4.2.4 — Surcharge Compose ciblée, sans parser le YAML d origine

- Corrige `Bloc Compose services.orborus introuvable ou ambigu` provoqué par un éditeur qui supposait exactement deux espaces d indentation.
- L original `/opt/aegismesh/integrations/shuffle/compose.yaml` reste inchangé. Un override minimal propre à AEGISMESH-SOAR ne définit que les deux variables des pipelines du service Orborus.
- Avant de redémarrer Orborus: fusion contrôlée `docker compose -f base -f override config --format json`, comparaison stricte du reste des services et des paramètres Compose, préconditions Wazuh/Orborus/Tenzir.
- `up -d --no-deps --no-build orborus` ciblé; post-contrôles sur variables dans le conteneur, identité du Compose, propriété Wazuh du port 1514/TCP, journaux Orborus. Arrêt et retour arrière si échec.
- Aucun changement de Wazuh, de Fail2ban, des agents, du pare-feu ou de la politique EDR. Pas de suppression de conteneur Tenzir.

## V4.2.3 — Détection fiable du port Wazuh (1514/TCP)

- Corrige un faux négatif dans le contrôle `ss -lntp` : l'ancien motif écartait `0.0.0.0:1514` à cause du chiffre précédant `:`.
- Analyse la colonne locale et le champ processus, exige un port TCP 1514 exact et l'attribution explicite à `wazuh-remoted` ; refuse les autres propriétaires, PID absents ou résultats incomplets.
- Convertit les erreurs de précondition du module Tenzir en messages CLI propres, sans traceback Python dû à la double importation de `AuditError`.
- Aucun changement Wazuh, Tenzir, Docker, pare-feu, Shuffle, EDR, secrets ou décisions lors de l'update. La suspension optionnelle des pipelines requiert toujours `--confirm`, conserve la sauvegarde et le rollback.

## V4.2.2 — Conflit de ports Tenzir/Wazuh, mode pipeline optionnel

- Confirme le conflit réel : Wazuh `wazuh-remoted` conserve `1514/TCP` ; Tenzir veut publier `1514/TCP` via toutes interfaces.
- `aegismesh-soar audit tenzir --pipeline-status` : diagnostic en lecture seule (Orborus / Compose / propriétaire de port).
- `aegismesh-soar audit tenzir --disable-pipelines --confirm` : suspend *uniquement* les pipelines Tenzir dans l'environnement du service Orborus par le Compose existant. Sauvegarde hors Git (`/var/lib/aegismesh-soar/compose-backups`, mode 0600), modification validée par `docker compose config --format json` et comparaison stricte de tous les services, redéploiement ciblé `--no-deps --no-build orborus`. Restauration automatique de la configuration si le contrôle Orborus échoue.
- Cette option **ne répare pas Tenzir** : elle élimine ses tentatives de lancement dans la chaîne SOAR classique. Elle ne doit pas être utilisée si les pipelines de détection/Sigma Shuffle sont nécessaires.
- Aucun réseau ou conteneur Tenzir supprimé, pas de changement du port Wazuh, aucune action de sécurité sur les agents.

## 4.2.1 — Référence réseau Tenzir obsolète sous Docker bridge

- `audit tenzir` inspecte aussi `NetworkSettings.Networks` et identifie les rattachements à `tenzir-network` même si `HostConfig.NetworkMode=bridge`.
- `audit tenzir --repair --confirm` accepte seulement un rattachement explicite au réseau manquant et conserve les contrôles image, identité, exposition des ports et état.
- Si Docker refuse le démarrage à cause d’un ancien identifiant réseau, la procédure s’arrête sans suppression du conteneur, sans reconnexion forcée et sans modification des volumes.
- Réparation ciblée Tenzir uniquement : aucune modification automatique des politiques de blocage, du bridge, des workers ou de l’isolation EDR.

## 4.2.0 — Audit sur preuves et récupération contrôlée Tenzir

- `aegismesh-soar audit status` : inventaire non destructif de Docker Shuffle, Tenzir, du bridge, des timers, des décisions réellement enregistrées et de l'état EDR.
- `aegismesh-soar audit tenzir --repair --confirm` : reconstitution strictement contrôlée du réseau manquant du conteneur Tenzir existant, refus des configurations ambiguës ou de ports publiés globalement.
- `aegismesh-soar audit worker --confirm` : une décision `OBSERVE` réelle et sans action de sécurité; vérification du callback authentifié ainsi que observation non attributive d'éventuels workers éphémères.
- `aegismesh-soar audit blocks [--probe --confirm]` : corrélation décisions/résultats réels et sondes existantes en lecture seule, sans inventer de preuve si un endpoint n'est pas testé.
- `aegismesh-soar audit timers [--ensure --confirm]` : état des deux timers, installation optionnelle des seuls timers gérés.
- `aegismesh-soar audit edr` : affiche clairement l'isolation désactivée et l'absence de preuve de filtrage réseau; exclusion du contrôleur de domaine conservée.
- Aucun changement automatique des secrets, Wazuh, Windows, Firewalls, règles EDR ou conteneurs Shuffle lors de `update`.

## 4.1.0 — Diagnostic de la chaîne SOAR vérifiable (sans action)

- `chain status` distingue le header webhook sortant facultatif du jeton de rappel Shuffle obligatoire.
- Le retour Shuffle est établi par un callback **historique authentifié** et exécuté enregistré en base ; il n’est jamais présenté comme une preuve de disponibilité en temps réel.
- La confiance TLS Wazuh reflète le certificat local exploité sur l’API loopback ou une CA explicite, sans prétendre que le handshake HTTPS a été testé.
- Aucun changement aux secrets, configurations de production, pare-feu, Wazuh, Shuffle, Velociraptor ou moteur de décision.
- Test de non-régression de la lecture SQLite et de l’affichage d’états.

## 4.0.1 — Tests EDR multiplateformes (2026-11-22)
- `test_edr_triage_v40.py` simule explicitement le contrôle root pour les tests hors production Windows/Linux; tous les appels EDR et les écritures sont simulés.
- `require_root()` refuse proprement l'absence de `os.geteuid` sous Windows (PermissionError au lieu d'AttributeError) et continue d'exiger root sur Linux GCP.
- Test de non-régression `test_edr_root_guard_v401.py`. Aucune configuration ni action distante modifiée.

## 4.0.0 — Evidence-based response lifecycle (2026-11-22)
- PostgreSQL `response_checks` and exact Wazuh endpoint read-only block-state probes, bound to agent/decision/check/IP.
- Linux nftables and Windows Firewall verified scopes, Wazuh rules 119877-119878, systemd bounded post-TTL audit timer (opt-in).
- Optional progressive isolation gate requiring prior verified scoped block and recent completed EDR collection; no auto isolation.
- OS-specific EDR triage, renamed Kali/Velociraptor host attestation, read-only quarantine monitor audit.
- Windows DC Kerberos/NTLM event exposure inspection without account/session mutation.
- Local unit tests only: no remote firewall, Windows AD or EDR action performed during patch creation.

## 3.9.2 — AD lab : appel sur interface locale Docker (2026-11-22)

- Corrige `Bridge non-local` lorsque `SOAR_BIND_HOST` est la véritable passerelle Docker locale au lieu de `127.0.0.1`.
- Vérifie que l'adresse IPv4 d'écoute est réellement attribuée à une interface GCP (`ip -j address show`), sans DNS, sans URL distante et sans modifier les restrictions réseau.
- Utilise le même point d'accès local pour `/health` et `POST /v1/decisions`, avec le jeton SOAR privé existant.
- Vérifie la santé HTTP **avant** de modifier `AD_LAB_UNTIL`; garde le ciblage SID du vrai compte, les protections AD et l'étape Shuffle/Wazuh inchangés.
- Test unitaire fail-closed des interfaces locales, des adresses distantes et de la séquence de soumission. Aucun compte AD modifié par les tests.

## 3.9.1 — Wazuh API readiness for AD (2026-11-22)

- `aegismesh-soar ad doctor`: read-only Wazuh service, local API, AD evidence rule and DC allowlist diagnosis.
- `aegismesh-soar ad recover --confirm`: one guarded manager restart only if the local API is unavailable; refuses unsafe configuration or invalid analysis rules and verifies authenticated readiness.
- `fleet evidence install` now also waits for the Wazuh HTTPS listener after service restart without rolling back valid rules on API-only delay.
- `aegismesh-soar ad probe --confirm` waits for port 55000 after Wazuh rule installation before a single read-only Active Response dispatch.
- AD status now distinguishes unconfigured DC fields from the existing pre-probe allowlist for agent 006.
- No changes to PostgreSQL, AD accounts, the Windows executor, or production decision policy.

## 3.9.0 — PostgreSQL SOAR + validation réelle AD/LDAP sur compte de laboratoire

- Commande intégrée `database migrate --apply --confirm` : provision PostgreSQL local isolé, secret root-only hors Git, sauvegarde SQLite, copie transactionnelle, empreinte SHA-256 intégrale et bascule avec contrôle de santé.
- `bridge.dbconn()` supporte SQLite et PostgreSQL avec fermeture des connexions, SQL paramétré et même contrat de lignes ; `orchestrate recent` et `ad status` compatibles PostgreSQL.
- Action réelle distincte `AD_LAB_DISABLE` : origine `operator_lab`, sans score IA ni preuves fictives, fenêtre temporaire, SID réel, passage obligatoire par Shuffle et Wazuh agent 006, contrôle indépendant du préfixe `aegis-lab-*` sur le DC.
- Création d'un nouveau compte AD de laboratoire explicitement autorisée, mot de passe saisi de façon sécurisée, ajout au groupe d'éligibilité. Aucun compte réel existant modifié sans action explicite.
- Tests unitaires de migration et de politique du laboratoire, sans PostgreSQL ni AD réels.

## 3.8.1 — Correction fermeture SQLite pour les tests AD sous Windows

- Les connexions `bridge.dbconn()` sont maintenant refermées explicitement à la fin de chaque transaction, y compris en cas d'exception ; `with sqlite3.Connection` ne les fermait pas.
- Corrige `WinError 32` sur `db.sqlite3` pendant le nettoyage de `TemporaryDirectory` dans `test_ad_response_v38.py` avec Python 3.14/Windows.
- Le test AD restaure aussi le chemin initial `bridge.DB`, sans laisser un chemin temporaire après exécution.
- Nouveau test de non-régression pour commit, rollback et fermeture systématique de la connexion, inclus dans les contrôles `aegismesh-soar update`. Aucune modification des politiques AD, de Wazuh, Shuffle, des agents ou de l'authentification.

## 3.8.0 — Intégration réelle de la remédiation AD/LDAP via Shuffle et Wazuh

- Nouveau `AD_DISABLE_ACCOUNT`: décision authentifiée → Shuffle existant → Wazuh API sur DC `006` → PowerShell ActiveDirectory, sans connexion LDAP administrative depuis GCP.
- Contrôles indépendants d'identité SID/domaine, groupe AD opt-in, groupes protégés, rôles et comptes de service; action désactivée par défaut et activée une seule fois.
- Exécuteur Windows DC installable, audit préalable/postérieur, relecture `Get-ADUser`, réactivation manuelle encadrée.
- Règles de preuve `119874` (succès), `119875` (échec) et `119876` (précontrôle DC), attribution stricte agent + décision + SID. Échec tardif = état à confirmer, jamais succès inventé.
- Commandes `aegismesh-soar ad status|probe|enable|disable` et tests non destructifs ; pas de réinstallation Wazuh/Shuffle/Velociraptor.

## 3.7.4 — Compatibilité du schéma `session_id` de Velociraptor

- Le flow VQL possède `session_id`, et pas seulement `FlowId` ou `flow_id`; valeurs contradictoires refusées.
- Validation croisée des identifiants en entête et dans `request` lorsque présents.
- État absent : lecture complémentaire via `get_flow()` authentifié, sans considérer une valeur inconnue comme FINISHED.
- Aucun déploiement agent, nouveau flow, modification de quarantaine ou redémarrage de Velociraptor.

## 3.7.3 — Correction du schéma réel des flows Velociraptor

- Prend en charge les propriétés VQL `FlowId`, `ClientId`, `State`, `Request`, `Creator` et leurs variantes snake_case.
- Contrôle la correspondance exacte entre Wazuh, client EDR et Flow ID; tout schéma inconnu ou incohérent produit une erreur explicite, jamais un faux `aucune collecte`.
- Les commandes `edr flows`, `edr flow-status`, `edr investigations` restent en lecture seule.
- Aucun changement des exécutants, agents, ACL, certificats, Wazuh, Shuffle, Fail2ban, ou quarantaine.

## 3.7.2 — Suivi réel des flows Velociraptor

- `edr flows`, `edr flow-status`, `edr investigations` lisent les flows du serveur, sans nouvelles actions distantes.
- Association agent/client et flow vérifiée; résultats Generic.Client.Info limités et empreinte SHA256, sans contenu sensible dans les journaux.
- `edr collect` conserve désormais le Flow ID dans un registre privé.
- Aucun changement Wazuh, Shuffle, Fail2ban ni politiques d’isolement.

## V3.6.0 — Windows response via Wazuh Active Response + Windows Firewall
- Windows action `WINDOWS_BLOCK_IP` uses the verified Shuffle → bridge → Wazuh workflow, targeting only a single public IPv4 for 120 seconds.
- Windows LAB and DC agents have separate allowlists. Domain Controllers require explicit consent on both manager and endpoint; EDR_ISOLATE remains disabled.
- Two scoped Windows Firewall rules (in/out) with SYSTEM scheduled automatic rollback; local ActiveStore verification and Wazuh evidence rules 119872/119873 for block and scheduled removal evidence.
- Windows endpoint installer, cleanup, read-only Wazuh/Velociraptor/Sysmon service status. No service reinstall.
- Windows operation `chain block-windows` and statuses; guardrails and offline regressions.

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

## V3.7.0 — Orchestration sans saisie répétée et EDR Velociraptor
- `orchestrate status|catalog|recent|reconcile`: constat réel sans déclencher une décision.
- `edr discover|configure|clients|link-auto|link|collect|status`: connexion gRPC mTLS du Velociraptor existant, inventaire et collecte d'artefact sécurisé.
- `EDR_COLLECT` et `EDR_ISOLATE` reconnus par le bridge et soumis à la politique de décision, via Shuffle.
- Quarantaine par label Quarantine sur agent non DC, score minimum 0.95, approbation, bail 300 s, timer de retrait et opération release.
- `EDR_ISOLATE` est désactivé par défaut et ne prétend jamais que la quarantaine a été appliquée sur le réseau du poste sans preuve d'agent.
- Aucun secret Velociraptor dans Git, aucune réinstallation ni changement AD. Normalisation LF sur code Linux via .gitattributes.

## 3.7.1 — API Velociraptor existante : raccordement automatique et refus explicites

- `edr doctor` découvre un conteneur Velociraptor unique, son binaire et la configuration serveur, sans lire ni exposer les clés.
- `edr setup --confirm` raccorde une configuration API mTLS déjà existante uniquement après deux requêtes réelles réussies.
- `edr bootstrap --confirm --allow-restart` peut créer un compte API dédié via le serveur Docker existant **uniquement** si le certificat sera écrit dans un volume Docker persistant; attribution des rôles api/investigator et redémarrage **Velociraptor uniquement**, avec confirmation explicite. Jamais d'élévation admin silencieuse.
- `edr clients` et `edr link-auto` expliquent l'absence de mTLS plutôt que de produire `mode doit être host ou docker`.
- Aucune quarantaine EDR n'est activée, aucun agent n'est isolé, les services Shuffle/Wazuh/Fail2ban sont conservés.
