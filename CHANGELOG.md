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
