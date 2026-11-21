# Journal des versions

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
