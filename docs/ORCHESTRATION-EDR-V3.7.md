# AEGISMESH-SOAR V3.7 — Orchestration intégrée et EDR Velociraptor

## Principes

- **Aucune saisie manuelle répétée de score, IP ou preuves.** Le moteur de détection et d'analyse (Personne 1) continue de produire des décisions structurées via `POST /v1/decisions` avec `X-Aegismesh-Token: DECISION_TOKEN`. Le bridge applique les politiques, expédie à Shuffle, puis accepte le rappel `/v1/execute` avec `SHUFFLE_ACTION_TOKEN`.
- `aegismesh-soar orchestrate status` et `orchestrate recent` sont des contrôles **en lecture seule**, sans nouvelles décisions.
- Wazuh et Fail2ban restent opérationnels tels quels. **Aucun code de la Personne 1 n'est modifié.**
- Le contrôleur de domaine `006` n'est **jamais** éligible à `EDR_ISOLATE`; il reste accessible pour les collectes forensic si un client EDR réel est présent.
- La quarantaine Velociraptor repose sur le label `Quarantine` et les artefacts de l'agent. La présence du label ne constitue **pas** une preuve d'isolation réseau réussie. Pas de nouvelle fonctionnalité payante requise.

## Déploiement

Dans PowerShell du poste Windows de développement (pas sur le serveur GCP) :

```powershell
Set-Location 'F:\SOUTENANCE\Lady\aegismesh-soar'
Expand-Archive -LiteralPath 'C:\Users\raph\Downloads\AEGISMESH-SOAR-PATCH-V3.7.zip' -DestinationPath . -Force
py -3 tests/test_edr_orchestrator_v37.py
if ($LASTEXITCODE -ne 0) { throw 'Régression EDR' }
git diff --check
if ($LASTEXITCODE -ne 0) { throw 'Diff invalide' }
git add -A
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Index invalide' }
git commit -m 'feat: Velociraptor EDR and zero-input SOAR orchestration V3.7'
git push origin main
```

Sur GCP :

```bash
aegismesh-soar update
aegismesh-soar orchestrate status
aegismesh-soar orchestrate catalog
aegismesh-soar orchestrate recent
aegismesh-soar edr discover
```

## Raccordement à l'API Velociraptor existante (unique mise en place)

Velociraptor utilise une API **gRPC authentifiée par certificat client mTLS**. Le service EDR et ses clients existants ne sont ni réinstallés ni reconfigurés ici. Le certificat client privé doit être délivré par le serveur Velociraptor lui-même, avec permissions `api`, `reader`, `investigator`, et `LABEL_CLIENT` uniquement si l'isolement doit ensuite être autorisé. **Ne jamais pousser ces clés privées dans Git**. Aucun mode `insecure` n'est fourni.

Si l'API est exécutée dans un conteneur :

```bash
# Nom réel du conteneur et chemin réel du fichier API client à relever dans l'existant.
aegismesh-soar edr discover
# Après provisionnement du certificat API client à l'intérieur du conteneur :
aegismesh-soar edr configure --mode docker --container NOM_REEL --api-config /CHEMIN_PRIVE/api_client.yaml
```

Si le binaire et l'API client mTLS existent sur l'hôte GCP :

```bash
aegismesh-soar edr configure --mode host --api-config /etc/aegismesh-soar/velociraptor-api.yaml --binary /usr/local/bin/velociraptor
```

La configuration appelle une requête `SELECT * FROM info() LIMIT 1` **réelle** avant d'accepter le fichier API.

Ensuite :

```bash
aegismesh-soar edr clients
# Corrélation automatique par nom d'hôte exact et non ambigu.
aegismesh-soar edr link-auto
aegismesh-soar edr status
```

Si un nom Wazuh diffère du nom Velociraptor (notamment Kali `kali-ikom` versus `offensive`), l'opérateur vérifie **une seule fois** l'identité des deux terminaux et peut exécuter `edr link --agent-id 002 --client-id C.xxxxx --confirm`. Le client ID ne peut pas être deviné, mais est affiché par `edr clients`. Les ID 001/002/006 ne sont pas des identifiants Velociraptor.

## Investigation effective — sans scores/IP manuels

```bash
aegismesh-soar edr collect --agent-id 001
```

Cette commande programme l'artefact **non destructif** `Generic.Client.Info` sur le client Velociraptor correspondant. La réponse indique que la collecte est programmée, et **pas** que ses résultats sont déjà arrivés. Une décision `EDR_COLLECT` produite automatiquement par le moteur d'analyse utilise la même intégration à travers Shuffle.

Pour Kali, le résultat de `edr clients` décide si un client Velociraptor existe réellement sur ce poste. Si absent, provisionner un client Linux à partir de la configuration certifiée de **l'instance Velociraptor déjà installée**, puis répéter `edr link-auto` ou l'association vérifiée. Ne jamais fabriquer le `client.config.yaml` ni désactiver TLS.

## Quarantaine Velociraptor (LAB seulement, séparée du blocage IP)

La quarantaine doit être une décision exceptionnelle : `EDR_ISOLATE`, score ≥ 0,95, deux preuves distinctes, `approved=true`, agent Wazuh **autorisé et actif**, correspondance EDR validée, timer de retrait actif. Ce protocole ne modifie pas l'AD ni les comptes. La fonction Quarantine de Velociraptor peut rester active après le redémarrage du client.

Opérations uniques après validation préalable de l'API EDR :

```bash
aegismesh-soar edr enable-expiry --confirm
# Pour le Windows LAB, non pour le DC :
aegismesh-soar edr allow-isolation --agent-id 001 --confirm
aegismesh-soar edr quarantine-status --agent-id 001
```

Le timer `aegismesh-soar-edr-expiry.timer` vérifie chaque minute les baux locaux et retire le label `Quarantine` quand les 300 secondes expirent. Si l'API est indisponible, la suppression ne peut être garantie; le timer réessaie. Une intervention via la console Velociraptor doit être possible **avant toute première quarantaine réelle**.

L'action n'est pas déclenchée par les commandes ci-dessus. Elle sera déclenchée par une décision autorisée venant de l'analyse et envoyée par Shuffle. Le résultat est `dispatched_unverified` (`edr_quarantine_requested`), **jamais** `executed` sur simple création du label. L'application réseau et le retour effectif doivent être confirmés par le client Velociraptor.

Retrait explicite, si besoin :

```bash
aegismesh-soar edr release --agent-id 001 --confirm
```

Cela ne retire que les quarantaines créées par AEGISMESH-SOAR et inscrites dans son registre privé. Une quarantaine préexistante ou créée par un autre opérateur ne sera pas retirée.

## Actions préparées / limites

| Tag | Réalité | Vérification |
|---|---|---|
| OBSERVE | Aucun effet externe | Exécution Shuffle persistée |
| F2B_BAN_SERVER | Fail2ban sur GCP | Jail + nftables |
| WAZUH_BLOCK_AGENT | Blocage IP sur Kali | Preuve Wazuh agent 002 |
| WINDOWS_BLOCK_IP | Blocage IP sur Windows 001/006, distinct de la quarantaine | WINBLOCK et WINUNBLOCK |
| EDR_COLLECT | Collecte Velociraptor asynchrone | Flow ID + résultats EDR après collecte |
| EDR_ISOLATE | Label Quarantine, **uniquement sous garde renforcée** | Label et artefacts client + expiration |
| AD_DISABLE_ACCOUNT | **Non implémenté** | Étape AD/LDAP distincte |

### Étape future : remédiation AD/LDAP

Interroger AD par compte de service **dédié** au travers du VPN et de Kerberos/LDAPS; délimiter les objets autorisés, les privilèges de modification et les groupes protégés; écrire un exécuteur spécifique et réversible, journaliser `5136/4725/4722`, puis intégrer le résultat au graphe d'incident. Ne jamais réutiliser la quarantaine réseau de Windows LAB sur le contrôleur de domaine, ni permettre un désactivation générique de comptes Tier 0.
