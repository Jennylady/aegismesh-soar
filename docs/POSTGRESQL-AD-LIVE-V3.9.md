# AEGISMESH-SOAR V3.9 — PostgreSQL et essai AD/LDAP réel

Les commandes ci-dessous concernent la **vraie** infrastructure : SOAR GCP, Wazuh agent AD `006`, domaine `ad.ikom.mg` et contrôleur Windows Server. Elles n'inventent ni événement Wazuh ni score IA.

## 1. PostgreSQL : installation et migration automatique GCP

Après publication GitHub et `aegismesh-soar update` :

```bash
aegismesh-soar database status
aegismesh-soar database migrate --apply --confirm
aegismesh-soar database status
aegismesh-soar orchestrate recent
aegismesh-soar ad status
```

`database migrate` s'exécute sur l'hôte GCP (root). Elle :

- Installe **uniquement si nécessaire** les paquets Debian/Ubuntu PostgreSQL, client et adaptateur `python3-psycopg2`. Ne modifie ni les bases ni les rôles d'autres applications.
- Crée la base et le rôle isolés `aegismesh_soar`, avec mot de passe aléatoire enregistré dans `/etc/aegismesh-soar/postgres.password` (root, permissions 0600), port local `127.0.0.1:5432`.
- Arrête brièvement **seulement** le bridge SOAR, sauvegarde SQLite sous `/var/lib/aegismesh-soar/backups/`, copie **toutes** les décisions dans PostgreSQL, compare les lignes et une empreinte SHA-256 complète avant de changer de backend.
- Bascule `/etc/aegismesh-soar/soar.env` à `SOAR_DB_BACKEND=postgresql`, redémarre le bridge et contrôle `/health`. Une panne avant bascule conserve SQLite ; une panne après bascule ne ramène SQLite que s'il n'existe aucune nouvelle écriture PostgreSQL.
- Conserve l'ancienne base SQLite comme sauvegarde, **sans** la supprimer. Aucun mot de passe n'est commité dans Git.

Si la migration échoue, **ne répétez pas à l'aveugle** et ne supprimez aucun fichier. Lisez l'erreur, `aegismesh-soar database status` et `systemctl status aegismesh-soar-bridge`. Les bases restent séparées.

## 2. Installer l'exécuteur AD sur Windows Server (une fois)

PowerShell administrateur **sur le contrôleur** `ad.ikom.mg`, et uniquement après `git push` :

```powershell
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP 'aegismesh-soar-ad-v39'
New-Item -Path $dir -ItemType Directory -Force | Out-Null
$base = 'https://raw.githubusercontent.com/Jennylady/aegismesh-soar/main/ops/wazuh/windows'
$files = @('Install-AegisMeshAD.ps1','Test-AegisMeshAD.ps1',
           'aegismesh-soar-ad.cmd','aegismesh-soar-ad.ps1','aegismesh-soar-ad-lib.ps1',
           'Restore-AegisMeshADAccount.ps1','New-AegisMeshADLabUser.ps1')
foreach ($file in $files) {
    Invoke-WebRequest -Uri "$base/$file" -OutFile (Join-Path $dir $file) -UseBasicParsing
}
Set-Location $dir
Get-ChildItem -File | Select-Object Name,Length
# Examiner les scripts du dépôt avant de lancer l'installation.
.\Install-AegisMeshAD.ps1 -CreateScopeGroup
.\Test-AegisMeshAD.ps1
```

Installer de nouveau le script AD mis à jour V3.9 même si V3.8 existait : le nouveau chemin de démonstration ajoute la vérification stricte `aegis-lab-*`. Le contrôleur doit déjà être membre du domaine, avec Wazuh agent 006 installé et démarré.

## 3. Activer seulement après preuve du DC

Sur GCP :

```bash
aegismesh-soar fleet evidence install --apply --confirm
aegismesh-soar ad probe --confirm
# Exiger AD readiness: VERIFIED; un ACK seul n'est pas une preuve.
aegismesh-soar ad enable --agent-id 006 --domain ad.ikom.mg --confirm
aegismesh-soar ad status
```

Le probe doit être **VERIFIED** via une ligne Wazuh collectée depuis `006` pour l'ID de sonde exact, au plus 40 minutes avant `ad enable`.

## 4. Créer un vrai compte de test AD

Sur le Windows Server DC, PowerShell administrateur, après avoir installé les scripts :

```powershell
.\New-AegisMeshADLabUser.ps1 -SamAccountName 'aegis-lab-01' -ConfirmCreate
# Un vrai mot de passe fort est demandé par Read-Host -AsSecureString.
# Lire le SID réel imprimé par le script, sans l'inventer.
Get-ADUser 'aegis-lab-01' -Properties Enabled,MemberOf,adminCount |
    Select-Object SamAccountName,SID,Enabled,MemberOf,adminCount
```

Le nouveau compte est ajouté au vrai groupe d'éligibilité `AEGISMESH-SOAR-Remediable` ; **aucun utilisateur existant n'est ciblé**. Cette opération ne désactive pas le compte. Un compte déjà présent est refusé pour éviter toute réutilisation accidentelle.

## 5. Déclencher une VRAIE désactivation via Shuffle

Avec le SID **réel** du compte de démonstration lu sur le DC, et seulement après `AD readiness: VERIFIED` et `ad enable` :

```bash
aegismesh-soar ad lab-disable --sid 'SID-REEL-DE-AEGIS-LAB-01' --confirm
```

Cette commande :

1. Vérifie la politique AD, l'agent DC `006`, la preuve de disponibilité récente et ouvre une fenêtre `AD_LAB_UNTIL` de 10 minutes.
2. Crée une **décision réelle** `AD_LAB_DISABLE`, avec `origin=operator_lab`, `confidence=0`, aucune fausse preuve ni fausse alerte ; soumet l'action au **vrai** `POST /v1/decisions` du bridge.
3. Utilise le webhook Shuffle existant, puis son rappel authentifié `POST /v1/execute`, déclenche `!aegismesh-soar-ad.cmd` via l'API Wazuh vers l'agent `006`.
4. Le DC vérifie **de nouveau** le SID, le domaine, l'appartenance au groupe d'éligibilité, la non-élévation des privilèges et **le préfixe exact** `aegis-lab-*` ; seulement alors il exécute `Disable-ADAccount` puis `Get-ADUser Enabled=False` et publie une preuve Wazuh.

**Important :** c'est une **action réelle** de démonstration **opérateur**, pas une détection IA. La politique normale `AD_DISABLE_ACCOUNT` continue d'exiger une décision de l'analyse avec `confidence >= 0.98`, deux preuves d'incident distinctes, un SID du DC et une fenêtre d'expiration valide.

## 6. Vérifier l'effet réel (pas l'accusé Wazuh)

Sur GCP, utiliser l'ID `am-...` réel affiché :

```bash
aegismesh-soar orchestrate recent
aegismesh-soar fleet evidence reconcile
aegismesh-soar decision am-IDENTIFIANT-REEL
aegismesh-soar ad status
```

Sur le vrai DC :

```powershell
Get-ADUser 'aegis-lab-01' -Properties Enabled |
    Select-Object SamAccountName,SID,Enabled
# Résultat attendu après l'exécution effective : Enabled = False
```

Un statut `dispatched_unverified` confirme seulement la demande d'exécution, pas une désactivation. La preuve complète exige la vérification sur DC **et** le marqueur `ADACCOUNT` collecté par Wazuh pour la bonne décision/SID. `ADFAIL` impose une revue manuelle.

## 7. Remise en état

La désactivation AD **n'expire pas automatiquement**. La remise en service est strictement manuelle depuis le contrôleur, après vérification :

```powershell
.\Restore-AegisMeshADAccount.ps1 -DecisionId am-IDENTIFIANT-REEL -ConfirmRestore
Get-ADUser 'aegis-lab-01' -Properties Enabled | Select-Object SamAccountName,Enabled
```

`ad disable --confirm` sur GCP empêche de nouvelles décisions automatiques AD, mais **ne réactive pas** les comptes déjà désactivés.

## Limites

- Aucun effet réel ne peut être déclaré sans exécution sur GCP et le vrai DC. Les tests Python du dépôt sont simulés.
- Le compte de démonstration ne doit pas être employé pour des accès de production.
- Le retour d'état du bridge ne remplace pas la confirmation de l'attribut AD réel. Un compte désactivé peut encore avoir des sessions ouvertes et des tickets Kerberos valides, qu'il faut traiter séparément si nécessaire.
- Le moteur d'analyse de Personne 1 reste la source du vrai score et des alertes pour `AD_DISABLE_ACCOUNT`. `AD_LAB_DISABLE` ne doit jamais être confondu avec sa décision.
