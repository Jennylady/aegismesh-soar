# AEGISMESH-SOAR V3.8.0 — Désactivation ciblée de comptes AD, vraie chaîne Wazuh / Shuffle

## Périmètre et état initial

Ce patch se base sur l'instance **AD existante** `ad.ikom.mg`, son agent Wazuh `006` (`ad-aws`), le bridge SOAR déjà connecté à Shuffle et les règles de preuve déjà collectées. Aucune deuxième connexion LDAP administrative, aucun compte/mot de passe AD stocké sur GCP et aucun nouveau DC. Exécution sur le contrôleur existant sous le service Wazuh `LocalSystem` (contrôlé). Les collectes Velociraptor Kali RUNNING restent indépendantes.

**IMPORTANT :** le code de l'action est réel. Il n'est **pas activé par défaut** et ne désactive aucun compte pendant l'installation ou les tests. Les tests utilisent des doubles; ils ne prouvent pas que l'environnement AD réel est prêt. L'activation demande un opérateur sur le contrôleur puis un unique opt-in côté GCP.

## Chaîne d'une vraie décision (aucune valeur de démonstration envoyée)

```text
AEGISMESH analyse Personne 1 (vrai événement Windows/Sysmon/LDAP)
  → décision unique: tag=AD_DISABLE_ACCOUNT; target.agent_id=006,
    target.user_sid=SID Windows résolu depuis la preuve d'identité,
    target.domain_dns=ad.ikom.mg; incident_id, expires_at, approved=true,
    confidence≥0.98, evidence_ids: deux références distinctes d'alertes réelles
  → POST /v1/decisions (DECISION_TOKEN existant)
  → bridge valide sa politique dédiée (ENABLE_AD_REMEDIATION=false par défaut)
  → webhook Shuffle existant puis POST /v1/execute (SHUFFLE_ACTION_TOKEN)
  → Wazuh HTTPS local PUT /active-response?agents_list=006
  → Windows DC Wazuh AR !aegismesh-soar-ad.cmd
  → PowerShell ActiveDirectory/Get-ADUser/Disable-ADAccount/Get-ADUser
  → Wazuh 119874 confirme ADACCOUNT ou 119875 remonte ADFAIL
  → bridge recoupe decision_id + agent.id=006 + user_sid, puis met à jour la décision
```

L'accusé de réception de la distribution API est **`dispatched_unverified`** et jamais une preuve de désactivation. Le statut `executed` ne résulte que d'une ligne reçue du **bon agent** avec `status=disabled` et le **même SID**, émise après un `Get-ADUser Enabled=False` sur AD. Un résultat `failed` ou `needs_manual_review` nécessite une intervention; il ne signifie pas que le compte est intact.

## Gardes indépendants sur le contrôleur de domaine

- Compte sélectionné par **SID de l'utilisateur** (`S-1-5-21-...`), pas par un nom libre ou une commande PowerShell du moteur IA.
- Domaine constaté localement `ad.ikom.mg`, machine réellement contrôleur de domaine; SID dans le même domaine.
- Seuls les membres (y compris membres imbriqués) du groupe de sécurité globale **`AEGISMESH-SOAR-Remediable`** peuvent être ciblés. Aucun membre n'est ajouté par l'installateur.
- Refus si RID système/réservé, `adminCount=1`, compte déjà désactivé, SPN ou délégation, mot de passe sans expiration, primaryGroupID autre que Domain Users, appartenance transitive à des groupes administratifs/protégés, ou ambiguïté de domaine/SID.
- Le groupe éligible doit lui-même être non privilégié. **Les délégations AD sur mesure par ACL ne sont pas entièrement détectables par ces vérifications : seuls des comptes ordinaires non critiques doivent être inscrits.**
- Identifiant de décision non rejouable sur l'agent; audit persistant avant et après modification. Aucun mot de passe transmis au DC.
- Une commande de réactivation **manuelle** est fournie pour un compte dont le registre local prouve la désactivation par AEGISMESH. Pas de réactivation automatique des identifiants potentiellement compromis.

## Déploiement du patch (poste Windows → GitHub → GCP)

Dans le dépôt local PowerShell `F:\SOUTENANCE\Lady\aegismesh-soar`, décompresser à la racine, exécuter `py -3 tests/test_ad_response_v38.py`, `git diff --check`, `git add -A`, `git diff --cached --check`, `git commit`, puis `git push origin main`. Sur GCP, **uniquement `aegismesh-soar update`**, puis `aegismesh-soar ad status`.

## Installation unique sur le VRAI Windows Server AD (PowerShell administrateur)

Les fichiers ci-dessous proviennent du dépôt GitHub après `git push`. Ils sont téléchargés uniquement sur le **contrôleur AD**, jamais sur GCP. Examiner le code téléchargé avant toute exécution.

```powershell
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP 'aegismesh-soar-ad-v38'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$src = 'https://raw.githubusercontent.com/Jennylady/aegismesh-soar/main/ops/wazuh/windows'
$files = @('Install-AegisMeshAD.ps1','Test-AegisMeshAD.ps1',
           'aegismesh-soar-ad.cmd','aegismesh-soar-ad.ps1','aegismesh-soar-ad-lib.ps1',
           'Restore-AegisMeshADAccount.ps1')
foreach ($file in $files) {
    Invoke-WebRequest -Uri "$src/$file" -OutFile (Join-Path $dir $file) -UseBasicParsing
}
Set-Location $dir
# Contrôle du contenu avant de lancer l'installateur :
Get-ChildItem . | Select-Object Name,Length
# Opération réelle de configuration : crée le groupe si absent, sans ajouter d'utilisateur.
.\Install-AegisMeshAD.ps1 -CreateScopeGroup
.\Test-AegisMeshAD.ps1
```

Ce script vérifie que Wazuh tourne en `LocalSystem`, crée si nécessaire le vrai groupe d'éligibilité dans AD, installe son exécuteur dans l'agent Windows existant, configure une politique protégée par ACL NTFS et un registre d'audit local. Il ne redémarre **aucun** service et ne désactive aucun utilisateur.

### Choix des comptes réellement éligibles

Un administrateur du domaine sélectionne **uniquement un utilisateur non privilégié dédié aux essais**, après vérification de ses groupes et propriétés. Par exemple, si le compte **réel** `dev` existe et répond aux critères du contrôle :

```powershell
Get-ADUser dev -Properties Enabled,adminCount,ServicePrincipalName,PasswordNeverExpires |
    Select-Object SamAccountName,Enabled,adminCount,ServicePrincipalName,PasswordNeverExpires
Get-ADPrincipalGroupMembership dev | Select-Object Name
# Décision administrative explicite, une seule fois :
# Add-ADGroupMember -Identity 'AMSOAR-Remediable' -Members dev
```

La ligne `Add-ADGroupMember` est délibérément commentée : **ne pas enrôler automatiquement un utilisateur existant sans vérification préalable**. Une fois confirmé, décommenter/exécuter une seule fois. Les remédiations suivantes ne nécessitent pas de saisie de SID, score ou preuves par l'opérateur : ces éléments doivent venir de l'incident réel du moteur Personne 1.

## Installation des règles Wazuh manager, puis activation GCP

```bash
aegismesh-soar fleet evidence install --apply --confirm
# Wazuh manager valide la configuration de règles puis redémarre ;
# interruption courte de la collecte possible.
aegismesh-soar ad status
# Vérification distante réelle en lecture seule (aucun compte modifié) :
aegismesh-soar ad probe --confirm
# Le probe doit répondre VERIFIED, pas seulement DISPATCHED_UNVERIFIED.
# Après vérification du vrai DC et de son groupe opt-in :
aegismesh-soar ad enable --agent-id 006 --domain ad.ikom.mg --confirm
aegismesh-soar ad status
aegismesh-soar orchestrate status
```

`ad probe --confirm` demande au véritable Wazuh agent `006` de vérifier, sans identité utilisateur ni incident inventé, son rôle DC, le module AD, le domaine et le groupe d'éligibilité. Il n'est `VERIFIED` qu'après réception d'une ligne `AEGISMESH-SOAR-ADREADY` sur le manager avec le bon ID d'agent et la bonne décision de sonde. Si la preuve manque, activation refusée.

`ad enable` vérifie que `006` figure déjà dans `WAZUH_WINDOWS_DC_AGENT_IDS`, qu'il est actif et Windows, que la règle de preuve 119874 est installée, que la production SOAR est déjà autorisée, puis fixe l'agent/domaine dans `/etc/aegismesh-soar/soar.env`. Il redémarre **seulement le bridge** avec rollback de configuration si le contrôle santé échoue. **L’activation exige une preuve de précontrôle du vrai DC reçue par Wazuh dans les 40 dernières minutes.** Le statut de l'exécuteur DC reste à confirmer **sur le contrôleur** par `Test-AegisMeshAD.ps1` ; le manager ne peut pas certifier sa présence sans preuve distante.

Pour désarmer cette action sans toucher aux autres réponses :

```bash
aegismesh-soar ad disable --confirm
```

## Contrôle après une décision réelle, sans en inventer

La source d'analyse doit résoudre le **SID exact** du compte concerné depuis les événements AD/Wazuh, et produire `AD_DISABLE_ACCOUNT` seulement pour un utilisateur explicitement éligible et un incident multi-événements réellement corrélé. Ne jamais transformer `5136` en désactivation automatique sans déterminer qui a fait la modification, son contexte et les preuves suffisantes. Ne jamais remplir un score fictif ni déclencher une modification sans incident réel.

```bash
aegismesh-soar orchestrate recent
aegismesh-soar fleet evidence reconcile
aegismesh-soar ad status
# Pour une décision réellement retournée par l'analyse :
aegismesh-soar decision ID_REEL
# Diagnostic en lecture seule :
aegismesh-soar fleet evidence diagnose --agent-id 006 --decision-id ID_REEL
```

À l'arrivée d'un événement `ADFAIL`, SOAR ne dit jamais que le compte a été désactivé, même si un échec a pu survenir **après** la modification. Il faut inspecter le véritable état du compte dans AD.

## Réactivation de secours (sur DC, pas via la chaîne automatique)

```powershell
# À exécuter seulement après évaluation de l'incident, récupération des identifiants et
# décision de l'administrateur, en utilisant l'ID réel de la désactivation.
.\Restore-AegisMeshADAccount.ps1 -DecisionId am-IDENTIFIANT_REEL -ConfirmRestore
```

Le script refuse les identifiants inconnus et les comptes qui n'ont pas de preuve locale d'une désactivation réussie par SOAR. Il recontrôle `Enabled` après `Enable-ADAccount` et ajoute une entrée d'audit. Ce retour arrière n'annule pas les tickets Kerberos déjà émis et ne remplace pas la réinitialisation des identifiants ou la revue des sessions. Il n'est **pas** exposé comme action automatisable depuis Shuffle.

## Limites opérationnelles transparentes

1. Les tests automatisés sont non destructifs, **pas** des preuves d'une modification AD en production.
2. L'activation dépend d'une véritable installation locale Windows DC, de la collecte Wazuh déjà active, des permissions Windows/AD du service et de l'enrôlement d'un utilisateur ordinaire. Une API Wazuh `200` seule n'est jamais une preuve.
3. **L'IA / la corrélation Personne 1 doit réellement émettre la décision via POST /v1/decisions** avec le SID, le domaine, les deux références d'incident et son score. Le dépôt SOAR ne calcule pas lui-même ce score et ne crée pas d'incident fictif.
4. La vérification `adminCount` et groupes imbriqués réduit les risques mais ne détecte pas toutes les délégations ACL et relations de confiance. Le groupe d'éligibilité doit rester limité aux comptes utilisateurs non critiques.
5. La remédiation concerne **la désactivation temporaire d'un compte utilisateur existant**, pas la suppression d'objets LDAP, les GPO, les groupes privilégiés, la rotation de `krbtgt`, ni l'isolement réseau du DC. Les actions AD supplémentaires devront avoir chacune une politique spécifique.
