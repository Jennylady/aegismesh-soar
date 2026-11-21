# AEGISMESH-SOAR Fleet V3.4 — Déploiement et preuve de réponse sur trois agents

## Architecture réelle

- **GCP `/opt/aegismesh/soar`** : API Wazuh HTTPS locale, identifiants privés, Shuffle, bridge et CLI.
- **Kali (agent 002)** : agent Wazuh et `aegismesh-soar-proof` Linux + `aegismesh-soar-block` déjà installé ; aucun secret API.
- **WIN-LAB-01 (agent 001)** : agent Wazuh et `aegismesh-soar-proof.cmd/.ps1` installés localement ; pas d'API Wazuh sur Windows.
- **Windows Server AD (agent 006)** : exécuteur de preuve Windows uniquement, aucune action AD automatique.

Le flow du tag `WAZUH_AR_PROOF` est : `SOAR Bridge → Shuffle Webhook → HTTP /v1/execute → Wazuh API PUT /active-response?agents_list=... → wazuh-execd de l'agent → active-responses.log → Wazuh Manager (alerts.json/archives.json) → rapprochement de la décision`.

L'API Wazuh qui accepte une commande n'établit *pas* son exécution sur l'agent. Tant que la preuve distante n'est pas reçue, la décision reste `dispatched_unverified`.

## 1. Patch sur Kali (repo, sans identifiants API)

Après téléchargement du ZIP V3.4, décompresser le patch à la **racine du dépôt local Kali**, exécuter les tests et publier sur `main`. Sur le serveur GCP, uniquement `aegismesh-soar update`.

Sur le Kali portant l'agent 002, la commande d'installation de la preuve (sans action de blocage) est :

```bash
cd /home/lady/SOUTENANCE/aegismesh-soar
sudo bash ops/wazuh/install_agent_proof.sh
sudo ls -l /var/ossec/active-response/bin/aegismesh-soar-proof
```

Ne pas exécuter `aegismesh-soar chain wazuh-connect` sur Kali : les identifiants restent sur GCP.

## 2. Installer sur WIN-LAB-01 et Windows Server AD

Exécuter PowerShell **en administrateur** sur chacun des deux Windows, après avoir obtenu les trois fichiers du dépôt `ops/wazuh/windows/` dans un répertoire local :

```powershell
Set-Location C:\chemin\vers\ops\wazuh\windows
.\Install-AegisMeshProof.ps1
Get-ChildItem "${env:ProgramFiles(x86)}\ossec-agent\active-response\bin\aegismesh-soar-proof.*"
```

Pour préparer ces fichiers dans l'état **actuellement public** du dépôt, PowerShell peut les récupérer par HTTPS :

```powershell
$dir=Join-Path $env:TEMP 'aegismesh-soar-proof'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$root='https://raw.githubusercontent.com/Jennylady/aegismesh-soar/main/ops/wazuh/windows'
'aegismesh-soar-proof.cmd','aegismesh-soar-proof.ps1','Install-AegisMeshProof.ps1' | ForEach-Object {
  Invoke-WebRequest -Uri "$root/$_" -OutFile (Join-Path $dir $_) -ErrorAction Stop
}
Set-Location $dir
.\Install-AegisMeshProof.ps1
```

**Avant d'exécuter du code téléchargé**, contrôler qu'il correspond au commit GitHub que tu viens de pousser. Si le dépôt passe en privé, ne pas utiliser de contournement : récupérer les fichiers via une session Git authentifiée ou un transfert de fichier approuvé.

L'installation ne modifie ni les services AD, ni les utilisateurs, ni les règles de pare-feu. Si l'exécutable nouvellement installé n'est pas découvert lors du déclenchement Wazuh, la commande `./Install-AegisMeshProof.ps1 -RestartWazuhAgent` peut redémarrer **uniquement WazuhSvc** sur ce poste, après validation du créneau de maintenance.

## 3. Sur GCP : autoriser l'inventaire et les preuves

```bash
aegismesh-soar update
aegismesh-soar fleet status
aegismesh-soar configure wazuh-proof-agents 001,002,006
aegismesh-soar configure enable-tests
```

`enable-tests` autorise également les autres tests déjà présents dans V3, sans les déclencher. La configuration de production existante reste inchangée.

Soumettre **un agent à la fois**, et utiliser la preuve reçue pour arrêter en cas d'anomalie :

```bash
aegismesh-soar fleet proof --agent-id 002
# Puis si Kali a exécuté, même commande pour 001, puis 006
```

Chaque décision passe par ton workflow Shuffle en place, pas par un autre accès direct. Si la réponse revient `dispatched_unverified`, recopier l'ID `am-...` et exécuter :

```bash
aegismesh-soar fleet verify --agent-id 002 am-IDENTIFIANT
```

La preuve peut également être consultée localement :

- **Kali** : `sudo tail -n 30 /var/ossec/logs/active-responses.log` et `sudo tail -n 30 /var/ossec/logs/aegismesh-soar-proof.jsonl`.
- **Windows/AD** : `Get-Content "${env:ProgramFiles(x86)}\ossec-agent\active-response\active-responses.log" -Tail 25` ou `aegismesh-soar-proof.jsonl` dans le même dossier.
- **Manager GCP** : `sudo grep -F 'AEGISMESH-SOAR-PROOF' /var/ossec/logs/archives/archives.json | tail -n 5` si les archives sont activées. Le CLI vérifie également les journaux `alerts.json`.

Terminer en désactivant les tests si aucune autre démonstration ne suit :

```bash
aegismesh-soar configure disable-tests
```

## 4. Actions de sécurité réelles (séparées de la preuve)

- `F2B_BAN_SERVER` : l'action existante vérifie Fail2ban et l'élément nftables sur GCP, mais nécessite **une véritable IP hostile, un incident et deux preuves distinctes**. La jail `aegismesh-soar-gcp` conserve son délai d'expiration.
- `WAZUH_BLOCK_AGENT` : uniquement Linux agent 002 si autorisé, avec `aegismesh-soar-block` déjà installé et expiration nftables native. Le log `AEGISMESH-SOAR-BLOCK` permet une vérification Wazuh par ID.
- Agents Windows 001 et AD 006 : exécution d'une preuve inoffensive **uniquement**. Aucune isolation du contrôleur de domaine ou désactivation de compte n'est introduite par V3.4.

Ne pas confondre une décision `WAZUH_AR_PROOF` exécutée avec un confinement EDR : c'est une vraie commande distante de diagnostic, mais elle n'applique aucune protection réseau.
