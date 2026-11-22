# AEGISMESH-SOAR V4.0 — Response lifecycle: preuves, progressivité, investigations

> Déploiement GCP: `aegismesh-soar update` après push GitHub. Ne pas transférer le ZIP sur GCP.
> La V4.0 **n'active aucun isolement** ni aucun nouveau blocage à l'installation.

## Réalisé

1. **Post-vérification de blocage IP réelle**: `response verify-block --decision-id am-... --confirm` lit l'état du blocage enregistré sans réinstaller de règles. Sur GCP la sonde interroge Fail2ban **et** nftables. Pour Kali/Windows LAB, elle envoie une action Wazuh *read-only*, puis exige un marqueur Wazuh `BLOCKSTATE`/`WINSTATE` renvoyé du **bon agent**, du bon ID de décision, d'un `check_id` frais et de la bonne IP.
2. **Traçabilité PostgreSQL**: chaque contrôle est inscrit dans `response_checks` (`requested`, `dispatched_unverified`, `blocked`, `removed`, ou échec), et peut être retrouvé par `response check --check-id` ou `response audit --decision-id`. Un ACK d'API n'est **jamais** une preuve de blocage ou de retrait.
3. **Retrait après TTL**: `response enable-expiry-audit --confirm` installe un timer systemd géré toutes les 2 minutes. Il demande seulement des **sondes read-only** des décisions de blocage récentes après 120 s (+ marge), limitées à 2 par exécution et 4 par décision. Il ne modifie aucun pare-feu. Pour chaque machine, `removed` signifie que **les règles appartenant à AEGISMESH-SOAR** ne sont plus présentes, pas que tous les flux réseau ont réussi un test actif.
4. **Garde-fou progressif**: `response enable-progressive --confirm` active `ENABLE_PROGRESSIVE_GUARD=true` de manière atomique, avec contrôle du bridge. Avant `EDR_ISOLATE`, les décisions ultérieures doivent posséder (a) un blocage IP antérieur du **même incident et agent** vérifié par Wazuh dans les 15 min, (b) un flow EDR `FINISHED` récent avec résultats non vides et empreinte. Ceci ne met pas `ENABLE_EDR_ISOLATION=true` et ne change aucune liste d'agents autorisés. Un isolement demandé est toujours soumis aux règles existantes: pas de DC, mTLS, lien unique, agent actif, timer de retrait, score >= 0,95. Le garde-fou n'est pas un moteur d'IA et ne crée aucune décision de lui-même.
5. **Investigation EDR**: `edr triage --agent-id 001|002 --confirm` soumet exactement les artefacts Windows `Windows.System.Pslist`, `Windows.Network.Netstat`, ou Linux `Linux.Sys.Pslist`, `Linux.Network.Netstat`. Le flow réel est tracé, avec empreinte SHA256 de l'échantillon (20 lignes par artefact maximum) seulement lorsque le flow est `FINISHED`. Le compte et les données restent dans Velociraptor, pas d'export automatique des lignes sensibles.
6. **Mapping Kali renommé**: Wazuh `002=kali-ikom` et Velociraptor `offensive` ne correspondent pas textuellement. `edr attest --agent-id 002 --confirm` vérifie les deux identités via Wazuh et API mTLS, sans inventer de nom, et enregistre une attestation de 2 h. Elle ne crée ni modifie un lien client, ni n'ouvre une quarantaine.
7. **Diagnostic EDR de quarantaine**: `edr quarantine-doctor --agent-id 001` lit le label, le bail et la présence textuelle d'artefacts de surveillance côté serveur. **Ne déclare pas** une isolation réseau effective. Les artefacts `Windows.Remediation.QuarantineMonitor` et `Linux.Remediation.Quarantine` doivent réellement être configurés et leur effet mesuré côté client avant validation.
8. **Audit AD de sessions**: `Get-AegisMeshADSessionExposure.ps1 -UserSid 'S-...'` sur le contrôleur Windows collecte seulement les événements de sécurité **locaux au DC** (4624, 4768, 4769, 4771, 4776), par SID/compte, sur une fenêtre limitée. Aucune authentification ni identité modifiée. Ces événements ne prouvent pas que des tickets/sessions déjà émis ont été révoqués.

## Installation GCP après `aegismesh-soar update`

```bash
# Règles de preuve Wazuh ; peut redémarrer le manager si le XML change
sudo aegismesh-soar fleet evidence install --apply --confirm
# Vérifier que le manager et l'API sont revenus
sudo aegismesh-soar ad doctor
# État du garde-fou (il reste désactivé tant qu'on ne l'active pas)
sudo aegismesh-soar response progressive-status
# Optionnel, avant toute autorisation de vraie quarantaine
sudo aegismesh-soar response enable-progressive --confirm
# Après installation des sondes Linux et Windows, activer le contrôle automatique du retrait
sudo aegismesh-soar response enable-expiry-audit --confirm
```

## Installer les sondes sur les endpoints existants

**Kali agent Wazuh 002** (sur Kali et non sur GCP): `install_agent_block.sh` copie à présent `aegismesh-soar-block-status` en plus du blocage existant. Télécharger ensemble ces deux fichiers et le script d'installation depuis le dépôt GitHub validé, puis exécuter `sudo bash install_agent_block.sh`. Cela n'active aucune règle de blocage.

**Windows LAB agent Wazuh 001** (PowerShell admin sur ce poste): télécharger dans un même répertoire `Install-AegisMeshFirewall.ps1`, `aegismesh-soar-firewall.cmd`, `aegismesh-soar-firewall.ps1`, `aegismesh-soar-firewall-cleanup.ps1`, `aegismesh-soar-firewall-status.cmd`, `aegismesh-soar-firewall-status.ps1`, puis exécuter `./Install-AegisMeshFirewall.ps1`. Cela ne désactive ni service ni machine.

**Windows DC agent 006**: l'exécuteur AD déjà validé n'a pas besoin d'être réinstallé pour fonctionner. Pour l'audit de session, télécharger uniquement `Get-AegisMeshADSessionExposure.ps1` et l'exécuter localement en administrateur. Ne pas activer l'isolement global du contrôleur.

## Cycle de preuve sur une vraie décision de blocage existante

```bash
sudo aegismesh-soar response verify-block --decision-id am-IDENTIFIANT-EXISTANT --confirm
# Copier le check_id retourné, puis interroger à nouveau si nécessaire
sudo aegismesh-soar response check --check-id am-CHECK-ID-RETOURNE
sudo aegismesh-soar response audit --decision-id am-IDENTIFIANT-EXISTANT
sudo aegismesh-soar response incident --incident-id ID-INCIDENT-EXISTANT
```

Une décision IP doit préexister (score et références d'événements fournis par le moteur d'analyse); aucun exemple ne fabrique d'IP attaquante, de score ou de preuve. `blocked` est la vérification d'une configuration de blocage de **cet IP**; une preuve de rejet de paquets en conditions réelles exige un test de trafic **autorisé** depuis un poste de laboratoire, puis un test de retour après TTL.

## Vérification et tests EDR

```bash
sudo aegismesh-soar edr clients
sudo aegismesh-soar edr flow-status --agent-id 002 --flow-id F.DC1B583LF7L32
# Si ce flow est toujours RUNNING, ne pas lancer un duplicata.
sudo aegismesh-soar edr attest --agent-id 002 --confirm
sudo aegismesh-soar edr triage --agent-id 001 --confirm
sudo aegismesh-soar edr investigations --agent-id 001
sudo aegismesh-soar edr quarantine-doctor --agent-id 001
sudo aegismesh-soar edr status
```

L'ordre pour un **test réel d'isolement** reste: préparation locale de secours, attestation des agents, EDR flow FINISHED, blocage IP prouvé, assignation réellement vérifiée du moniteur de quarantaine Velociraptor, autorisation explicite et collecte de preuve réseau, puis `edr release --agent-id ... --confirm` et vérification de la restauration. Le label `Quarantine` ne constitue **pas** une preuve suffisante. Aucun test d'isolement ou de blocage n'a été exécuté par la génération du patch.

## AD/LDAP et identité

La chaîne `AD_DISABLE_ACCOUNT` et `AD_LAB_DISABLE` reste inchangée et validée en réel sur `ad.ikom.mg` avec le SID déjà testé. L'audit post-remédiation ajoute un examen des tickets Kerberos/NTLM vus **sur ce DC**; pour révoquer des sessions distantes et des tickets valides déjà émis, une étape supplémentaire doit s'appuyer sur les membres du domaine et leurs sessions réelles. V4.0 ne réinitialise pas de mot de passe et ne ferme pas de session à l'insu de l'opérateur.

## Rollback

- Les règles Windows LAB sont retirées par la tâche SYSTEM 120s. Les entrées nftables Linux ont un timeout natif 120s. Le jail Fail2ban GCP conserve 30–300s.
- L'audit après expiry ne bloque jamais de nouveau.
- Le label Velociraptor n'est retiré que pour un bail SOAR par `edr release` ou timer `edr release-expired`; retrait du label != preuve du retour du trafic.
- Pour désactiver le garde-fou progressif de V4.0, modifier sa configuration par procédure administrateur contrôlée; son activation ne désactive aucune alerte ni fonction de collecte.
