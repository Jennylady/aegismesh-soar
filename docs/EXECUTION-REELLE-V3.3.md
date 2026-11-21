# AEGISMESH SOAR V3.3 — Actions réelles, sans simulation

## Périmètre et contrat d'exécution

Cette version conserve **Shuffle et son Webhook existants**, le service `aegismesh-soar-bridge`, Wazuh Manager 4.14 et la jail Fail2ban `aegismesh-soar-gcp`. Elle ne modifie pas le moteur de détection/corrélation de la personne 1.

Le moteur d'analyse soumet une décision JSON authentifiée avec `DECISION_TOKEN`. Le bridge valide la politique, l'expiration, les références de preuves et la liste des actions; il transmet à Shuffle. Shuffle rappelle `/v1/execute` avec `SHUFFLE_ACTION_TOKEN`. Le bridge ne reçoit **aucune commande shell arbitraire** et exécute uniquement l'adaptateur déterminé par le tag conservé en base.

- `F2B_BAN_SERVER`: `fail2ban-client set aegismesh-soar-gcp banip <ip>` puis vérifications de la jail, du set nftables **et** de la règle utilisant ce set. Le délai est contrôlé via `bantime` (30 à 300 s). Si nftables ne prouve pas le blocage, le ban ajouté par ce bridge est retiré et la décision échoue.
- `WAZUH_BLOCK_AGENT`: API Wazuh `PUT /active-response?agents_list=<ID>` avec la commande **fixe** `!aegismesh-soar-block`. L'agent Linux autorisé doit posséder `/var/ossec/active-response/bin/aegismesh-soar-block`. Son script ajoute un élément à un set `nftables` dédié, expirant automatiquement après **120 secondes**. Il refuse les IP non publiques et les adresses d'administration SSH actuellement connectées ou listées dans son fichier de protection.

**Important :** L'API Wazuh peut confirmer la **distribution** à un agent sans confirmer l'application de la règle sur cet agent. Cette version retourne donc `action_status=dispatched_unverified`, non `executed`, tant qu'une preuve de l'agent n'a pas été consultée.

Windows et Windows Server AD sont volontairement exclus de `WAZUH_BLOCK_AGENT` V3.3 : leur confinement exige un exécuteur Windows spécifique, avec garantie de maintien du canal de gestion. Ne pas réutiliser un script Linux via `netsh` sur AD.

## 1. Développement et publication : KALI uniquement

Dans `/home/lady/SOUTENANCE/aegismesh-soar` :

```bash
unzip -o ~/Downloads/AEGISMESH-SOAR-PATCH-V3.3.zip
chmod +x bin/aegismesh-soar ops/wazuh/aegismesh-soar-block ops/wazuh/install_agent_block.sh
python3 bin/aegismesh-soar test
git diff --check
git add -A && git commit -m 'feat: Wazuh Linux Active Response et Fail2ban réels V3.3'
git push origin main
```

## 2. GCP : mise à jour sans ZIP

```bash
aegismesh-soar update
aegismesh-soar health --verbose
aegismesh-soar chain wazuh-connect
```

`wazuh-connect` utilise en boucle locale le **certificat de serveur Wazuh** `/var/ossec/api/configuration/ssl/server.crt` comme ancre de confiance spécifique à cette instance ; il conserve la vérification du certificat. Sur une API distante, la vérification du nom et la CA explicite restent obligatoires. `WAZUH_TLS_INSECURE=true` est refusé pour la chaîne SOAR.

Si la connexion ne fonctionne pas, le message détaille la cause, notamment port refusé, délai dépassé, erreur TLS ou HTTP 401. Ne pas utiliser `curl -k` comme solution permanente. Si Wazuh ne répond pas sur `https://127.0.0.1:55000`, vérifier l'adresse d'écoute et utiliser `aegismesh-soar configure wazuh-url https://ADRESSE_PRIVEE:55000` avec une CA valide pour ce nom/IP.

## 3. Déployer **une seule fois** l'exécuteur sur l'agent Linux (Kali, ID 002)

Sur la machine Kali qui exécute réellement l'agent Wazuh 002 (pas sur le manager) :

```bash
cd /home/lady/SOUTENANCE/aegismesh-soar
sudo bash ops/wazuh/install_agent_block.sh
```

Cela ne redémarre pas Wazuh, ne modifie pas `ossec.conf` et ne lance aucun ban. Sur les autres agents Linux, distribuer cette même paire de fichiers de façon contrôlée avant de les autoriser dans la liste de production. Si `nft` ou `/var/ossec/active-response/bin` manque sur un agent, l'installation s'arrête sans action.

Option de protection locale supplémentaire sur chaque agent (une CIDR par ligne) : `/etc/aegismesh-soar-agent/protected-cidrs.txt`. Les connexions SSH actuellement établies sont protégées indépendamment de ce fichier.

## 4. Autoriser explicitement les actions réelles

Sur GCP :

```bash
aegismesh-soar configure production
aegismesh-soar chain production-status
```

Le menu demande les plages **publiques de gestion** à ne jamais bloquer et les **IDs d'agents Linux autorisés** (par exemple `002` seulement une fois l'agent provisionné). Il requiert la confirmation `ACTIVER`, enregistre les paramètres dans `/etc/aegismesh-soar/soar.env` hors Git, puis redémarre **uniquement** `aegismesh-soar-bridge.service`.

L'activation ne déclenche aucun blocage par elle-même. Les décisions nécessitent `approved=true`, `confidence>=0.90`, deux preuves distinctes, un incident et une IP publique globale non protégée. Une approbation ne doit être délivrée que par la politique de décision autorisée, pas fabriquée par les événements bruts.

## 5. Exécution réelle d'une décision Fail2ban

Quand la personne 1 a produit un incident confirmé avec deux preuves, sur GCP :

```bash
aegismesh-soar chain ban-ip \
  --ip 'IP_PUBLIQUE_CONFIRMED' \
  --incident 'INCIDENT_REEL' \
  --evidence 'PREUVE_1' --evidence 'PREUVE_2' \
  --confidence 0.96 --confirm
```

`0.96` est **un exemple de syntaxe**, pas un score à inventer. Remplacer par le score réellement évalué. Le parcours exact reste **décision → Shuffle → bridge → Fail2ban → nftables → état**. Le résultat ne peut être `executed` que si la jail et nftables montrent le ban.

Pour arrêter de nouvelles actions de production sans toucher aux bans déjà présents :

```bash
aegismesh-soar configure disable-production
```

## 6. Exécution réelle d'une décision sur un agent Wazuh Linux

Après l'installation et le contrôle de l'accès API :

```bash
aegismesh-soar chain block-agent --agent-id 002 \
  --ip 'IP_PUBLIQUE_CONFIRMED' \
  --incident 'INCIDENT_REEL' \
  --evidence 'PREUVE_1' --evidence 'PREUVE_2' \
  --confidence 0.96 --confirm
```

La commande est transmise via **Shuffle** et l'API Wazuh au **seul** agent sélectionné. Une réponse API positive conduit à `dispatched_unverified` (pas à `executed`). Sur l'agent Linux lui-même, vérifier la preuve et l'état du set, avant expiration du délai de 120 s :

```bash
sudo tail -n 10 /var/ossec/logs/aegismesh-soar-ar.jsonl
sudo nft list set inet aegismesh_soar_ar blocked_ipv4
```

La présence de `decision_id` dans le journal et de l'IP dans le set avec une expiration restante apporte la preuve de l'effet réel. Le blocage expire automatiquement sans commande d'unban manuelle.

## 7. Raccordement de la personne 1

Son moteur ne doit jamais invoquer directement `nft`, `fail2ban-client` ou une commande shell sur l'agent. Il transmet au bridge une décision structurée avec les tags autorisés et ses véritables `confidence`, `approved`, `evidence_ids`, `incident_id`, `target.agent_id`, `target.ip`. Le bridge conserve les contraintes et Shuffle reste l'orchestrateur central.

## Restrictions de sécurité

- Aucune remédiation automatique activée pendant `update`.
- Aucune modification des configurations Wazuh Manager, du relais Shuffle existant ni des jails SSH.
- Aucune IP privée, WireGuard, loopback, TEST-NET, CIDR de gestion ou cible non approuvée.
- Les éléments nftables côté agent Linux expirent à 120 secondes. La jail Fail2ban doit avoir un `bantime` entre 30 et 300 secondes.
- Pas de ciblage Windows/AD dans cet exécuteur Linux.
- L'API Wazuh doit présenter un certificat vérifié ; aucun TLS désactivé.
