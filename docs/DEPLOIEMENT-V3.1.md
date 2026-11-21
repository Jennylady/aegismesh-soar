# AEGISMESH SOAR V3.1 — Déploiement Git depuis Kali uniquement

## Ce qui s'est passé

Sur GCP, le code de l'updater V2 fait : `systemctl restart` → `systemctl is-active` → unique requête `/health`. Il ne laisse aucun délai au serveur Python pour ouvrir son socket. Lorsque cette vérification échoue, l'updater fait un rollback vers le commit antérieur même si le nouveau code a réussi tous ses tests.

Ce diagnostic est une **cause plausible** à confirmer : un service qui plante ou un port déjà utilisé produisent également ce symptôme. Les tests simulés en local ne prouvent pas que GCP est sain.

## Correctif compatible avec l'updater déjà installé

Le fichier `ops/systemd/aegismesh-soar-bridge.service` contient désormais :

```ini
Type=simple
TimeoutStartSec=45
ExecStart=/usr/bin/python3 /opt/aegismesh/soar/soar/bridge.py
ExecStartPost=/usr/bin/python3 /opt/aegismesh/soar/ops/wait_ready.py --timeout 30
```

Systemd n'achève le `restart` qu'après la sortie de `ExecStartPost`. Il attend donc un vrai HTTP 200 + JSON `service=aegismesh-soar-bridge, status=up`, exactement ce qui manquait à V2. Si la santé n'est pas obtenue, la commande signale son échec ; la politique de retour arrière est conservée.

## Opérations

**Kali :**

```bash
cd /home/lady/SOUTENANCE/aegismesh-soar
unzip -o /home/raph/Downloads/AEGISMESH-SOAR-PATCH-V3.1.zip
python3 bin/aegismesh-soar test
git diff --check
git add -A
git commit -m 'fix: reliable SOAR bridge readiness during update'
git push origin main
```

**Serveur GCP :**

```bash
aegismesh-soar update
# Uniquement si l'update échoue encore :
systemctl show aegismesh-soar-bridge.service -p ActiveState -p SubState -p Result -p ExecMainStatus -p MainPID -p NRestarts
journalctl -u aegismesh-soar-bridge.service --since '15 minutes ago' -n 65 --no-pager
ss -lntp | grep ':19081' || true
curl --noproxy '*' -sS --max-time 4 -i http://127.0.0.1:19081/health
```

Ne partager aucun mot de passe, jeton ou header d'authentification. Ne pas redémarrer Wazuh, Fail2ban, Shuffle ou le relais existant.

## États à distinguer

- Dépôt Git à jour : version de code téléchargée, pas preuve de fonctionnement.
- `systemctl active/running` : processus démarré, pas preuve que l'API répond.
- `/health` validé : disponibilité HTTP du bridge, pas preuve du workflow Shuffle.
- Workflow Shuffle avec retour `/v1/execute` : preuve d'orchestration non destructive sur un tag OBSERVE.
- Wazuh/Fail2ban exécuté et vérifié : phase d'intégration ultérieure, nécessite garde-fous.

## Configuration privée et futur dépôt GitHub privé

`update` accepte `https://github.com/Jennylady/aegismesh-soar.git` ou `git@github.com:Jennylady/aegismesh-soar.git`. Pour un dépôt privé, préparer **avant** le changement de visibilité la clé de déploiement en lecture seule depuis `aegismesh-soar repo prepare-private`, l'enregistrer sur GitHub, et tester `aegismesh-soar repo use-ssh`. Ne jamais enregistrer la clé privée ou `/etc/aegismesh-soar/soar.env` dans Git.
