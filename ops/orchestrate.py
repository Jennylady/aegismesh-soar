#!/usr/bin/env python3
"""One command to inspect AEGISMESH/SOAR capabilities, no fabricated scores.

No live actions here; incident decisions are already delivered to /v1/decisions
by Person 1, then through Shuffle to /v1/execute and policy gates.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'soar'))
import bridge


def load():
    env={}
    p=Path('/etc/aegismesh-soar/soar.env')
    if p.is_file():
        for line in p.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                k,v=line.split('=',1); env[k.strip()]=v.strip().strip('"')
    bridge.ENV.clear();bridge.ENV.update(env)
    bridge.DB=env.get('SOAR_DB','/var/lib/aegismesh-soar/decisions.sqlite3')
    return env


def check_service(name):
    try:
        p=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=4)
        return p.stdout.strip() if p.returncode==0 else 'inactive'
    except (OSError,subprocess.TimeoutExpired):return 'unavailable'


def status():
    conf=load()
    print('AEGISMESH SOAR — intégrations déployées (lecture seule)')
    host=conf.get('SOAR_BIND_HOST','127.0.0.1');port=conf.get('SOAR_PORT','19081')
    try:
        req=urllib.request.Request(f'http://{host}:{port}/health')
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=3) as r:
            http=json.load(r)
            bridge_status='OK' if r.status==200 and http.get('status')=='up' else 'ECHEC'
    except (OSError,ValueError):bridge_status='INJOIGNABLE'
    print('Bridge:',bridge_status)
    print('Shuffle webhook:', 'configuré' if conf.get('SHUFFLE_WEBHOOK_URL') else 'absent')
    print('Wazuh manager:',check_service('wazuh-manager.service'))
    print('Fail2ban:',check_service('fail2ban.service'))
    try:
        p=subprocess.run(['fail2ban-client','status','aegismesh-soar-gcp'],capture_output=True,text=True,timeout=5)
        print('Jail SOAR:', 'OK' if p.returncode==0 else 'non disponible')
    except (OSError,subprocess.TimeoutExpired):print('Jail SOAR: non disponible')
    print('Décisions de production:',conf.get('ENABLE_PROD_ACTIONS','false'))
    print('Windows LAB:',conf.get('WAZUH_WINDOWS_AGENT_IDS','non configuré'))
    print('Windows AD (blocage IP limité):',conf.get('WAZUH_WINDOWS_DC_AGENT_IDS','non configuré'))
    try:
        token=bridge.wazuh_auth_token()
        data=bridge.wazuh_api_request('GET','/agents?agents_list=001,002,006&limit=10',None,{'Authorization':'Bearer '+token})
        for agent in (data.get('data',{}).get('affected_items') or []):
            print('Wazuh agent',agent.get('id'),agent.get('name'),agent.get('status'))
    except Exception as exc:
        print('Wazuh API :',type(exc).__name__,'(pas de preuve de liaison actuelle)')
    try:
        from ops import edr_velociraptor as edr
        print('Velociraptor conteneurs:',edr.discovered() or 'aucun détecté')
        print('Velociraptor API mTLS:', 'configurée' if edr.CONF.exists() else 'à raccorder')
        if edr.CONF.exists():
            try:
                print('Velociraptor clients enregistrés:',len(edr.api_clients()))
                print('Correspondances Wazuh/EDR:',edr.read_json(edr.MAPPING,{}))
            except Exception as exc: print('Velociraptor API :',type(exc).__name__)
        print('Quarantaine EDR activée:',conf.get('ENABLE_EDR_ISOLATION','false'))
        print('Retrait automatique:', 'actif' if edr.timer_active() else 'non installé')
    except Exception as exc:print('Velociraptor diagnostic:',type(exc).__name__)
    print('Source des scores et preuves : moteur d analyse de Personne 1 → POST /v1/decisions')
    print('Aucune action envoyée par ce diagnostic.')


def recent():
    load()
    print('Dernières décisions réellement enregistrées (aucune action déclenchée) :')
    if not Path(bridge.DB).is_file():
        print('Aucune base SOAR sur cet environnement. Cette commande se lance sur GCP.')
        return
    with bridge.dbconn() as db:
        rows=db.execute('SELECT id,tag,payload,action_status,updated_at FROM decisions ORDER BY updated_at DESC LIMIT 15').fetchall()
    for r in rows:
        try:
            d=json.loads(r['payload']);agent=(d.get('target') or {}).get('agent_id','-')
            incident=str(d.get('incident_id','-'))[:48]
        except (ValueError,TypeError):agent='-';incident='-'
        print(r['updated_at'],r['id'],r['tag'],'agent='+agent,'state='+r['action_status'],'incident='+incident)


def catalog():
    print('AEGISMESH SOAR — catalogue d’actions')
    print('OBSERVE/ENRICH       collecte et enregistrement, aucune modification sécurité')
    print('F2B_BAN_SERVER       blocage IP publique sur GCP, Fail2ban/nftables, TTL 30–300s')
    print('WAZUH_BLOCK_AGENT    blocage IP publique sur agent Linux 002, nftables, TTL 120s')
    print('WINDOWS_BLOCK_IP     blocage IP publique Windows LAB 001, TTL 120s')
    print('WINDOWS_BLOCK_IP DC  blocage IP public ciblé seulement, agent 006 explicitement autorisé')
    print('EDR_COLLECT          artefact Generic.Client.Info via Velociraptor, async et non destructif')
    print('EDR_ISOLATE          label Quarantine Velociraptor, autorisé seulement après API mTLS,')
    print('                     correspondance agent unique, timer de retrait et autorisation explicite')
    print('EDR_RELEASE          retrait de la quarantaine SOAR exclusivement; pas de quarantaine externe')
    print('AD_DISABLE_ACCOUNT   NON IMPLEMENTÉ : attend l’étape AD/LDAP, stratégie dédiée')
    print('Aucune commande libre, pas de score ou preuve inventés : incidents Personne 1 → SOAR.')


def main():
    p=argparse.ArgumentParser(description='AEGISMESH / diagnostic d’orchestration')
    p.add_argument('action',choices=['status','recent','catalog','reconcile'])
    a=p.parse_args()
    if a.action=='status':status()
    elif a.action=='recent':recent()
    elif a.action=='catalog':catalog()
    else:
        load();print(json.dumps(bridge.reconcile_wazuh_decisions(),indent=2,ensure_ascii=False))
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,RuntimeError,ValueError,PermissionError) as exc:
        print('ÉCHEC orchestration:',type(exc).__name__,str(exc)[:120],file=sys.stderr)
        sys.exit(2)
