#!/usr/bin/env python3
"""Wazuh fleet actions via a real Shuffle-dispatched decision, not a second bridge.

Execute on GCP (not Kali or Windows); no Wazuh credentials copied to agents.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'soar'))
import bridge


def configure_bridge():
    cfg={}
    path=Path('/etc/aegismesh-soar/soar.env')
    if not path.is_file():
        raise RuntimeError('Configuration privée absente; exécuter sur GCP')
    for line in path.read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,val=line.split('=',1)
            cfg[key.strip()]=val.strip().strip('"')
    if not cfg.get('WAZUH_USER') or not cfg.get('WAZUH_PASSWORD'):
        raise RuntimeError('API Wazuh non configurée sur ce serveur')
    bridge.ENV.clear();bridge.ENV.update(cfg)
    bridge.DB=cfg.get('SOAR_DB','/var/lib/aegismesh-soar/decisions.sqlite3')
    return cfg


def status():
    token=bridge.wazuh_auth_token()
    data=bridge.wazuh_api_request('GET','/agents?agents_list=001,002,006&limit=10',None, {'Authorization':'Bearer '+token})
    items=(data.get('data') or {}).get('affected_items') or []
    print('ID  Agent                 OS                Wazuh')
    for item in sorted(items,key=lambda i:str(i.get('id',''))):
        label=str((item.get('os') or {}).get('name','?'))[:17]
        print(f"{str(item.get('id','')):3s} {str(item.get('name',''))[:21]:21s} {label:17s} {str(item.get('status','?'))}")
    print('Vérifie la liaison de contrôle, pas encore l’exécution sur la machine.')


def proof(agent):
    if not re.fullmatch(r'\d{3}',agent):
        raise ValueError('ID Wazuh de trois chiffres requis')
    cfg=configure_bridge()
    if cfg.get('ENABLE_TEST_ACTIONS')!='true':
        raise RuntimeError('Activer explicitement: aegismesh-soar configure enable-tests')
    allowed={x.strip() for x in cfg.get('WAZUH_TEST_AGENTS','000').split(',')}
    if agent not in allowed:
        raise RuntimeError('Agent absent de la liste de preuve: configure wazuh-proof-agents 001,002,006')
    jwt=bridge.wazuh_auth_token()
    record=bridge.wazuh_agent_record(agent,jwt)
    print('Wazuh agent actif:',record.get('name'), '/',agent)
    proc=subprocess.run([sys.executable,str(ROOT/'soar/soarctl.py'), 'submit',
        '--tag','WAZUH_AR_PROOF','--incident-id','AEGISMESH-AR-CONNECTIVITY',
        '--agent-id',agent,'--approved','--confidence','0.99',
        '--evidence','operator-confirmed-proof','--evidence','authorized-endpoint-action',
        '--wait','40'],check=False)
    return proc.returncode


def verify(agent, ident):
    if not re.fullmatch(r'\d{3}',agent) or not bridge.RX_ID.fullmatch(ident):
        raise ValueError('Identifiant agent/décision invalide')
    proofpath=bridge.wazuh_evidence(agent,ident,'proof')
    blockpath=bridge.wazuh_evidence(agent,ident,'block')
    if proofpath or blockpath:
        print('EXÉCUTION AGENT VÉRIFIÉE via',proofpath or blockpath)
        print('Agent:',agent,'Décision:',ident)
        return 0
    print('PAS DE PREUVE MANAGER : vérifier le fichier active-responses.log sur l’agent concerné.')
    print('Aucun journal reçu ne permet de conclure que l’action a été exécutée.')
    return 3




def evidence_status():
    rules = Path('/var/ossec/etc/rules/aegismesh-soar-evidence.xml')
    print('Règles de collecte SOAR :', 'INSTALLÉES' if rules.is_file() else 'ABSENTES')
    for source in bridge.EVIDENCE_LOGS:
        path=Path(source)
        print('Manager:',source,'present='+str(path.is_file()),
              'taille_octets='+str(path.stat().st_size if path.is_file() else 0))
    with bridge.dbconn() as conn:
        rows=conn.execute("SELECT id,payload,action_status FROM decisions WHERE tag IN ('WAZUH_AR_PROOF','WAZUH_BLOCK_AGENT') ORDER BY updated_at DESC LIMIT 12").fetchall()
    print('Décisions Wazuh (dernières 12) :')
    for row in rows:
        try:
            agent=json.loads(row['payload']).get('target',{}).get('agent_id','?')
        except (ValueError,TypeError):agent='?'
        print(' ',str(agent),row['id'],row['action_status'])
    print('La présence du script sur l’agent ne prouve pas la collecte. Seules les alertes associées au bon agent sont acceptées.')


def evidence_operation(args):
    if args.evidence_action=='install':
        sys.path.insert(0,str(ROOT/'ops/wazuh'))
        import install_manager_evidence
        print(install_manager_evidence.install(apply=args.apply,confirm=args.confirm))
        return 0
    if args.evidence_action=='status':
        evidence_status();return 0
    if args.evidence_action=='reconcile':
        print('Réconciliation (aucune action distante envoyée) :')
        print(json.dumps(bridge.reconcile_wazuh_decisions(), ensure_ascii=False,indent=2))
        return 0
    raise ValueError('Opération de preuve inconnue')

def main():
    parser=argparse.ArgumentParser(description='AEGISMESH : parc des agents et preuves Wazuh')
    subs=parser.add_subparsers(dest='action',required=True)
    subs.add_parser('status')
    a=subs.add_parser('proof');a.add_argument('--agent-id',required=True)
    b=subs.add_parser('verify');b.add_argument('--agent-id',required=True);b.add_argument('decision_id')
    e=subs.add_parser('evidence',help='Collecte Wazuh et réconciliation des preuves')
    es=e.add_subparsers(dest='evidence_action',required=True)
    ins=es.add_parser('install');ins.add_argument('--apply',action='store_true');ins.add_argument('--confirm',action='store_true')
    es.add_parser('status')
    es.add_parser('reconcile')
    args=parser.parse_args()
    if args.action=='proof':return proof(args.agent_id)
    if args.action=='evidence' and args.evidence_action=='install':
        return evidence_operation(args)
    configure_bridge()
    if args.action=='evidence':return evidence_operation(args)
    return status() if args.action=='status' else verify(args.agent_id,args.decision_id)


if __name__=='__main__':
    try:sys.exit(main() or 0)
    except (RuntimeError,ValueError,PermissionError,ConnectionError) as exc:
        print('ÉCHEC :',type(exc).__name__,str(exc)[:180],file=sys.stderr)
        sys.exit(2)
