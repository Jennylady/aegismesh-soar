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
    winpath=bridge.wazuh_evidence(agent,ident,'winblock')
    if proofpath or blockpath or winpath:
        print('EXÉCUTION AGENT VÉRIFIÉE via',proofpath or blockpath or winpath)
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
        rows=conn.execute("SELECT id,payload,action_status FROM decisions WHERE tag IN ('WAZUH_AR_PROOF','WAZUH_BLOCK_AGENT','WINDOWS_BLOCK_IP','AD_DISABLE_ACCOUNT') ORDER BY updated_at DESC LIMIT 12").fetchall()
    print('Décisions Wazuh (dernières 12) :')
    for row in rows:
        try:
            agent=json.loads(row['payload']).get('target',{}).get('agent_id','?')
        except (ValueError,TypeError):agent='?'
        print(' ',str(agent),row['id'],row['action_status'])
    print('La présence du script sur l’agent ne prouve pas la collecte. Seules les alertes associées au bon agent sont acceptées.')


def evidence_diagnose(agent, decision_id):
    """Read-only Wazuh manager evidence trace, never sends a new AR."""
    if not re.fullmatch(r'\d{3}', agent) or not bridge.RX_ID.fullmatch(decision_id):
        raise ValueError('Identifiants agent/decision invalides')
    with bridge.dbconn() as conn:
        row = conn.execute('SELECT payload,action_status FROM decisions WHERE id=?', (decision_id,)).fetchone()
    if row is None:
        raise ValueError('Decision inconnue dans la base SOAR')
    payload=json.loads(row['payload'])
    target=str((payload.get('target') or {}).get('agent_id',''))
    if target != agent:
        raise ValueError('La decision appartient a un autre agent : refus de confusion des preuves')
    print('Agent Wazuh:',agent,'Decision:',decision_id)
    print('Action demandee:',payload.get('tag'),'Etat SOAR:',row['action_status'])
    print('Regle de preuve installee:',Path('/var/ossec/etc/rules/aegismesh-soar-evidence.xml').is_file())
    kind=('winblock' if payload.get('tag') == 'WINDOWS_BLOCK_IP' else
          'adaccount' if payload.get('tag') == 'AD_DISABLE_ACCOUNT' else
          'block' if payload.get('tag') == 'WAZUH_BLOCK_AGENT' else 'proof')
    found=bridge.wazuh_evidence(agent,decision_id,kind,
                                user_sid=(payload.get('target') or {}).get('user_sid'))
    if found:
        print('PREUVE RECUE ET ATTRIBUEE au bon agent depuis:',found)
        print('Utiliser: aegismesh-soar fleet evidence reconcile')
    else:
        print('AUCUNE PREUVE CORRESPONDANTE dans les fichiers Wazuh du manager.')
        print('Sur le poste Windows: Diagnose-AegisMeshProof.ps1 -DecisionId '+decision_id)
        print('Si le journal local contient la preuve: rechercher la collecte sur le poste.')
        print('Si le journal local est vide: examiner ossec.log et le lanceur Active Response.')
    return 0


def windows_firewall_status(agent, decision_id):
    """Read-only actual Windows firewall application and expiration evidence."""
    if not re.fullmatch(r'\d{3}', agent) or not bridge.RX_ID.fullmatch(decision_id):
        raise ValueError('Identifiant agent ou decision invalide')
    with bridge.dbconn() as conn:
        item=conn.execute('SELECT tag,payload,action_status FROM decisions WHERE id=?', (decision_id,)).fetchone()
    if not item or item['tag']!='WINDOWS_BLOCK_IP' or json.loads(item['payload'])['target'].get('agent_id')!=agent:
        raise PermissionError('Decision non associee a cet agent Windows')
    applied=bridge.wazuh_evidence(agent,decision_id,'winblock')
    removed=bridge.wazuh_evidence(agent,decision_id,'winunblock')
    print('Agent:',agent,'Decision:',decision_id,'Statut SOAR:',item['action_status'])
    print('Regles Windows confirmees via Wazuh:',bool(applied))
    print('Retrait TTL confirme via Wazuh:',bool(removed))
    if removed and not applied:
        print('ALERTE: retrait signale sans preuve de creation dans les journaux accessibles')
    if not removed:
        print('ATTENTION: absence de preuve de suppression ne prouve pas le maintien du blocage.')
    return 0

def evidence_operation(args):
    if args.evidence_action=='install':
        sys.path.insert(0,str(ROOT/'ops/wazuh'))
        import install_manager_evidence
        print(install_manager_evidence.install(apply=args.apply,confirm=args.confirm))
        return 0
    if args.evidence_action=='status':
        evidence_status();return 0
    if args.evidence_action=='diagnose':
        return evidence_diagnose(args.agent_id,args.decision_id)
    if args.evidence_action=='reconcile':
        print('Réconciliation (aucune action distante envoyée) :')
        print(json.dumps(bridge.reconcile_wazuh_decisions(), ensure_ascii=False,indent=2))
        return 0
    raise ValueError('Opération de preuve inconnue')

def main():
    parser=argparse.ArgumentParser(description='AEGISMESH : parc des agents et preuves Wazuh')
    subs=parser.add_subparsers(dest='action',required=True)
    subs.add_parser('status')
    fw=subs.add_parser('firewall-status',help='Verifier creation et expiration du blocage Windows via Wazuh')
    fw.add_argument('--agent-id',required=True)
    fw.add_argument('--decision-id',required=True)
    a=subs.add_parser('proof');a.add_argument('--agent-id',required=True)
    b=subs.add_parser('verify');b.add_argument('--agent-id',required=True);b.add_argument('decision_id')
    e=subs.add_parser('evidence',help='Collecte Wazuh et réconciliation des preuves')
    es=e.add_subparsers(dest='evidence_action',required=True)
    ins=es.add_parser('install');ins.add_argument('--apply',action='store_true');ins.add_argument('--confirm',action='store_true')
    es.add_parser('status')
    es.add_parser('reconcile')
    di=es.add_parser('diagnose',help='Diagnostic lecture seule d’une commande sur un agent')
    di.add_argument('--agent-id', required=True)
    di.add_argument('--decision-id', required=True)
    args=parser.parse_args()
    if args.action=='proof':return proof(args.agent_id)
    if args.action=='firewall-status':
        configure_bridge();return windows_firewall_status(args.agent_id,args.decision_id)
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
