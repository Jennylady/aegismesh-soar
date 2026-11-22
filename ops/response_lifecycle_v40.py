#!/usr/bin/env python3
"""AEGISMESH SOAR: real, idempotent containment state observations.

Unlike an API dispatch ACK, each observation must originate from the existing
firewall (GCP Fail2ban+nftables) or from an endpoint's read-only status executor
collected by the Wazuh manager. This CLI never creates a blocking rule.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import subprocess
import urllib.request
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'soar'))
import bridge

ENV = Path('/etc/aegismesh-soar/soar.env')
RX_CHECK = re.compile(r'am-[0-9a-f]{24}\Z')
MARKER = re.compile(r'AEGISMESH-SOAR-(BLOCKSTATE|WINSTATE) decision_id=(am-[0-9a-f]{24}) check_id=(am-[0-9a-f]{24}) status=(blocked|removed) ip=((?:\d{1,3}\.){3}\d{1,3})(?=\s|$)')
SCHEMA = ('CREATE TABLE IF NOT EXISTS response_checks ('
          'check_id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, agent_id TEXT NOT NULL, '
          'ip TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, '
          'evidence_source TEXT, checked_at TEXT NOT NULL)')


def configure(path=ENV):
    if not path.is_file():
        raise RuntimeError('Configuration SOAR privée introuvable : exécuter sur le serveur GCP')
    cfg={}
    for line in path.read_text(encoding='utf-8').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,value=line.split('=',1)
            cfg[key.strip()]=value.strip().strip('"')
    bridge.ENV.clear();bridge.ENV.update(cfg)
    bridge.DB=cfg.get('SOAR_DB','/var/lib/aegismesh-soar/decisions.sqlite3')
    return cfg


def ensure_table():
    with bridge.dbconn() as db:
        db.execute(SCHEMA)


def decision_data(ident):
    if not RX_CHECK.fullmatch(str(ident)):
        raise ValueError('Identifiant de décision réel attendu am-...')
    with bridge.dbconn() as db:
        row=db.execute('SELECT payload,action_status,detail FROM decisions WHERE id=?',(ident,)).fetchone()
    if not row:
        raise ValueError('Décision absente de PostgreSQL SOAR')
    data=json.loads(row['payload'])
    if data.get('decision_id')!=ident or data.get('tag') not in ('F2B_BAN_SERVER','WAZUH_BLOCK_AGENT','WINDOWS_BLOCK_IP'):
        raise PermissionError('Vérification réservée à une décision de blocage IP enregistrée')
    if row['action_status'] not in ('executed','dispatched_unverified','needs_manual_review'):
        raise PermissionError('Décision sans action distribuée : aucun effet réseau à prouver')
    target=data.get('target') or {}
    ip=str(ipaddress.ip_address(target.get('ip','')))
    if not ipaddress.ip_address(ip).is_global:
        raise PermissionError('Seule une IP globale approuvée par la décision est admissible')
    agent=str(target.get('agent_id','000')) if data['tag']!='F2B_BAN_SERVER' else '000'
    if not re.fullmatch(r'\d{3}',agent):
        raise ValueError('ID agent Wazuh invalide')
    return data,row,ip,agent


def extract_state(message, *, decision_id, check_id, ip, kind):
    """Strong correlation: marker, Wazuh agent, decision ID, fresh check ID, IP."""
    if not isinstance(message,str):return None
    states=[]
    for match in MARKER.finditer(message):
        if match.group(1)==kind and match.group(2)==decision_id and match.group(3)==check_id and match.group(5)==ip:
            states.append(match.group(4))
    return states[-1] if states else None


def collected_state(agent, decision_id, check_id, ip, kind, *, sources=None, tail_bytes=24_000_000):
    """Read only real Wazuh manager archives, not any agent-supplied local file."""
    found=None
    paths=sources if sources is not None else bridge.EVIDENCE_LOGS
    for path in paths:
        try:
            with open(path,'rb') as f:
                f.seek(0,os.SEEK_END)
                f.seek(max(0,f.tell()-tail_bytes))
                if f.tell()!=0:f.readline()
                for line in f:
                    if b'AEGISMESH-SOAR-' not in line:continue
                    try:event=json.loads(line)
                    except (ValueError,UnicodeDecodeError):continue
                    if str((event.get('agent') or {}).get('id','')).zfill(3)!=agent:continue
                    state=extract_state(event.get('full_log',''),decision_id=decision_id,check_id=check_id,ip=ip,kind=kind)
                    if state:
                        found={'state':state,'source':str(path)}
        except (OSError,PermissionError):continue
    return found


def record(check_id, decision, agent, ip, action, state, source=None):
    ensure_table()
    now=dt.datetime.now(dt.timezone.utc).isoformat()
    with bridge.dbconn() as db:
        exists=db.execute('SELECT check_id FROM response_checks WHERE check_id=?',(check_id,)).fetchone()
        if exists:
            db.execute('UPDATE response_checks SET status=?,evidence_source=?,checked_at=? WHERE check_id=?',
                       (state,source,now,check_id))
        else:
            db.execute('INSERT INTO response_checks (check_id,decision_id,agent_id,ip,action,status,evidence_source,checked_at) '
                       'VALUES (?,?,?,?,?,?,?,?)',(check_id,decision,agent,ip,action,state,source,now))


def last_check(check_id):
    if not RX_CHECK.fullmatch(str(check_id)):raise ValueError('check_id invalide')
    ensure_table()
    with bridge.dbconn() as db:
        result=db.execute('SELECT * FROM response_checks WHERE check_id=?',(check_id,)).fetchone()
    if result is None:raise ValueError('Vérification inconnue')
    return dict(result)


def f2b_state(ip):
    """Fail closed if fail2ban and its nftables backend disagree."""
    proc=subprocess.run(['nft','-j','list','ruleset'],capture_output=True,text=True,timeout=12)
    if proc.returncode:
        raise RuntimeError('Impossible de vérifier l état nftables, refus de conclure au retrait')
    json.loads(proc.stdout)
    bans=bridge.f2b_get_bans('aegismesh-soar-gcp')
    in_jail=ip in bans
    in_nft=bridge.f2b_nft_confirmed(ip)
    if in_jail and in_nft:
        return 'blocked'
    if not in_jail and not in_nft:
        return 'removed'
    return 'unknown'


def verify(ident, *, wait=28, sleep=time.sleep):
    data, row, ip, agent=decision_data(ident)
    kind=data['tag']
    check_id='am-'+secrets.token_hex(12)
    record(check_id,ident,agent,ip,kind,'requested')
    if kind=='F2B_BAN_SERVER':
        result=f2b_state(ip)
        record(check_id,ident,agent,ip,kind,result,'fail2ban-client+nftables-local')
        return last_check(check_id)
    token=bridge.wazuh_auth_token()
    record_w=bridge.wazuh_agent_record(agent,token)
    osname=' '.join(str(x) for x in (record_w.get('os') or {}).values()).lower()
    if kind=='WAZUH_BLOCK_AGENT' and 'linux' not in osname and not any(x in osname for x in ('kali','ubuntu','debian')):
        raise PermissionError('L agent ciblé ne déclare pas Linux')
    if kind=='WINDOWS_BLOCK_IP' and 'windows' not in osname:
        raise PermissionError('L agent ciblé ne déclare pas Windows')
    command='!aegismesh-soar-block-status' if kind=='WAZUH_BLOCK_AGENT' else '!aegismesh-soar-firewall-status.cmd'
    body={'command':command,'arguments':[], 'alert':{'data':{
        'decision_id':ident,'check_id':check_id,'srcip':ip}}}
    response=bridge.wazuh_api_request('PUT','/active-response?agents_list='+agent,body,
                                       {'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    if response.get('error') or int((response.get('data') or {}).get('total_affected_items',0))!=1:
        record(check_id,ident,agent,ip,kind,'dispatch_failed')
        raise RuntimeError('Wazuh API n a pas confirmé la distribution de la sonde de lecture')
    record(check_id,ident,agent,ip,kind,'dispatched_unverified')
    probe_kind='BLOCKSTATE' if kind=='WAZUH_BLOCK_AGENT' else 'WINSTATE'
    deadline=time.monotonic()+wait
    while True:
        found=collected_state(agent,ident,check_id,ip,probe_kind)
        if found:
            record(check_id,ident,agent,ip,kind,found['state'],found['source'])
            break
        if time.monotonic()>=deadline:break
        sleep(min(1.5,max(0,deadline-time.monotonic())))
    return last_check(check_id)


def refresh(check_id):
    row=last_check(check_id)
    if row['status']!='dispatched_unverified':return row
    kind={'WAZUH_BLOCK_AGENT':'BLOCKSTATE','WINDOWS_BLOCK_IP':'WINSTATE'}.get(row['action'])
    if kind:
        found=collected_state(row['agent_id'],row['decision_id'],check_id,row['ip'],kind)
        if found:
            record(check_id,row['decision_id'],row['agent_id'],row['ip'],row['action'],found['state'],found['source'])
    return last_check(check_id)


def audit(ident=None):
    ensure_table()
    if ident is not None and not RX_CHECK.fullmatch(ident):raise ValueError('decision_id invalide')
    with bridge.dbconn() as db:
        if ident:
            rows=db.execute('SELECT * FROM response_checks WHERE decision_id=? ORDER BY checked_at DESC LIMIT 30',(ident,)).fetchall()
        else:
            rows=db.execute('SELECT * FROM response_checks ORDER BY checked_at DESC LIMIT 30').fetchall()
    return [dict(r) for r in rows]


def incident(incident_id):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{4,120}',incident_id):
        raise ValueError('Identifiant incident invalide')
    with bridge.dbconn() as db:
        rows=db.execute('SELECT id,tag,action_status,payload,detail,updated_at FROM decisions ORDER BY updated_at DESC LIMIT 250').fetchall()
    decisions=[]
    for row in rows:
        data=json.loads(row['payload'])
        if data.get('incident_id')==incident_id:
            decisions.append({'decision_id':row['id'],'tag':row['tag'], 'state':row['action_status'],
                              'confidence':data.get('confidence'), 'evidence_ids':data.get('evidence_ids',[]),
                              'agent_id':(data.get('target') or {}).get('agent_id'), 'updated_at':row['updated_at']})
    return decisions



def progressive_status():
    cfg=configure()
    return {'guard_enabled':cfg.get('ENABLE_PROGRESSIVE_GUARD')=='true',
            'policy':'Require one previous executed scoped IP block for same incident/agent + '
                     'FINISHED EDR flow with bounded real results within 30 minutes',
            'isolation_enabled_separately':cfg.get('ENABLE_EDR_ISOLATION')=='true',
            'edr_allowed_agents':cfg.get('EDR_ISOLATION_AGENT_IDS',''),
            'no_action_sent':True}


def enable_progressive(confirm, *, path=ENV):
    """Atomically enable a stronger gate, never EDR isolation itself."""
    if not confirm:raise PermissionError('--confirm obligatoire')
    if os.geteuid()!=0:raise PermissionError('root requis')
    previous=path.read_text(encoding='utf-8')
    if re.search(r'^ENABLE_PROGRESSIVE_GUARD=true\s*$',previous,re.MULTILINE):
        return {'already_enabled':True,'service_changed':False}
    rows=previous.splitlines()
    result=[];replaced=False
    for row in rows:
        if row.startswith('ENABLE_PROGRESSIVE_GUARD='):
            result.append('ENABLE_PROGRESSIVE_GUARD=true');replaced=True
        else:result.append(row)
    if not replaced:result.append('ENABLE_PROGRESSIVE_GUARD=true')
    fd,tmp=tempfile.mkstemp(prefix='.response-v40-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            os.fchmod(f.fileno(),0o600)
            f.write('\n'.join(result)+'\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        try:
            r=subprocess.run(['systemctl','restart','aegismesh-soar-bridge.service'],capture_output=True,timeout=40)
            if r.returncode:raise RuntimeError('Bridge restart failed')
            conf=configure(path)
            url='http://'+conf.get('SOAR_BIND_HOST','127.0.0.1')+':'+conf.get('SOAR_PORT','19081')+'/health'
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url,timeout=5) as res:
                state=json.load(res)
            if res.status!=200 or state.get('status')!='up':raise RuntimeError('Bridge health is not up')
        except Exception:
            path.write_text(previous,encoding='utf-8');os.chmod(path,0o600)
            subprocess.run(['systemctl','restart','aegismesh-soar-bridge.service'],capture_output=True,timeout=40)
            raise
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return {'guard_enabled':True,'bridge_healthy':True,'isolation_not_automatically_enabled':True}


def reconciler(*, limit=2, now=None):
    """Automated READ-ONLY checks of short-lived SOAR blocks after TTL.

    Never installs/renews rules. A missing response remains unverified and is
    retried at bounded intervals; it is never mislabeled as removed.
    """
    now=now or dt.datetime.now(dt.timezone.utc)
    ensure_table()
    with bridge.dbconn() as db:
        rows=db.execute("SELECT id,tag,payload,action_status,updated_at FROM decisions "
                        "WHERE tag IN ('F2B_BAN_SERVER','WAZUH_BLOCK_AGENT','WINDOWS_BLOCK_IP') "
                        "AND action_status IN ('executed','dispatched_unverified') "
                        "ORDER BY updated_at DESC LIMIT 120").fetchall()
    checked=[]
    for row in rows:
        try:
            when=dt.datetime.fromisoformat(row['updated_at'].replace('Z','+00:00'))
            age=(now-when).total_seconds()
            if not 140 <= age <= 3600:continue
            records=audit(row['id'])
            if any(item['status']=='removed' for item in records):continue
            # The latest test is rate-limited, including pending/failed dispatch.
            if records:
                most=records[0]
                stamp=dt.datetime.fromisoformat(most['checked_at'].replace('Z','+00:00'))
                if (now-stamp).total_seconds()<120:continue
                if len(records)>=4:continue
            checked.append(verify(row['id'],wait=12))
            if len(checked)>=limit:break
        except (ValueError,RuntimeError,PermissionError,OSError) as exc:
            checked.append({'decision_id':row['id'],'status':'unknown',
                            'error_type':type(exc).__name__})
            if len(checked)>=limit:break
    return {'checks':checked,'action':'read_only_expiry_observation',
            'removed_status_requires_endpoint_or_local_firewall_proof':True}


def enable_timer(*, confirm):
    if not confirm:raise PermissionError('--confirm obligatoire')
    if os.geteuid()!=0:raise PermissionError('root requis')
    for name in ('aegismesh-soar-response-audit.service','aegismesh-soar-response-audit.timer'):
        src=ROOT/'ops/systemd'/name
        dst=Path('/etc/systemd/system')/name
        if dst.exists() and 'X-Aegismesh-Soar-Managed=yes' not in dst.read_text():
            raise PermissionError('Unité systemd non gérée déjà présente, refus de remplacement')
        dst.write_bytes(src.read_bytes())
        os.chmod(dst,0o644)
    for cmd in (['systemctl','daemon-reload'],['systemctl','enable','--now','aegismesh-soar-response-audit.timer']):
        p=subprocess.run(cmd,capture_output=True,timeout=15)
        if p.returncode:raise RuntimeError('Impossible de démarrer le timer de vérification')
    return {'timer':'aegismesh-soar-response-audit.timer','active':True,
            'no_firewall_change':True}

def main(argv=None):
    p=argparse.ArgumentParser(description='AEGISMESH-SOAR proof-based progressive response / containment observation')
    sub=p.add_subparsers(dest='action',required=True)
    v=sub.add_parser('verify-block',help='Sonde read-only de l état exact d un blocage via Wazuh ou Fail2ban')
    v.add_argument('--decision-id',required=True);v.add_argument('--confirm',action='store_true')
    c=sub.add_parser('check',help='Relire le résultat d une sonde déjà distribuée, sans action')
    c.add_argument('--check-id',required=True)
    a=sub.add_parser('audit',help='Historique PostgreSQL des sondes de confinement')
    a.add_argument('--decision-id')
    i=sub.add_parser('incident',help='Chronologie réelle enregistrée pour un incident (lecture seule)')
    i.add_argument('--incident-id',required=True)
    sub.add_parser('progressive-status',help='État du garde-fou progressif (lecture seule)')
    enable=sub.add_parser('enable-progressive',help='Renforcer le gate d isolement sans l activer')
    enable.add_argument('--confirm',action='store_true')
    rec=sub.add_parser('reconcile',help='Observer les TTL expirés, sans bloquer ni modifier un endpoint')
    rec.add_argument('--confirm',action='store_true')
    timer=sub.add_parser('enable-expiry-audit',help='Installer timer de vérification de retrait read-only')
    timer.add_argument('--confirm',action='store_true')
    args=p.parse_args(argv)
    try:
        if os.geteuid()!=0:raise PermissionError('root requis : secrets de Wazuh et historique PostgreSQL')
        configure()
        if args.action=='verify-block':
            if not args.confirm:raise PermissionError('--confirm requis : envoi d une sonde Wazuh read-only')
            result=verify(args.decision_id)
        elif args.action=='check':result=refresh(args.check_id)
        elif args.action=='audit':result=audit(args.decision_id)
        elif args.action=='incident':result=incident(args.incident_id)
        elif args.action=='progressive-status':result=progressive_status()
        elif args.action=='enable-progressive':result=enable_progressive(args.confirm)
        elif args.action=='reconcile':
            if not args.confirm:raise PermissionError('--confirm requis pour sonder les agents via Wazuh')
            result=reconciler()
        elif args.action=='enable-expiry-audit':result=enable_timer(confirm=args.confirm)
        print(json.dumps(result,ensure_ascii=False,indent=2,default=str))
        if args.action=='verify-block' and result['status'] not in ('blocked','removed'):
            print('PREUVE ABSENTE / INCERTAINE : ne pas inférer un blocage ou un retrait',file=sys.stderr)
            return 3
        return 0
    except (RuntimeError,ValueError,PermissionError,KeyError,OSError) as exc:
        print('AEGISMESH RESPONSE FAILED:',type(exc).__name__,str(exc)[:220],file=sys.stderr)
        return 2

if __name__=='__main__':sys.exit(main())
