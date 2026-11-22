#!/usr/bin/env python3
"""Readiness / explicit AD feature gate on existing GCP SOAR.

The command never disables an AD account itself: only a validated incident
via bridge -> Shuffle callback -> Wazuh agent 006 may execute that action.
"""
import argparse
import datetime as dt
import os
import subprocess
import urllib.request
import json
import secrets
import time
from pathlib import Path
import re
import sys
import socket
import urllib.parse
import ipaddress

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'soar'))
import bridge

CONFIG = Path('/etc/aegismesh-soar/soar.env')
RULES = Path('/var/ossec/etc/rules/aegismesh-soar-evidence.xml')
PROBE_STATE = Path('/var/lib/aegismesh-soar/ad-readiness.json')


def read_cfg(path=CONFIG):
    if not path.is_file():
        raise RuntimeError('SOAR private configuration missing (run on GCP)')
    vals={}
    for line in path.read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            k, v = line.split('=',1)
            vals[k.strip()] = v.strip().strip('"')
    return vals


def status(path=CONFIG, rules_path=RULES):
    cfg=read_cfg(path)
    bridge.ENV.clear();bridge.ENV.update(cfg)
    bridge.DB=cfg.get('SOAR_DB','/var/lib/aegismesh-soar/decisions.sqlite3')
    print('AD/LDAP SOAR — read-only readiness')
    print('Feature enabled:',cfg.get('ENABLE_AD_REMEDIATION') == 'true')
    print('Production enabled:',cfg.get('ENABLE_PROD_ACTIONS') == 'true')
    print('DC Wazuh ID:',cfg.get('AD_DC_AGENT_ID') or 'not configured (probe defaults to 006)')
    print('AD DNS domain:',cfg.get('AD_DOMAIN_DNS') or 'not configured')
    allowed={x.strip() for x in cfg.get('WAZUH_WINDOWS_DC_AGENT_IDS','').split(',') if x.strip()}
    print('Probe candidate 006 allowlisted:', '006' in allowed)
    print('Configured DC in Wazuh allowlist:', (cfg.get('AD_DC_AGENT_ID') in allowed) if cfg.get('AD_DC_AGENT_ID') else 'not yet configured')
    print('Evidence rules installed:',rules_path.is_file() and all(('id="'+r+'"') in rules_path.read_text() for r in ('119874','119875','119876')))
    print('Live DC readiness confirmed:', current_probe(cfg.get('AD_DC_AGENT_ID') or '006',cfg.get('AD_DOMAIN_DNS') or 'ad.ikom.mg'))
    print('Endpoint executor and opt-in group: VERIFY ON REAL WINDOWS DC with Test-AegisMeshAD.ps1')
    with bridge.dbconn() as conn:
        rows=conn.execute("SELECT id,action_status,updated_at,detail FROM decisions WHERE tag IN ('AD_DISABLE_ACCOUNT','AD_LAB_DISABLE') ORDER BY updated_at DESC LIMIT 10").fetchall()
    for row in rows:
        try:
            detail=json.loads(row['detail'] or '{}')
            verified=isinstance(detail,dict) and detail.get('account_disabled_verified') is True
        except (ValueError,TypeError):
            verified=False
        print(row['updated_at'],row['id'],row['action_status'],'dc_proof='+str(verified))
    print('Operator AD lab window:',cfg.get('AD_LAB_UNTIL') or 'disabled / expired')
    print('No remote action sent.')




def wazuh_api_endpoint(cfg):
    """Permit automatic recovery only for the existing loopback Wazuh endpoint."""
    parsed=urllib.parse.urlsplit(cfg.get('WAZUH_API_URL') or 'https://127.0.0.1:55000')
    if parsed.scheme != 'https' or parsed.hostname not in ('127.0.0.1', 'localhost', '::1') or (parsed.port or 443)!=55000:
        raise PermissionError('Automated Wazuh recovery requires local HTTPS API on port 55000')
    return ('::1' if parsed.hostname=='::1' else '127.0.0.1'), 55000


def wazuh_port_ready(cfg, *, connect=None):
    host,port=wazuh_api_endpoint(cfg)
    check=connect or socket.create_connection
    try:
        sock=check((host,port), 1.2)
        sock.close()
        return True
    except (OSError, TimeoutError):
        return False


def wait_wazuh_api(cfg, *, timeout=55, interval=2, connect=None, monotonic=None, sleeper=None):
    """Wait for socket readiness only; authentication/TLS is checked separately."""
    clock=monotonic or time.monotonic
    sleep=sleeper or time.sleep
    end=clock()+timeout
    while True:
        if wazuh_port_ready(cfg,connect=connect):
            return True
        if clock()>=end:
            return False
        sleep(min(interval,max(end-clock(),0)))


def wazuh_doctor(*, cfg=None, rules_path=RULES, runner=None, connect=None):
    """Only checks local Wazuh state, never restarts a service or sends AD actions."""
    cfg=read_cfg() if cfg is None else cfg
    run=runner or subprocess.run
    proc=run(['systemctl','is-active','wazuh-manager.service'],capture_output=True,text=True,timeout=8)
    active=proc.returncode==0 and proc.stdout.strip()=='active'
    print('Wazuh manager:', 'active' if active else 'inactive/failed')
    try:
        healthy=wazuh_port_ready(cfg,connect=connect)
        print('Wazuh API HTTPS loopback :55000:', 'LISTENING' if healthy else 'NOT LISTENING')
    except PermissionError as e:
        healthy=False
        print('Wazuh API configuration: '+str(e))
    hasrules=rules_path.is_file() and all(('id="'+r+'"') in rules_path.read_text() for r in ('119874','119875','119876'))
    print('AD proof rules installed:', hasrules)
    print('Agent 006 eligible for read-only probe:', '006' in {x.strip() for x in cfg.get('WAZUH_WINDOWS_DC_AGENT_IDS','').split(',')})
    if not healthy:
        print('Next: aegismesh-soar ad recover --confirm (one guarded manager restart)')
        print('Logs if still down: journalctl -u wazuh-manager -n 50 --no-pager; tail -n 50 /var/ossec/logs/api.log')
    else:
        print('Next: aegismesh-soar ad probe --confirm')
    print('No AD account modified; no remote action sent.')
    return active and healthy


def wazuh_recover(*, confirm, cfg=None, runner=None, connect=None, wait_fn=None, token_fn=None):
    """Explicit one-restart repair, never rewrites Wazuh config nor changes AD."""
    if not confirm:
        raise PermissionError('--confirm required for restarting Wazuh manager')
    if os.geteuid()!=0:
        raise PermissionError('root required for Wazuh service restart')
    cfg=read_cfg() if cfg is None else cfg
    bridge.ENV.clear(); bridge.ENV.update(cfg)
    if wazuh_port_ready(cfg,connect=connect):
        # An already listening API must not be restarted for auth/TLS/config mistakes.
        token=(token_fn or bridge.wazuh_auth_token)()
        if not token:
            raise RuntimeError('Wazuh authentication produced no token')
        print('Wazuh API already healthy and authenticated: no restart required')
        return True
    run=runner or subprocess.run
    test=run(['/var/ossec/bin/wazuh-analysisd','-t'],capture_output=True,text=True,timeout=35)
    if test.returncode:
        raise RuntimeError('Wazuh analysisd rules invalid; manager not restarted (see local Wazuh logs)')
    result=run(['systemctl','restart','wazuh-manager.service'],capture_output=True,text=True,timeout=100)
    if result.returncode:
        raise RuntimeError('Wazuh manager restart failed (see journalctl -u wazuh-manager)')
    ready=(wait_fn or wait_wazuh_api)(cfg,connect=connect)
    if not ready:
        raise RuntimeError('Wazuh manager restarted, but HTTPS API :55000 still unavailable; inspect /var/ossec/logs/api.log and journalctl')
    token=(token_fn or bridge.wazuh_auth_token)()
    if not token:
        raise RuntimeError('Wazuh HTTPS API reachable but returned no authentication token')
    print('Wazuh manager restarted once, API :55000 reachable and authenticated.')
    print('No AD account modified.')
    return True



def current_probe(agent, domain, *, state_path=PROBE_STATE, evidence_fn=None):
    if not state_path.is_file():
        return False
    try:
        data=json.loads(state_path.read_text())
        if data.get('agent')!=agent or data.get('domain')!=domain:
            return False
        issued=dt.datetime.fromisoformat(data['verified_at'])
        if issued.tzinfo is None or not dt.timedelta(0)<=dt.datetime.now(dt.timezone.utc)-issued<dt.timedelta(minutes=40):
            return False
        ident=data.get('probe_id','')
        if not bridge.RX_ID.fullmatch(ident):
            return False
        verify=evidence_fn or bridge.wazuh_evidence
        return bool(verify(agent,ident,'adready'))
    except (ValueError, TypeError, OSError,KeyError):
        return False


def write_probe(agent,domain,ident,*,state_path=PROBE_STATE):
    import os
    import tempfile
    state_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    content={'agent':agent,'domain':domain,'probe_id':ident,
             'verified_at':dt.datetime.now(dt.timezone.utc).isoformat()}
    fd,name=tempfile.mkstemp(prefix='.ad-ready-',dir=str(state_path.parent),text=True)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as out:
            json.dump(content,out)
        os.replace(name,state_path)
    finally:
        if os.path.exists(name): os.unlink(name)


def enable(args, *, config_path=CONFIG, rules_path=RULES, env_update=None, agent_lookup=None,
           probe_path=PROBE_STATE, evidence_fn=None):
    if not args.confirm:
        raise PermissionError('--confirm required to enable AD remediation')
    if not re.fullmatch(r'\d{3}',args.agent_id) or args.agent_id == '000':
        raise ValueError('real Wazuh DC agent ID required')
    if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',args.domain):
        raise ValueError('full AD DNS domain required')
    cfg=read_cfg(config_path)
    if cfg.get('ENABLE_PROD_ACTIONS') != 'true':
        raise PermissionError('Enable SOAR production actions first')
    allow={x.strip() for x in cfg.get('WAZUH_WINDOWS_DC_AGENT_IDS','').split(',')}
    if args.agent_id not in allow:
        raise PermissionError('DC is not already explicitly allowlisted in WAZUH_WINDOWS_DC_AGENT_IDS')
    if not rules_path.is_file() or not all(('id="'+r+'"') in rules_path.read_text() for r in ('119874','119875','119876')):
        raise PermissionError('Manager AD evidence rule absent: fleet evidence install --apply --confirm')
    bridge.ENV.clear();bridge.ENV.update(cfg)
    if not current_probe(args.agent_id,args.domain,state_path=probe_path,evidence_fn=evidence_fn):
        raise PermissionError('Real DC readiness not verified recently: run ad probe --confirm first')
    lookup=agent_lookup or (lambda agent: bridge.wazuh_agent_record(agent,bridge.wazuh_auth_token()))
    record=lookup(args.agent_id)
    if 'windows' not in str((record.get('os') or {}).get('name','')).lower():
        raise PermissionError('Wazuh agent does not report Windows')
    update=env_update
    if update is None:
        from importlib.machinery import SourceFileLoader
        mod=SourceFileLoader('soar_management',str(ROOT/'bin/aegismesh-soar')).load_module()
        update=mod.atomic_env
    changes={'ENABLE_AD_REMEDIATION':'true','AD_DC_AGENT_ID':args.agent_id,
             'AD_DOMAIN_DNS':args.domain}
    if env_update is None:
        apply_and_restart(changes, cfg)
    else:
        update(changes)
    print('AD remediation enabled for ONE DC; endpoint independent scope policy still applies.')
    print('Only real decision -> Shuffle -> Wazuh -> AD account verified can become executed.')


def apply_and_restart(changes, previous):
    if os.geteuid()!=0:
        raise PermissionError('root required to change AD SOAR policy')
    from importlib.machinery import SourceFileLoader
    mod=SourceFileLoader('soar_manager_ad', str(ROOT/'bin/aegismesh-soar')).load_module()
    mod.atomic_env(changes)
    try:
        restarted=subprocess.run(['systemctl','restart','aegismesh-soar-bridge.service'],
                                 capture_output=True,timeout=60)
        if restarted.returncode:
            raise RuntimeError('SOAR bridge restart failed')
        cfg=read_cfg()
        host=cfg.get('SOAR_BIND_HOST','127.0.0.1')
        port=int(cfg.get('SOAR_PORT','19081'))
        if host not in ('127.0.0.1','localhost','::1') and not re.fullmatch(r'[0-9.]+',host):
            raise RuntimeError('Unexpected bridge bind address')
        req=urllib.request.Request('http://'+host+':'+str(port)+'/health')
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=8) as response:
            data=json.load(response)
            if response.status!=200 or data.get('status')!='up':
                raise RuntimeError('SOAR bridge health check failed')
    except Exception:
        mod.atomic_env({key:previous.get(key,'false' if key.startswith('ENABLE_') else '') for key in changes})
        subprocess.run(['systemctl','restart','aegismesh-soar-bridge.service'],
                       capture_output=True,timeout=60,check=False)
        raise


def disable(*, env_update=None):
    if env_update is None:
        from importlib.machinery import SourceFileLoader
        mod=SourceFileLoader('soar_management',str(ROOT/'bin/aegismesh-soar')).load_module()
        env_update=mod.atomic_env
    if env_update is None:
        apply_and_restart({'ENABLE_AD_REMEDIATION':'false'}, read_cfg())
    else:
        env_update({'ENABLE_AD_REMEDIATION':'false'})
    print('AD remediation disabled. No AD user account changed.')



def probe(*, agent='006', domain='ad.ikom.mg', wait=14, token_fn=None, request_fn=None, evidence_fn=None,
          state_path=PROBE_STATE, agent_lookup=None, config_path=CONFIG):
    """Real Wazuh AR read-only probe, no fabricated incident or AD modification."""
    if not re.fullmatch(r'\d{3}',agent) or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',domain):
        raise ValueError('DC agent or AD domain invalid')
    cfg=read_cfg(config_path)
    if agent not in cfg.get('WAZUH_WINDOWS_DC_AGENT_IDS','').split(','):
        raise PermissionError('DC Wazuh agent is not registered')
    bridge.ENV.clear();bridge.ENV.update(cfg)
    if token_fn is None and not wait_wazuh_api(cfg,timeout=55):
        raise ConnectionError('Wazuh API :55000 unavailable after readiness wait; run aegismesh-soar ad doctor then ad recover --confirm')
    ident='am-'+secrets.token_hex(12)
    jwt=(token_fn or bridge.wazuh_auth_token)()
    remote=(agent_lookup or bridge.wazuh_agent_record)(agent,jwt)
    if 'windows' not in str((remote.get('os') or {}).get('name','')).lower():
        raise PermissionError('AD readiness target is not Windows')
    body={'command':'!aegismesh-soar-ad.cmd','arguments':[],
          'alert':{'data':{'action':'check_ready','decision_id':ident,'domain_dns':domain}}}
    response=(request_fn or bridge.wazuh_api_request)(
        'PUT','/active-response?agents_list='+agent, body,
        {'Authorization':'Bearer '+jwt,'Content-Type':'application/json'})
    if response.get('error') or int((response.get('data') or {}).get('total_affected_items',0))!=1:
        raise RuntimeError('Wazuh API did not acknowledge AD read-only check')
    check=evidence_fn or bridge.wazuh_evidence
    deadline=time.monotonic()+min(max(int(wait),0),25)
    while True:
        proof=check(agent,ident,'adready')
        if proof:
            write_probe(agent,domain,ident,state_path=state_path)
            print('AD readiness: VERIFIED by agent '+agent+' via Wazuh manager')
            print('Probe ID:',ident)
            print('No account has been modified.')
            return 0
        if time.monotonic()>=deadline:
            print('AD readiness: DISPATCHED_UNVERIFIED (Wazuh API ACK only)')
            print('Probe ID:',ident)
            print('Inspect Windows AD evidence log, the manager collector, and AR errors.')
            return 3
        time.sleep(.75)



def _local_ipv4_interface_addresses(*, runner=None):
    """Find IPv4 interface addresses on this host; never trust DNS as proof of locality."""
    run=runner or subprocess.run
    try:
        proc=run(['ip','-j','address','show'],capture_output=True,text=True,timeout=6)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Impossible de lire les interfaces locales avec ip -j address show') from None
    if proc.returncode:
        raise RuntimeError('Interfaces locales illisibles : ip -j address show a échoué')
    try:
        items=json.loads(proc.stdout)
        return {entry['local'] for interface in items
                for entry in interface.get('addr_info',[])
                if entry.get('family')=='inet' and isinstance(entry.get('local'),str)}
    except (ValueError, TypeError, KeyError):
        raise RuntimeError('Impossible de vérifier les adresses IPv4 locales') from None


def local_bridge_endpoint(cfg, *, addresses_fn=None):
    """Select an authenticated HTTP endpoint on the SAME server as the SOAR CLI.

    The bridge may bind to a Docker gateway (e.g. 192.168.96.1) so the
    Shuffle container can call back. Connecting to that LOCAL address is fine;
    connecting to an arbitrary address from configuration is not.
    """
    raw_host=cfg.get('SOAR_BIND_HOST','127.0.0.1').strip()
    raw_port=str(cfg.get('SOAR_PORT','19081'))
    try:
        port=int(raw_port)
    except (ValueError,TypeError):
        raise ValueError('SOAR_PORT doit être un entier') from None
    if not 1<=port<=65535 or str(port)!=raw_port:
        raise ValueError('SOAR_PORT non valide')
    if raw_host in ('localhost','::1','[::1]'):
        host='127.0.0.1' if raw_host=='localhost' else '[::1]'
    else:
        try:
            addr=ipaddress.ip_address(raw_host)
        except ValueError:
            raise PermissionError('Bridge: nom DNS ou adresse ambiguë refusé pour le test AD') from None
        if addr.version != 4:
            raise PermissionError('Bridge: seule une IPv4 locale ou ::1 est autorisée')
        if addr.is_unspecified:
            host='127.0.0.1'  # wildcard bind accepts loopback, never dial 0.0.0.0
        elif addr.is_loopback:
            host=raw_host
        else:
            local=(addresses_fn or _local_ipv4_interface_addresses)()
            if raw_host not in local:
                raise PermissionError('Bridge non-local : adresse non attribuée à une interface GCP, appel refusé')
            host=raw_host
    return 'http://'+host+':'+str(port)


def ensure_local_bridge_health(endpoint, *, opener=None):
    """Preflight before opening any AD lab window or submitting decisions."""
    open_client=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req=urllib.request.Request(endpoint+'/health',headers={'Accept':'application/json'})
    with open_client.open(req,timeout=5) as response:
        data=json.load(response)
        if (response.status!=200 or data.get('service')!='aegismesh-soar-bridge'
                or data.get('status')!='up'):
            raise RuntimeError('Bridge local : /health ne confirme pas le service SOAR')
    return True


def lab_disable(*, sid, confirm, config_path=CONFIG, proof_path=PROBE_STATE):
    """Real full Shuffle/Wazuh/AD demonstration, explicitly NOT an AI finding."""
    if not confirm: raise PermissionError('--confirm requis')
    if not bridge.RX_AD_SID.fullmatch(sid):
        raise ValueError('SID AD Windows valide requis')
    cfg=read_cfg(config_path)
    agent=cfg.get('AD_DC_AGENT_ID')
    domain=cfg.get('AD_DOMAIN_DNS')
    if not (cfg.get('ENABLE_AD_REMEDIATION')=='true' and cfg.get('ENABLE_PROD_ACTIONS')=='true'
            and agent in cfg.get('WAZUH_WINDOWS_DC_AGENT_IDS','').split(',')):
        raise PermissionError('AD remediation real enable requis avant le test opérateur')
    bridge.ENV.clear();bridge.ENV.update(cfg)
    if not current_probe(agent,domain,state_path=proof_path):
        raise PermissionError('Readiness DC non confirmée depuis moins de 40 minutes')
    # Validate the exact local interface and HTTP health BEFORE opening
    # the temporary lab window. A Docker gateway is local even when it is
    # not in 127.0.0.0/8. External addresses remain forbidden.
    endpoint=local_bridge_endpoint(cfg)
    if not cfg.get('DECISION_TOKEN'):
        raise PermissionError('Jeton de décision SOAR absent')
    ensure_local_bridge_health(endpoint)
    until=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=10)).isoformat()
    apply_and_restart({'AD_LAB_UNTIL':until},cfg)
    decision_id='am-'+secrets.token_hex(12)
    incident_id='AD-LAB-'+secrets.token_hex(12)
    event={'decision_id':decision_id,'incident_id':incident_id,
           'tag':'AD_LAB_DISABLE','origin':'operator_lab',
           'confidence':0,'evidence_ids':[],'approved':True,
           'target':{'agent_id':agent,'user_sid':sid,'domain_dns':domain},
           'expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=3)).isoformat()}
    req=urllib.request.Request(endpoint+'/v1/decisions',
        data=json.dumps(event).encode('utf-8'),method='POST',
        headers={'X-Aegismesh-Token':cfg['DECISION_TOKEN'],'Content-Type':'application/json'})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=8) as response:
        reply=json.load(response)
        if response.status!=202 or reply.get('decision_id')!=decision_id:
            raise RuntimeError('Bridge did not accept lab decision')
    print('TEST AD REEL soumis au bridge → Shuffle → Wazuh agent '+agent)
    print('Decision:',decision_id)
    print('Origine: operator_lab (aucun score IA ni evenement Wazuh invente)')
    print('Attendre la preuve ADACCOUNT de Wazuh avant de conclure a la desactivation.')


def main():
    parser=argparse.ArgumentParser(description='SOAR AD: no fabricated incidents, one-time DC feature gate')
    actions=parser.add_subparsers(dest='action',required=True)
    actions.add_parser('status')
    actions.add_parser('doctor',help='Read-only Wazuh API and AD readiness diagnosis')
    rr=actions.add_parser('recover',help='Explicit one-time Wazuh manager API recovery')
    rr.add_argument('--confirm',action='store_true')
    a=actions.add_parser('enable')
    a.add_argument('--agent-id',default='006')
    a.add_argument('--domain',default='ad.ikom.mg')
    a.add_argument('--confirm',action='store_true')
    pr=actions.add_parser('probe',help='Execute a real, read-only Wazuh AR check on the DC')
    pr.add_argument('--agent-id',default='006')
    pr.add_argument('--domain',default='ad.ikom.mg')
    pr.add_argument('--confirm',action='store_true')
    l=actions.add_parser('lab-disable',help='Real explicitly operator-authorized AD lab test through Shuffle')
    l.add_argument('--sid',required=True)
    l.add_argument('--confirm',action='store_true')
    d=actions.add_parser('disable')
    d.add_argument('--confirm',action='store_true')
    args=parser.parse_args()
    if args.action=='status':
        cfg=read_cfg()
        bridge.DB=cfg.get('SOAR_DB','/var/lib/aegismesh-soar/decisions.sqlite3')
        status()
    elif args.action=='doctor':
        wazuh_doctor()
    elif args.action=='recover':
        wazuh_recover(confirm=args.confirm)
    elif args.action=='probe':
        if not args.confirm: raise PermissionError('Explicit --confirm required for remote readiness probe')
        return probe(agent=args.agent_id, domain=args.domain)
    elif args.action=='enable':
        enable(args)
    elif args.action=='lab-disable':
        lab_disable(sid=args.sid,confirm=args.confirm)
    elif args.action=='disable':
        if not args.confirm: raise PermissionError('--confirm required')
        disable()
    return 0

if __name__=='__main__':
    try:
        sys.exit(main())
    except (RuntimeError,ValueError,PermissionError,ConnectionError) as exc:
        print('AD SOAR FAILED:',type(exc).__name__,str(exc)[:180],file=sys.stderr)
        sys.exit(2)
