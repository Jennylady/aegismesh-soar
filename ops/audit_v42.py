#!/usr/bin/env python3
"""AEGISMESH-SOAR V4.2: proof-first recovery and live validation.

Default is read-only. Tenzir network creation, a live OBSERVE workflow and
read-only Wazuh probes require separate --confirm. Never triggers blocking,
account changes, or EDR isolation. No secrets are printed.
"""
from __future__ import annotations
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
ENV=Path('/etc/aegismesh-soar/soar.env')
TENZIR_NET='tenzir-network'
TENZIR_NODE='tenzir-node'
TIMER_EDR='aegismesh-soar-edr-expiry.timer'
TIMER_RESP='aegismesh-soar-response-audit.timer'
TAGS=('F2B_BAN_SERVER','WAZUH_BLOCK_AGENT','WINDOWS_BLOCK_IP')


class AuditError(Exception):pass


def command(args, *, timeout=12):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise AuditError(f'{args[0]} indisponible ({type(e).__name__})') from e


def checked(args, *, timeout=12):
    p=command(args,timeout=timeout)
    if p.returncode:
        raise AuditError(f'{args[0]}: code={p.returncode}; {(p.stderr or p.stdout).strip()[:160]}')
    return p.stdout


def docker_object(kind,name):
    p=command(['docker',kind,'inspect',name],timeout=12)
    if p.returncode:return None
    try:
        rows=json.loads(p.stdout)
        return rows[0] if isinstance(rows,list) and len(rows)==1 else None
    except (ValueError,TypeError):return None


def tenzir_networks(node):
    """Inspect attachments, not just HostConfig.NetworkMode (often 'bridge')."""
    networks=((node.get('NetworkSettings') or {}).get('Networks') or {})
    return networks if isinstance(networks,dict) else {}


def tenzir_status():
    node=docker_object('container',TENZIR_NODE)
    network=docker_object('network',TENZIR_NET)
    if node is None:
        return {'state':'unknown','reason':'conteneur tenzir-node absent ou Docker inaccessible',
                'network_exists':network is not None}
    mode=str((node.get('HostConfig') or {}).get('NetworkMode',''))
    status=str((node.get('State') or {}).get('Status','unknown'))
    image=str((node.get('Config') or {}).get('Image',''))
    attached=tenzir_networks(node)
    references_missing=mode==TENZIR_NET or TENZIR_NET in attached
    result={'state':status,'network_exists':network is not None,
            'configured_network':mode,'attached_networks':sorted(attached),
            'stale_tenzir_network_reference':references_missing and network is None,
            'image_tenzir':('tenzir' in image.lower()),
            'network_binding_verified':network is not None and TENZIR_NET in attached}
    if references_missing and network is None:
        result['state']='broken_missing_network'
        result['reason']='tenzir-node conserve une référence à tenzir-network, absent de Docker'
    elif network is not None and status=='running':
        result['reason']='conteneur démarré; connectivité Tenzir et pipeline non prouvés'
    elif status!='running':
        result['reason']='conteneur pas en cours d exécution'
    else:
        result['reason']='contexte réseau particulier; contrôle des rattachements requis'
    return result


def repair_tenzir(*, confirm=False):
    if not confirm:raise AuditError('--confirm requis pour créer un réseau Docker')
    if os.name!='posix' or os.geteuid()!=0:raise AuditError('root Linux requis')
    node=docker_object('container',TENZIR_NODE)
    if not node:raise AuditError('tenzir-node introuvable, aucune création arbitraire')
    mode=str((node.get('HostConfig') or {}).get('NetworkMode',''))
    image=str((node.get('Config') or {}).get('Image',''))
    state=str((node.get('State') or {}).get('Status',''))
    attached=tenzir_networks(node)
    # Linux Docker can report NetworkMode=bridge even though the stale custom
    # attachment is recorded under NetworkSettings.Networks. Only accept this
    # case when it explicitly names tenzir-network, never assume from logs.
    if ((mode!=TENZIR_NET and not (mode=='bridge' and TENZIR_NET in attached))
            or 'tenzir' not in image.lower()
            or (node.get('Name') and node.get('Name')!='/'+TENZIR_NODE)):
        raise AuditError('Identité/image ou référence réseau Tenzir non confirmée: réparation refusée')
    if state not in ('created','exited','running'):
        raise AuditError('État Tenzir non pris en charge, refus de modifier Docker')
    # A previously published service must not become Internet-reachable as a
    # side effect of this operation. Abort on any wildcard bind.
    bindings=(node.get('HostConfig') or {}).get('PortBindings') or {}
    for hosts in bindings.values():
        for bind in hosts or []:
            host=str(bind.get('HostIp',''))
            try:
                exposed=not (ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_private)
            except ValueError:
                exposed=True
            if exposed:
                raise AuditError('Port Tenzir publié hors interfaces privées : réseau à reconstruire via sa stack propriétaire')
    net=docker_object('network',TENZIR_NET)
    created=False
    if net is None:
        checked(['docker','network','create','--driver','bridge',TENZIR_NET],timeout=20)
        created=True
        net=docker_object('network',TENZIR_NET)
    if not net or net.get('Driver')!='bridge' or net.get('Name')!=TENZIR_NET:
        raise AuditError('Réseau Docker inattendu après création : ne pas redémarrer Tenzir')
    if state!='running':
        # Don't force-disconnect or recreate an orphan container. Its stale
        # NetworkID may still refer to a deleted object even after name reuse.
        attempt=command(['docker','start',TENZIR_NODE],timeout=35)
        if attempt.returncode:
            raise AuditError('Réseau restauré mais démarrage Tenzir refusé par Docker; '
                'référence réseau/ID peut être obsolète. Arrêt sans suppression '
                'de conteneur ou volumes. Diagnostic: '+
                (attempt.stderr or attempt.stdout).strip()[:140])
    after=tenzir_status()
    return {'operation':'tenzir_network_recovery','network_created':created,
            'node_state':after['state'],'network_exists':after['network_exists'],
            'network_binding_verified':after['network_binding_verified'],
            'orborus_untouched':True,
            'note':'Démarrage Docker seul; contrôler API Tenzir et journaux Orborus avant validation'}


def env_config(path=ENV):
    cfg={}
    for line in path.read_text(encoding='utf-8').splitlines():
        if '=' not in line or line.lstrip().startswith('#'):continue
        k,v=line.split('=',1)
        cfg[k.strip()]=v.strip()
    return cfg


def local_base(cfg):
    host=cfg.get('SOAR_BIND_HOST','127.0.0.1')
    try:
        addr=ipaddress.ip_address(host)
        if not (addr.is_private or addr.is_loopback):raise ValueError()
    except ValueError as e:
        raise AuditError('SOAR_BIND_HOST doit être une adresse IP privée/loopback') from e
    port=int(cfg.get('SOAR_PORT','19081'))
    if port<1 or port>65535:raise AuditError('Port bridge invalide')
    return f'http://{host}:{port}'


def request_json(url, token, *, payload=None):
    method='POST' if payload is not None else 'GET'
    body=json.dumps(payload,separators=(',',':')).encode() if payload is not None else None
    req=urllib.request.Request(url, data=body, method=method,
        headers={'X-Aegismesh-Token':token,'Content-Type':'application/json'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req,timeout=6) as response:
        data=json.load(response)
        if not isinstance(data,dict):raise AuditError('Bridge JSON invalide')
        return response.status,data


def worker_names():
    p=command(['docker','ps','--format','{{.Names}}'],timeout=5)
    if p.returncode:return []
    return [n for n in p.stdout.splitlines() if re.search(r'worker|shuffle-exec',n,re.I)][:20]


def prove_worker(*, confirm=False, timeout=75, sleeper=time.sleep, clock=time.monotonic):
    if not confirm:raise AuditError('--confirm requis : soumission réelle OBSERVE à Shuffle')
    if os.name!='posix' or os.geteuid()!=0:raise AuditError('root Linux requis')
    if not 5<=timeout<=120:raise AuditError('timeout doit être entre 5 et 120 secondes')
    cfg=env_config()
    token=cfg.get('DECISION_TOKEN','')
    if not token or not cfg.get('SHUFFLE_WEBHOOK_URL'):
        raise AuditError('Token décision et webhook Shuffle requis')
    base=local_base(cfg)
    code,health=request_json(base+'/health',token)
    if code!=200 or health.get('status')!='up':raise AuditError('Bridge /health indisponible')
    ident='am-'+secrets.token_hex(12)
    payload={'decision_id':ident,'incident_id':'SOAR-WORKER-E2E-OBSERVE',
        'tag':'OBSERVE','approved':False,'confidence':0,'evidence_ids':[],
        'target':{},'origin':'soar_audit_v42',
        'expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5)).isoformat()}
    code,answer=request_json(base+'/v1/decisions',token,payload=payload)
    if code not in (200,202) or answer.get('decision_id')!=ident:
        raise AuditError('Bridge ne confirme pas la création de la décision OBSERVE')
    names=set(worker_names())
    end=clock()+timeout
    final={}
    while True:
        _,final=request_json(base+'/v1/decisions/'+ident,token)
        names.update(worker_names())
        status=final.get('action_status')
        if status in ('executed','denied','failed') or clock()>=end:break
        sleeper(min(2,max(0,end-clock())))
    detail=final.get('detail')
    try:detail=json.loads(detail) if isinstance(detail,str) else detail
    except ValueError:detail={}
    ok=(final.get('action_status')=='executed' and bool(final.get('execution_id')) and
        isinstance(detail,dict) and detail.get('effect')=='record_only' and detail.get('external_action') is False)
    return {'decision_id':ident,'observe_callback_verified':ok,
            'delivery':final.get('delivery'),'action_status':final.get('action_status'),
            'execution_id':final.get('execution_id'),
            'worker_container_seen':bool(names),'worker_names_seen':sorted(names),
            'no_security_action_requested':True,
            'warning':('Worker exact non attribuable avec certitude sans journaux Shuffle' if not names
                       else 'Observer les journaux du worker pour l associer au workflow')}


def timer_status():
    result={}
    for timer in (TIMER_EDR,TIMER_RESP):
        active=command(['systemctl','is-active',timer],timeout=5)
        enabled=command(['systemctl','is-enabled',timer],timeout=5)
        result[timer]={'active':active.returncode==0 and active.stdout.strip()=='active',
                       'enabled':enabled.returncode==0 and enabled.stdout.strip()=='enabled'}
    return result


def ensure_timers(*, confirm=False):
    if not confirm:raise AuditError('--confirm requis pour activer les timers SOAR')
    if os.name!='posix' or os.geteuid()!=0:raise AuditError('root Linux requis')
    before=timer_status()
    if not (before[TIMER_EDR]['active'] and before[TIMER_EDR]['enabled']):
        from ops import edr_velociraptor
        edr_velociraptor.install_timer()
    if not (before[TIMER_RESP]['active'] and before[TIMER_RESP]['enabled']):
        from ops import response_lifecycle_v40
        response_lifecycle_v40.enable_timer(confirm=True)
    after=timer_status()
    return {'before':before,'after':after,
            'effect':'timers_enabled_not_proof_of_endpoint_removal'}


def block_inventory(*, probe=False, confirm=False):
    """Read real decisions and local endpoint-proof records. Never create bans."""
    if probe and not confirm:raise AuditError('--confirm requis pour sondes Wazuh read-only')
    if os.name!='posix' or os.geteuid()!=0:raise AuditError('root Linux requis')
    from soar import bridge
    from ops import response_lifecycle_v40 as response
    cfg=env_config()
    bridge.ENV.clear();bridge.ENV.update(cfg)
    bridge.DB=cfg.get('SOAR_DB',str(bridge.DB))
    with bridge.dbconn() as db:
        decisions=db.execute("SELECT id,tag,action_status,updated_at FROM decisions "
            "WHERE tag IN ('F2B_BAN_SERVER','WAZUH_BLOCK_AGENT','WINDOWS_BLOCK_IP') "
            "ORDER BY updated_at DESC LIMIT 90").fetchall()
    by_tag={tag:[] for tag in TAGS}
    for item in decisions:
        tag=item['tag']
        if len(by_tag[tag])>=3:continue
        entry={'decision_id':item['id'],'action_status':item['action_status'],
               'last_action_at':item['updated_at'],'endpoint_proof':'not_verified',
               'proof_is_historical':True}
        try:
            # Query directly: response.audit() calls ensure_table(), which
            # can create a database table even when --probe is not requested.
            with bridge.dbconn() as db:
                try:
                    raw=db.execute('SELECT * FROM response_checks WHERE decision_id=? '
                                   'ORDER BY checked_at DESC LIMIT 4',(item['id'],)).fetchall()
                    proofs=[dict(x) for x in raw]
                except Exception as exc:
                    if 'response_checks' in str(exc):proofs=[]
                    else:raise
            # Only the newest eligible decision of each kind is probed.
            if probe and not by_tag[tag] and item['action_status'] in ('executed','dispatched_unverified'):
                check=response.verify(item['id'])
                entry['proof_is_historical']=False
                proofs=[check]+proofs
            if proofs:
                latest=proofs[0]
                entry['endpoint_proof']=latest.get('status','unknown')
                entry['proof_time']=latest.get('checked_at')
                entry['check_id']=latest.get('check_id')
        except (RuntimeError,ValueError,PermissionError,OSError) as exc:
            entry['endpoint_proof']='unknown'
            entry['error_type']=type(exc).__name__
        by_tag[tag].append(entry)
    return {'type':'real_decision_and_firewall_probe_evidence',
            'no_block_created':True,'actions':by_tag,
            'note':'Une preuve historique blocked/removed ne prouve pas l état présent; relancer --probe pour contrôle actuel'}


def edr_inventory():
    cfg=env_config()
    allow=[a for a in cfg.get('EDR_ISOLATION_AGENT_IDS','').split(',') if a.strip()]
    from ops import edr_velociraptor as edr
    leases=edr.read_json(edr.LEASES,{})
    return {'enabled':cfg.get('ENABLE_EDR_ISOLATION')=='true',
            'guard_enabled':cfg.get('ENABLE_PROGRESSIVE_GUARD')=='true',
            'allowed_agents':allow,'domain_controller_excluded':'006' not in allow,
            'lease_count':len(leases),'lease_agent_ids':list(leases),
            'network_effect_proved':False,
            'reason':'Le label Quarantine et le moniteur ne prouvent pas un filtrage au niveau du poste'}


def infrastructure_status():
    names=('shuffle-backend','shuffle-frontend','shuffle-opensearch','shuffle-orborus')
    result={}
    for name in names:
        obj=docker_object('container',name)
        if obj is None:
            result[name]={'state':'unknown_or_missing'}
            continue
        state=obj.get('State') or {}
        result[name]={'state':state.get('Status','unknown'),
            'health':(state.get('Health') or {}).get('Status','not_configured')}
    for unit in ('aegismesh-soar-bridge.service','wazuh-manager.service','fail2ban.service'):
        p=command(['systemctl','is-active',unit],timeout=5)
        result[unit]={'active':p.returncode==0 and p.stdout.strip()=='active'}
    try:
        cfg=env_config()
        _,health=request_json(local_base(cfg)+'/health','')
        result['bridge_http']={'healthy':health.get('status')=='up'}
    except (OSError,ValueError,AuditError,urllib.error.URLError) as exc:
        result['bridge_http']={'healthy':False,'error_type':type(exc).__name__}
    return result


def full_report():
    output={}
    for label,func in [('infrastructure',infrastructure_status),('tenzir',tenzir_status),('timers',timer_status),('edr',edr_inventory),
                       ('blocks',block_inventory)]:
        try:output[label]=func()
        except Exception as exc:output[label]={'state':'unknown','error_type':type(exc).__name__}
    try:
        from ops.tenzir_conflict_v422 import check_status
        output['pipeline_mode']=check_status()
    except Exception as exc:output['pipeline_mode']={'state':'unknown','error_type':type(exc).__name__}
    output['worker_e2e']={'state':'not_tested','command':'aegismesh-soar audit worker --confirm'}
    output['documentation']='Vérifications live requises avant de déclarer confinement/EDR opérationnels'
    return output


def main(argv=None):
    p=argparse.ArgumentParser(description='AEGISMESH-SOAR V4.2 / correction guidée, preuves réelles')
    sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('status',help='Bilan lecture seule (ne déclenche aucun workflow ni pare-feu)')
    t=sub.add_parser('tenzir',help='Inspecter ou réparer uniquement tenzir-network')
    t.add_argument('--repair',action='store_true');t.add_argument('--confirm',action='store_true')
    t.add_argument('--disable-pipelines',action='store_true',help='Suspendre uniquement les pipelines Tenzir dans Orborus via Compose, sauvegarde et rollback')
    t.add_argument('--pipeline-status',action='store_true',help='Afficher la configuration des pipelines Orborus sans modifier de service')
    w=sub.add_parser('worker',help='Exécution réelle OBSERVE sans blocage; vérification callback')
    w.add_argument('--confirm',action='store_true');w.add_argument('--timeout',type=int,default=75)
    b=sub.add_parser('blocks',help='Preuves GCP/Linux/Windows (sondes à lecture seule facultatives)')
    b.add_argument('--probe',action='store_true');b.add_argument('--confirm',action='store_true')
    s=sub.add_parser('timers',help='Vérifier ou activer les timers SOAR uniquement')
    s.add_argument('--ensure',action='store_true');s.add_argument('--confirm',action='store_true')
    sub.add_parser('edr',help='État quarantaine sans déclencher isolation')
    a=p.parse_args(argv)
    try:
        if a.action=='status':output=full_report()
        elif a.action=='tenzir':
            if sum((a.repair,a.disable_pipelines,a.pipeline_status))>1:
                raise AuditError('Choisir une seule opération Tenzir')
            if a.disable_pipelines:
                from ops.tenzir_conflict_v422 import disable_pipelines
                output=disable_pipelines(confirm=a.confirm)
            elif a.pipeline_status:
                from ops.tenzir_conflict_v422 import check_status
                output=check_status()
            else:output=repair_tenzir(confirm=a.confirm) if a.repair else tenzir_status()
        elif a.action=='worker':output=prove_worker(confirm=a.confirm,timeout=a.timeout)
        elif a.action=='blocks':output=block_inventory(probe=a.probe,confirm=a.confirm)
        elif a.action=='timers':output=ensure_timers(confirm=a.confirm) if a.ensure else timer_status()
        else:output=edr_inventory()
        print(json.dumps(output,indent=2,ensure_ascii=False,default=str))
        if a.action=='worker' and not output['observe_callback_verified']:
            return 3
        if a.action=='tenzir' and a.repair and (output['node_state']!='running' or not output['network_binding_verified']):
            return 3
        if a.action=='timers' and a.ensure and not all(x['active'] for x in output['after'].values()):
            return 3
        return 0
    except (AuditError,ValueError,KeyError,OSError,RuntimeError,urllib.error.URLError) as exc:
        print('AEGISMESH AUDIT:',type(exc).__name__,str(exc)[:220],file=sys.stderr)
        return 2

if __name__=='__main__':sys.exit(main())
