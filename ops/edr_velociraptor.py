#!/usr/bin/env python3
"""AEGISMESH SOAR / Velociraptor, scoped API adapter.

No server installation, no arbitrary VQL from the network or the CLI.
The server's existing, mTLS-authenticated API is used by its own CLI only.
Quarantine is label-driven and NOT evidence of an applied network firewall.
"""
import argparse
import hashlib
import datetime as dt
try:
    import fcntl
except ImportError:
    fcntl = None  # Runtime operations are only supported on the GCP Linux host
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
CONF = Path('/etc/aegismesh-soar/velociraptor.json')
MAPPING = Path('/var/lib/aegismesh-soar/edr-agent-map.json')
LEASES = Path('/var/lib/aegismesh-soar/edr-quarantine-leases.json')
LOCK = Path('/var/lib/aegismesh-soar/edr-lease.lock')
FLOW_RECORDS = Path('/var/lib/aegismesh-soar/edr-flow-tracker.json')
LINK_ATTESTATIONS = Path('/var/lib/aegismesh-soar/edr-link-attestations.json')
ENV = Path('/etc/aegismesh-soar/soar.env')
RX_CLIENT = re.compile(r'C\.[0-9a-fA-F]{8,64}\Z')
RX_AGENT = re.compile(r'\d{3}\Z')
RX_FLOW = re.compile(r'F\.[A-Za-z0-9]{6,64}\Z')
EXPIRY_TIMER = 'aegismesh-soar-edr-expiry.timer'
SAFE_ARTIFACT = 'Generic.Client.Info'
READ_CLIENTS = 'SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, labels FROM clients() LIMIT 200'
READ_LABEL = 'SELECT client_id, labels FROM clients(client_id=ClientId)'
COLLECT = "SELECT collect_client(client_id=ClientId, artifacts='Generic.Client.Info', env=dict()) AS collection FROM scope()"
COLLECT_WIN_TRIAGE = "SELECT collect_client(client_id=ClientId, artifacts=['Windows.System.Pslist', 'Windows.Network.Netstat'], env=dict()) AS collection FROM scope()"
COLLECT_LINUX_TRIAGE = "SELECT collect_client(client_id=ClientId, artifacts=['Linux.Sys.Pslist', 'Linux.Network.Netstat'], env=dict()) AS collection FROM scope()"
READ_MONITORING = 'SELECT get_client_monitoring() AS monitoring FROM scope() LIMIT 1'
READ_FLOWS = 'SELECT * FROM flows(client_id=ClientId) LIMIT 50'
READ_FLOW = 'SELECT * FROM flows(client_id=ClientId, flow_id=FlowId) LIMIT 2'
READ_FLOW_DETAILS = 'SELECT get_flow(client_id=ClientId, flow_id=FlowId) AS details FROM scope() LIMIT 1'
READ_FLOW_RESULTS = "SELECT * FROM flow_results(client_id=ClientId, flow_id=FlowId, artifact='Generic.Client.Info/BasicInformation') LIMIT 20"
TRIAGE_RESULT_QUERIES = {
    'Windows.System.Pslist': "SELECT * FROM flow_results(client_id=ClientId, flow_id=FlowId, artifact='Windows.System.Pslist') LIMIT 20",
    'Windows.Network.Netstat': "SELECT * FROM flow_results(client_id=ClientId, flow_id=FlowId, artifact='Windows.Network.Netstat') LIMIT 20",
    'Linux.Sys.Pslist': "SELECT * FROM flow_results(client_id=ClientId, flow_id=FlowId, artifact='Linux.Sys.Pslist') LIMIT 20",
    'Linux.Network.Netstat': "SELECT * FROM flow_results(client_id=ClientId, flow_id=FlowId, artifact='Linux.Network.Netstat') LIMIT 20",
}
SET_QUARANTINE = "SELECT label(client_id=ClientId, labels=['Quarantine'], op='set') AS result FROM scope()"
REMOVE_QUARANTINE = "SELECT label(client_id=ClientId, labels=['Quarantine'], op='remove') AS result FROM scope()"


def read_json(path, default):
    if not path.is_file(): return default
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, type(default)):
        raise ValueError('Mauvais format de configuration privée EDR')
    return value


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.resolve() not in (Path('/etc/aegismesh-soar'),Path('/var/lib/aegismesh-soar')):
        raise PermissionError('Destination de configuration privée non autorisée')
    os.chmod(path.parent, 0o700)
    fd, name = tempfile.mkstemp(prefix='.edr-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            os.fchmod(out.fileno(), 0o600)
            json.dump(data, out, ensure_ascii=False, indent=2, sort_keys=True)
            out.write('\n');out.flush();os.fsync(out.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)


def require_root():
    # GCP Linux only. Windows Python has no os.geteuid(); refuse cleanly
    # instead of throwing AttributeError. Offline tests mock this guard.
    get_euid = getattr(os, 'geteuid', None)
    if os.name != 'posix' or not callable(get_euid) or get_euid() != 0:
        raise PermissionError('root Linux requis sur GCP pour secrets et contrôles EDR')


def read_env():
    vals={}
    if ENV.is_file():
        for line in ENV.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                k,v=line.split('=',1); vals[k.strip()]=v.strip().strip('"')
    return vals


def validate_config(c):
    if c.get('mode') not in ('host','docker'): raise ValueError('mode doit être host ou docker')
    api = c.get('api_config','')
    if not api.startswith('/') or '..' in Path(api).parts or '\n' in api:
        raise ValueError('Chemin API mTLS absolu obligatoire')
    binary=c.get('binary','velociraptor')
    if not re.fullmatch(r'[A-Za-z0-9_./-]{1,120}',binary) or '..' in binary:
        raise ValueError('Binaire EDR invalide')
    if c['mode']=='docker' and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}',c.get('container','')):
        raise ValueError('Nom de conteneur Docker invalide')
    if c['mode']=='host' and not Path(api).is_file():
        raise FileNotFoundError('Configuration API mTLS absente sur l’hôte')
    return c


def client_rows(output):
    result=[]
    for line in output.splitlines():
        try:
            obj=json.loads(line)
        except (TypeError,ValueError):
            continue
        if isinstance(obj,list): result.extend(x for x in obj if isinstance(x,dict))
        elif isinstance(obj,dict): result.append(obj)
    return result


def api_query(query, env=None, *, cfg=None):
    """Only call sites supply constant VQL; user values are sent via --env."""
    if query not in (READ_CLIENTS,READ_LABEL,COLLECT,COLLECT_WIN_TRIAGE,COLLECT_LINUX_TRIAGE,READ_MONITORING,READ_FLOWS,READ_FLOW,READ_FLOW_DETAILS,READ_FLOW_RESULTS,*TRIAGE_RESULT_QUERIES.values(),SET_QUARANTINE,REMOVE_QUARANTINE,'SELECT * FROM info() LIMIT 1'):
        raise PermissionError('VQL arbitraire refusé')
    if cfg is None and not CONF.is_file():
        raise RuntimeError('API Velociraptor non configurée : edr doctor, puis edr setup --confirm ou edr bootstrap --confirm --allow-restart')
    cfg=validate_config(cfg if cfg is not None else read_json(CONF, {}))
    command=[cfg.get('binary','velociraptor'),'--api_config',cfg['api_config'],'query',query,'--format','jsonl']
    for k,v in (env or {}).items():
        if not ((k=='ClientId' and RX_CLIENT.fullmatch(str(v))) or (k=='FlowId' and RX_FLOW.fullmatch(str(v)))):
            raise ValueError('Variable VQL non autorisée')
        command.extend(['--env',f'{k}={v}'])
    # The dedicated API certificate is root-owned (0600) inside the persisted Docker volume.
    if cfg['mode']=='docker': command=['docker','exec','--user','0',cfg['container']]+command
    try:
        run=subprocess.run(command,capture_output=True,text=True,timeout=20)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RuntimeError('API Velociraptor non joignable : '+type(exc).__name__) from None
    if run.returncode:
        # Do not expose cert/key paths or arbitrary stderr with credentials.
        raise RuntimeError('Échec API Velociraptor mTLS / droits / binaire (code '+str(run.returncode)+')')
    return client_rows(run.stdout)


def discovered():
    try:
        p=subprocess.run(['docker','ps','--format','{{.Names}}'],capture_output=True,text=True,timeout=5)
        names=[x for x in p.stdout.splitlines() if 'velociraptor' in x.lower()] if p.returncode==0 else []
    except (OSError,subprocess.TimeoutExpired): names=[]
    return names


def api_clients():
    rows=api_query(READ_CLIENTS)
    return [r for r in rows if RX_CLIENT.fullmatch(str(r.get('client_id','')))]


def valid_client(client_id):
    if not RX_CLIENT.fullmatch(str(client_id)):
        raise ValueError('Velociraptor client_id doit être C.<identifiant hexadécimal>')
    matches=[r for r in api_clients() if r.get('client_id')==client_id]
    if len(matches)!=1: raise ValueError('Client Velociraptor absent ou ambigu')
    return matches[0]


def wazuh_agents():
    sys.path.insert(0,str(ROOT/'soar'))
    import bridge
    bridge.ENV.clear(); bridge.ENV.update(read_env())
    token=bridge.wazuh_auth_token()
    response=bridge.wazuh_api_request('GET','/agents?limit=500',None,{'Authorization':'Bearer '+token})
    return response.get('data',{}).get('affected_items',[])


def linked(agent):
    if not RX_AGENT.fullmatch(str(agent)) or agent=='000': raise ValueError('ID Wazuh invalide')
    m=read_json(MAPPING,{})
    cid=m.get(agent)
    if not cid: raise ValueError('Agent Wazuh sans correspondance Velociraptor : edr link-auto')
    return str(cid)


def client_os(record):
    return str(record.get('os','')).lower()


def auto_link():
    clients=api_clients()
    wazuh=wazuh_agents()
    mapping=read_json(MAPPING,{})
    updated=[]; unmatched=[]
    for item in wazuh:
        aid=str(item.get('id',''))
        if not RX_AGENT.fullmatch(aid) or aid=='000': continue
        name=str(item.get('name','')).lower().split('.')[0]
        found=[x for x in clients if str(x.get('hostname','')).lower().split('.')[0]==name]
        if len(found)==1 and found[0]['client_id'] not in [v for k,v in mapping.items() if k!=aid]:
            mapping[aid]=found[0]['client_id']; updated.append((aid,found[0]['client_id']))
        else: unmatched.append((aid,name,len(found)))
    if updated: atomic_json(MAPPING,mapping)
    return updated,unmatched



def attest_link(agent, *, confirm):
    """Persist a short-lived, explicit identity attestation for renamed hosts.

    Linking is not equivalent to an authentication proof. A fresh Wazuh active
    record and an existing Velociraptor mTLS client are both required. It only
    permits the *already stored* one-to-one ID mapping; no new link is created.
    """
    require_root()
    if not confirm: raise PermissionError('--confirm obligatoire pour l attestation des hôtes')
    cid=linked(agent)
    client=valid_client(cid)
    wazuh=next((x for x in wazuh_agents() if str(x.get('id'))==agent),None)
    if not wazuh or wazuh.get('status')!='active':
        raise PermissionError('Agent Wazuh non connecté : attestation impossible')
    wazuh_os=' '.join(str(v) for v in (wazuh.get('os') or {}).values()).lower()
    if ('windows' in wazuh_os)!=('windows' in client_os(client)):
        raise PermissionError('Famille OS différente : attestation interdite')
    if not str(client.get('hostname','')).strip() or not str(wazuh.get('name','')).strip():
        raise PermissionError('Hôtes sans noms vérifiables')
    until=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=2)).isoformat()
    rows=read_json(LINK_ATTESTATIONS,{})
    rows[agent]={'client_id':cid,'wazuh_name':str(wazuh.get('name','')),
                 'edr_hostname':str(client.get('hostname','')),'expires_at':until}
    atomic_json(LINK_ATTESTATIONS,rows)
    return {'agent_id':agent,'wazuh_name':str(wazuh.get('name','')),
            'edr_client_id':cid,'edr_hostname':str(client.get('hostname','')),
            'expires_at':until,'mapping_explicitly_attested':True,
            'isolation_effect_verified':False}


def identity_corresponds(agent, client, wazuh):
    wname=str(wazuh.get('name','')).lower().split('.')[0]
    cname=str(client.get('hostname','')).lower().split('.')[0]
    if wname and wname==cname:return True
    cid=str(client.get('client_id',''))
    if not RX_CLIENT.fullmatch(cid):return False
    record=read_json(LINK_ATTESTATIONS,{}).get(agent,{})
    try:
        expires=dt.datetime.fromisoformat(record['expires_at'])
    except (KeyError,TypeError,ValueError):return False
    return bool(expires.tzinfo and expires>dt.datetime.now(dt.timezone.utc) and
                record.get('client_id')==cid and
                str(record.get('wazuh_name','')).casefold()==str(wazuh.get('name','')).casefold() and
                str(record.get('edr_hostname','')).casefold()==str(client.get('hostname','')).casefold())

def labels_for(cid):
    rows=api_query(READ_LABEL, {'ClientId':cid})
    if len(rows)!=1 or rows[0].get('client_id') !=cid:
        raise RuntimeError('Impossible de confirmer état de client Velociraptor')
    return rows[0].get('labels') or []


def check_allowed(agent):
    if not RX_AGENT.fullmatch(str(agent)) or agent=='000':
        raise PermissionError('Agent Wazuh non autorisé')
    env=read_env()
    dc={x.strip() for x in env.get('WAZUH_WINDOWS_DC_AGENT_IDS','').split(',') if x.strip()}
    if agent in dc or agent=='006':
        raise PermissionError('Quarantaine générale du contrôleur de domaine interdite')
    allow={x.strip() for x in env.get('EDR_ISOLATION_AGENT_IDS','').split(',') if x.strip()}
    if agent not in allow:
        raise PermissionError('Agent non autorisé en quarantaine EDR')
    if env.get('ENABLE_PROD_ACTIONS') !='true' or env.get('ENABLE_EDR_ISOLATION')!='true':
        raise PermissionError('Production ou isolement EDR désactivé')
    if not timer_active(): raise PermissionError('Timer de retrait EDR inactif : refus de quarantaine persistante')
    for r in wazuh_agents():
        if str(r.get('id',''))==agent:
            if r.get('status')!='active': raise PermissionError('Agent Wazuh non connecté')
            return r
    raise PermissionError('Agent Wazuh inconnu')


def timer_active():
    try:
        p=subprocess.run(['systemctl','is-active',EXPIRY_TIMER],capture_output=True,text=True,timeout=4)
        return p.returncode==0 and p.stdout.strip()=='active'
    except (OSError,subprocess.TimeoutExpired):return False


def modify_label(cid, op):
    if op not in ('set','remove'): raise ValueError('Opération interdite')
    query=SET_QUARANTINE if op=='set' else REMOVE_QUARANTINE
    rows=api_query(query,{'ClientId':cid})
    if not rows: raise RuntimeError('API Velociraptor n’a pas confirmé la commande de label')
    current=labels_for(cid)
    if ('Quarantine' in current)!=(op=='set'):
        raise RuntimeError('État de label Quarantine incohérent après opération')
    return current


def lease_lock():
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    fd=open(LOCK,'a+',encoding='utf-8')
    os.chmod(LOCK,0o600)
    if fcntl is None:
        fd.close()
        raise OSError('Verrou de quarantaine disponible uniquement sous Linux')
    fcntl.flock(fd,fcntl.LOCK_EX)
    return fd


def request_quarantine(agent, decision_id, *, ttl=300):
    require_root()
    if agent=='000' or not RX_AGENT.fullmatch(agent):raise ValueError('ID agent Wazuh invalide')
    if not re.fullmatch(r'am-[0-9a-f]{24}',decision_id):raise ValueError('decision_id non autorisé')
    if ttl != 300:raise ValueError('Durée de quarantaine limitée à 300 secondes')
    wazuh=check_allowed(agent)
    cid=linked(agent)
    client=valid_client(cid)
    if not identity_corresponds(agent,client,wazuh):
        raise PermissionError('Correspondance Wazuh / EDR non attestée : quarantaine refusée')
    wazuh_os=' '.join(str(v) for v in (wazuh.get('os') or {}).values()).lower()
    if ('windows' in wazuh_os) != ('windows' in client_os(client)):
        raise PermissionError('Famille OS différente entre Wazuh et Velociraptor')
    if 'windows' not in client_os(client) and 'linux' not in client_os(client):
        raise PermissionError('Velociraptor : OS non pris en charge')
    # Never place a label that might be inert: a server-side quarantine
    # monitoring assignment must be visible first. This STILL does not prove
    # that network policy was applied on the endpoint.
    monitor=quarantine_monitoring_status(agent)
    if not monitor['artifact_referenced_by_server_monitoring']:
        raise PermissionError('Aucun moniteur de quarantaine Velociraptor prouvé; refus du simple label')
    with lease_lock():
        leases=read_json(LEASES,{})
        if agent in leases or 'Quarantine' in labels_for(cid):
            raise PermissionError('Isolement préexistant : refus de modifier une quarantaine non créée par SOAR')
        until=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=ttl)).isoformat()
        # Store lease first: a failed label change is cleaned by the timer.
        leases[agent]={'client_id':cid,'decision_id':decision_id,'expires_at':until}
        atomic_json(LEASES,leases)
        try:
            modify_label(cid,'set')
        except Exception:
            try:
                modify_label(cid,'remove')
                leases.pop(agent,None);atomic_json(LEASES,leases)
            except Exception:
                # Keep lease and request earliest cleanup, never lose rollback record.
                leases[agent]['expires_at']=dt.datetime.now(dt.timezone.utc).isoformat()
                atomic_json(LEASES,leases)
            raise
    return {'effect':'edr_quarantine_requested','agent_id':agent,'client_id':cid,
            'expires_at':until,'isolation_verified_on_endpoint':False,
            'note':'Label Quarantine posé; application réseau à vérifier dans les artefacts client'}


def release(agent, *, expected_cid=None):
    require_root()
    with lease_lock():
        leases=read_json(LEASES,{})
        item=leases.get(agent)
        if item is None: raise ValueError('Aucun bail EDR SOAR sur cet agent, ne pas modifier une quarantaine externe')
        cid=item['client_id']
        if expected_cid and expected_cid!=cid:raise ValueError('Client Velociraptor changé')
        modify_label(cid,'remove')
        leases.pop(agent,None)
        atomic_json(LEASES,leases)
    return {'agent_id':agent,'client_id':cid,'quarantine_label_removed':True,
            'network_restoration_verified_on_endpoint':False}


def release_expired():
    require_root()
    leases=read_json(LEASES,{})
    now=dt.datetime.now(dt.timezone.utc)
    failed=0;done=0
    for agent,row in leases.items():
        try:
            when=dt.datetime.fromisoformat(row['expires_at'])
            if when.tzinfo is None or when>now:continue
            release(agent,expected_cid=row['client_id']);done+=1
        except Exception as exc:
            failed+=1
            print('RETRAIT EN ÉCHEC agent='+str(agent)+' erreur='+type(exc).__name__,file=sys.stderr)
    print(json.dumps({'release_count':done,'release_failed':failed}))
    return 0 if not failed else 2


def install_timer():
    require_root()
    for name in ('aegismesh-soar-edr-expiry.service','aegismesh-soar-edr-expiry.timer'):
        src=ROOT/'ops/systemd'/name
        dest=Path('/etc/systemd/system')/name
        if dest.exists() and 'X-Aegismesh-Soar-Managed=yes' not in dest.read_text():
            raise PermissionError('Unité systemd existante non gérée par AEGISMESH-SOAR')
        dest.write_bytes(src.read_bytes());os.chmod(dest,0o644)
    for arg in (['systemctl','daemon-reload'],['systemctl','enable','--now',EXPIRY_TIMER]):
        p=subprocess.run(arg,timeout=15)
        if p.returncode:raise RuntimeError('Activation du timer EDR impossible')
    if not timer_active():raise RuntimeError('Timer EDR non actif')
    print('Timer de désisolement EDR actif (toutes les minutes)')






def quarantine_monitoring_status(agent):
    """Read-only monitoring configuration: label alone is NOT network isolation."""
    cid=linked(agent)
    client=valid_client(cid)
    rows=api_query(READ_MONITORING)
    # API shapes differ by Velociraptor release. Never claim an enforced rule
    # based solely on presence of a monitor name in an arbitrary JSON blob.
    blob=rows[0].get('monitoring') if len(rows)==1 else None
    text=json.dumps(blob,ensure_ascii=False) if blob is not None else ''
    monitor='Windows.Remediation.QuarantineMonitor' if 'windows' in client_os(client) else 'Linux.Remediation.Quarantine'
    return {'agent_id':agent,'client_id':cid,'required_artifact':monitor,
            'artifact_referenced_by_server_monitoring':monitor in text,
            'quarantine_label_present':'Quarantine' in labels_for(cid),
            'lease':read_json(LEASES,{}).get(agent),
            'network_effect_verified':False,
            'warning':'Server-side monitor reference and label are not proof of endpoint packet filtering.'}


def request_triage(agent, *, confirm):
    require_root()
    if not confirm:raise PermissionError('Confirmer une collecte EDR réelle via --confirm')
    cid=linked(agent)
    client=valid_client(cid)
    wazuh=next((x for x in wazuh_agents() if str(x.get('id'))==agent),None)
    if not wazuh or wazuh.get('status')!='active':
        raise PermissionError('Agent Wazuh absent ou non connecté')
    w_os=' '.join(str(v) for v in (wazuh.get('os') or {}).values()).lower()
    is_windows='windows' in client_os(client)
    if is_windows != ('windows' in w_os):
        raise PermissionError('Systèmes Wazuh et Velociraptor divergents')
    if not identity_corresponds(agent,client,wazuh):
        raise PermissionError('Hôtes divergents et lien non attesté : edr attest --agent-id ID --confirm')
    if not is_windows and 'linux' not in client_os(client):
        raise PermissionError('Collecte ciblée seulement Linux / Windows')
    # Limit duplicate collections on an endpoint still processing a previous
    # SOAR flow. This specifically protects the Kali flow that may stay RUNNING.
    active={'RUNNING','WAITING','PENDING','SCHEDULED','IN_PROGRESS'}
    if any(r['state'] in active for r in flow_list(agent,only_soar=True)):
        raise RuntimeError('Collecte SOAR toujours active sur cet agent : diagnostic plutôt que duplicata')
    query=COLLECT_WIN_TRIAGE if is_windows else COLLECT_LINUX_TRIAGE
    rows=api_query(query,{'ClientId':cid})
    if len(rows)!=1 or not isinstance(rows[0].get('collection'),dict):
        raise RuntimeError('Triage non confirmé par API Velociraptor')
    fid=str(rows[0]['collection'].get('flow_id',''))
    validate_flow_id(fid)
    track_flow(agent,cid,fid,artifact='Windows.System.Pslist+Windows.Network.Netstat' if is_windows else 'Linux.Sys.Pslist+Linux.Network.Netstat')
    return {'agent_id':agent,'client_id':cid,'flow_id':fid,'state':'REQUESTED_NOT_COMPLETED',
            'artifacts':['Windows.System.Pslist','Windows.Network.Netstat'] if is_windows else
            ['Linux.Sys.Pslist','Linux.Network.Netstat'],
            'endpoint_data_verified':False}


def validate_flow_id(value):
    if not RX_FLOW.fullmatch(str(value)):
        raise ValueError('Flow ID Velociraptor invalide')
    return str(value)


def _field(row, *names):
    # Velociraptor flows() returns FlowId / ClientId / Request / Creator in
    # several server versions, while collect_client() returns snake_case.
    # Reject contradictory aliases rather than silently attributing a
    # collection to the wrong endpoint.
    present = [row[n] for n in names if n in row and row[n] is not None]
    if len(present) > 1 and any(x != present[0] for x in present[1:]):
        raise ValueError('Réponse EDR incohérente : noms de champs contradictoires')
    return present[0] if present else None


def normalize_flow(row, expected_client):
    """Canonicalize documented VQL flows() fields, preserving attribution."""
    if not isinstance(row, dict):
        raise ValueError('Réponse Velociraptor flows() non structurée')
    fid=_field(row,'FlowId','flow_id','flowId','FlowID','SessionId','session_id','sessionId')
    if fid is None:
        raise ValueError('Schéma flows() non reconnu : FlowId/session_id absents (champs: ' +
                         ','.join(sorted(str(k) for k in row)[:15]) + ')')
    # Some rows can be pre-existing, malformed collections: don't claim they
    # are real flows; only explicitly valid Velociraptor IDs are accepted.
    validate_flow_id(fid)
    cid=_field(row,'ClientId','client_id','clientId','ClientID')
    if cid is not None and cid != expected_client:
        raise ValueError('Flow retourné pour un autre client EDR')
    req=_field(row,'Request','request') or {}
    if not isinstance(req,dict):
        req={}
    # A remote flow may echo its intended endpoint in the request as well.
    # Reject divergent ownership even when the top-level client_id is valid.
    req_cid=_field(req,'ClientId','client_id','clientId','ClientID')
    if req_cid is not None and req_cid != expected_client:
        raise ValueError('Flow request attribuée à un autre client EDR')
    req_fid=_field(req,'FlowId','flow_id','SessionId','session_id')
    if req_fid is not None and req_fid != fid:
        raise ValueError('Flow request avec identifiant contradictoire')
    artifacts=_field(req,'Artifacts','artifacts')
    if artifacts is None:
        artifacts=_field(row,'Artifacts','artifacts')
    if isinstance(artifacts,str):artifacts=[artifacts]
    if not isinstance(artifacts,list):artifacts=[]
    creator=_field(row,'Creator','creator')
    if creator is None:creator=_field(req,'Creator','creator')
    state=_field(row,'State','state')
    if state is None:
        context=_field(row,'Context','context') or {}
        if isinstance(context,dict):state=_field(context,'State','state')
    rows=_field(row,'TotalCollectedRows','total_collected_rows','totalCollectedRows')
    normalized={
        'client_id':expected_client,'flow_id':str(fid),
        'state':state or 'UNKNOWN','creator':creator or '',
        'request':{'artifacts':artifacts,'creator':creator or ''},
        'total_collected_rows':rows
    }
    # Preserve existing normalized contract when a state was explicitly
    # reported. For servers omitting it, a detail query may be necessary.
    if state is None:
        normalized['state_missing']=True
    return normalized



def get_agent_flow_rows(agent):
    cid=linked(agent)
    valid_client(cid)
    raw=api_query(READ_FLOWS,{'ClientId':cid})
    # Never silently drop rows due to a server version's property case.
    # An unknown schema should be reported explicitly, not as "no flows".
    return cid,[normalize_flow(r,cid) for r in raw]


def matching_flow(cid, flow_id):
    validate_flow_id(flow_id)
    rows=api_query(READ_FLOW,{'ClientId':cid,'FlowId':flow_id})
    matched=[]
    for original in rows:
        row=normalize_flow(original,cid)
        if row['flow_id']==flow_id:matched.append(row)
    if len(matched)!=1:
        raise ValueError('Flow absent ou non attribuable à ce client EDR')
    return matched[0]


def verified_flow_details(cid, flow_id):
    """Optional read-only get_flow() fallback for records lacking `state`.

    Some deployments omit the state field in flows(). Missing is never
    treated as FINISHED; the fallback is also constrained to an exact client
    and flow identifier, and failures remain unknown.
    """
    try:
        responses=api_query(READ_FLOW_DETAILS, {'ClientId':cid,'FlowId':flow_id})
    except RuntimeError:
        return None
    if len(responses)!=1 or not isinstance(responses[0],dict):
        return None
    details=responses[0].get('details')
    if not isinstance(details,dict):
        return None
    # Never reuse status or results if returned identity is different.
    try:
        normalized=normalize_flow(details,cid)
    except ValueError:
        # A missing identifier does not authenticate a result. Conflicting
        # identities must still be rejected, not silently ignored.
        if any(k in details for k in ('FlowId','flow_id','SessionId','session_id','client_id','ClientId')):
            raise
        return None
    if normalized['flow_id']!=flow_id:
        raise PermissionError('get_flow() retourné pour un autre flow')
    return normalized


def flow_state(row):
    state=str(row.get('state') or row.get('State') or 'UNKNOWN').upper()
    return state if state in ('RUNNING','FINISHED','ERROR','CANCELED','CANCELLED','WAITING','PENDING','UNRESPONSIVE') else 'UNKNOWN'


def is_soar_flow(row, flow_id, tracked):
    creator=str(row.get('creator') or (row.get('request') or {}).get('creator') or '').upper()
    return flow_id in tracked or creator=='AEGISMESH_SOAR_API'


def track_flow(agent, cid, flow_id, *, status='requested', result_count=None, result_hash=None, artifact=SAFE_ARTIFACT):
    validate_flow_id(flow_id)
    history=read_json(FLOW_RECORDS,{})
    row=history.get(flow_id,{})
    if row and (row.get('agent_id')!=agent or row.get('client_id')!=cid):
        raise PermissionError('Flow suivi déjà associé à un autre agent')
    row.update({'agent_id':agent,'client_id':cid,'flow_id':flow_id,
                'state':status,'artifact':artifact,
                'last_checked':dt.datetime.now(dt.timezone.utc).isoformat()})
    if result_count is not None:row['result_rows']=result_count
    if result_hash is not None:row['result_sha256']=result_hash
    history[flow_id]=row
    if len(history)>250:
        history=dict(sorted(history.items(),key=lambda x:x[1].get('last_checked',''),reverse=True)[:250])
    atomic_json(FLOW_RECORDS,history)


def flow_status(agent, flow_id=None, *, include_result=True, persist=True):
    cid, all_rows = get_agent_flow_rows(agent)
    if flow_id is None:
        if not all_rows:raise ValueError('Aucun flow Velociraptor pour cet agent')
        flow_id=str(all_rows[0]['flow_id'])
    validate_flow_id(flow_id)
    row=matching_flow(cid,flow_id)
    state=flow_state(row)
    source='flows()'
    if state=='UNKNOWN' and row.get('state_missing'):
        details=verified_flow_details(cid,flow_id)
        if details is not None:
            detail_state=flow_state(details)
            if detail_state!='UNKNOWN':
                state=detail_state
                source='get_flow()'
                # The verified details can contain an updated artifact list.
                row=details
    outcome={'agent_id':agent,'client_id':cid,'flow_id':flow_id,'state':state,
             'artifacts':(row.get('request') or {}).get('artifacts',[]),
             'state_source':source,
             'total_collected_rows':row.get('total_collected_rows'),
             'result_rows_sampled':None,'sample_sha256':None,
             'collection_finished':state=='FINISHED','results_present':False}
    # Results accessible only for a verified FINISHED Generic.Client.Info collection.
    requested=outcome['artifacts']
    if include_result and state=='FINISHED' and isinstance(requested,list):
        queries=[]
        if SAFE_ARTIFACT in requested: queries.append((SAFE_ARTIFACT,READ_FLOW_RESULTS))
        queries.extend((name,query) for name,query in TRIAGE_RESULT_QUERIES.items() if name in requested)
        if queries:
            sampled={name:api_query(query,{'ClientId':cid,'FlowId':flow_id}) for name,query in queries}
            outcome['result_rows_sampled']=sum(len(rows) for rows in sampled.values())
            # Preserve V3.7.4 Generic.Client.Info evidence hash semantics.
            digest_input=sampled[SAFE_ARTIFACT] if set(sampled)=={SAFE_ARTIFACT} else sampled
            outcome['sample_sha256']=hashlib.sha256(json.dumps(digest_input,sort_keys=True,ensure_ascii=False,
                separators=(',',':')).encode('utf-8')).hexdigest()
            outcome['results_present']=any(bool(rows) for rows in sampled.values())
            outcome['sampled_artifacts']={name:len(rows) for name,rows in sampled.items()}
    if persist and (is_soar_flow(row,flow_id,read_json(FLOW_RECORDS,{}))):
        track_flow(agent,cid,flow_id,status=state,result_count=outcome['result_rows_sampled'],
                   result_hash=outcome['sample_sha256'],artifact='+'.join(requested) if isinstance(requested,list) and requested else SAFE_ARTIFACT)
    return outcome


def flow_list(agent=None, *, only_soar=False):
    mapping=read_json(MAPPING,{})
    agents=[agent] if agent is not None else sorted(mapping)
    tracked=read_json(FLOW_RECORDS,{})
    output=[]
    for aid in agents:
        cid,rows=get_agent_flow_rows(aid)
        for row in rows[:25]:
            fid=str(row['flow_id'])
            if only_soar and not is_soar_flow(row,fid,tracked):continue
            output.append({'agent_id':aid,'client_id':cid,'flow_id':fid,
                           'state':flow_state(row),
                           'artifacts':(row.get('request') or {}).get('artifacts',[]),
                           'soar_initiated':is_soar_flow(row,fid,tracked)})
    return output[:120]


def main(argv=None):
    p=argparse.ArgumentParser(description='AEGISMESH-SOAR / EDR Velociraptor existant')
    s=p.add_subparsers(dest='action',required=True)
    s.add_parser('discover'); s.add_parser('status'); s.add_parser('clients'); s.add_parser('link-auto')
    flow_cmd=s.add_parser('flows',help='Lister les collectes réelles Velociraptor, lecture seule')
    flow_cmd.add_argument('--agent-id')
    flow_state_cmd=s.add_parser('flow-status',help='Statut et empreinte des résultats réels du flow')
    flow_state_cmd.add_argument('--agent-id',required=True);flow_state_cmd.add_argument('--flow-id')
    inv=s.add_parser('investigations',help='Collectes lancées par SOAR et leur état, lecture seule')
    inv.add_argument('--agent-id')
    config=s.add_parser('configure',help='Réutilise une configuration API mTLS Velociraptor EXISTANTE')
    config.add_argument('--mode',choices=['host','docker'],required=True)
    config.add_argument('--container',default='')
    config.add_argument('--api-config',required=True)
    config.add_argument('--binary',default='velociraptor')
    manual=s.add_parser('link',help='Liaison Wazuh → Velociraptor vérifiée une seule fois')
    manual.add_argument('--agent-id',required=True);manual.add_argument('--client-id',required=True);manual.add_argument('--confirm',action='store_true')
    for name in ('collect','quarantine-status','release'):
        x=s.add_parser(name);x.add_argument('--agent-id',required=True)
        if name=='release':x.add_argument('--confirm',action='store_true')
    al=s.add_parser('allow-isolation');al.add_argument('--agent-id',required=True);al.add_argument('--confirm',action='store_true')
    timer=s.add_parser('enable-expiry');timer.add_argument('--confirm',action='store_true')
    si=s.add_parser('internal-isolate');si.add_argument('--agent-id',required=True);si.add_argument('--decision-id',required=True)
    triage=s.add_parser('triage',help='Collecte réelle bornée processus et connexions, OS spécifique')
    triage.add_argument('--agent-id',required=True);triage.add_argument('--confirm',action='store_true')
    qm=s.add_parser('quarantine-doctor',help='Monitor/label/lease EDR (sans prétendre preuve réseau)')
    qm.add_argument('--agent-id',required=True)
    att=s.add_parser('attest',help='Attester le mapping Wazuh/EDR réel d un client au nom différent')
    att.add_argument('--agent-id',required=True);att.add_argument('--confirm',action='store_true')
    s.add_parser('release-expired')
    a=p.parse_args(argv)
    try:
        require_root()
        if a.action=='discover':
            print('Conteneurs Velociraptor détectés:',discovered() or 'aucun')
            print('API mTLS configurée:',CONF.exists());print('Timer actif:',timer_active())
            print('Raccordement guidé: aegismesh-soar edr doctor')
        elif a.action=='configure':
            cfg={'mode':a.mode,'container':a.container,'api_config':a.api_config,'binary':a.binary}
            validate_config(cfg)
            api_query('SELECT * FROM info() LIMIT 1',cfg=cfg)
            atomic_json(CONF,cfg)
            print('API Velociraptor mTLS opérationnelle, configuration privée enregistrée')
        elif a.action=='status':
            print('API mTLS configurée:',CONF.exists(),'Timer de retrait actif:',timer_active())
            print('Parc Velociraptor Docker:',discovered() or 'non détecté')
            if CONF.exists():
                print('Clients Velociraptor:',len(api_clients()))
            print('Agents liés:',read_json(MAPPING,{}))
            print('Baux de quarantaine SOAR:',list(read_json(LEASES,{})))
            print('La présence du label n’est pas la preuve de l’isolement effectif du réseau')
        elif a.action in ('flows','investigations'):
            rows=flow_list(getattr(a,'agent_id',None),only_soar=a.action=='investigations')
            if not rows:print('Aucune collecte correspondante retrouvée sur le serveur Velociraptor')
            else:
                for row in rows:
                    print(row['agent_id'],row['flow_id'],row['state'],
                          'SOAR' if row['soar_initiated'] else 'externe',
                          ','.join(row['artifacts']) if isinstance(row['artifacts'],list) else '?')
        elif a.action=='flow-status':
            print(json.dumps(flow_status(a.agent_id,a.flow_id),ensure_ascii=False,indent=2))
        elif a.action=='clients':
            if not CONF.exists():
                raise RuntimeError('API mTLS absente : exécuter edr doctor, puis edr setup ou edr bootstrap')
            for r in api_clients():
                print(r['client_id'],r.get('hostname','?'),r.get('os','?'),r.get('labels',[]))
        elif a.action=='link-auto':
            if not CONF.exists():
                raise RuntimeError('API mTLS absente : exécuter edr doctor avant link-auto')
            ok,unmatched=auto_link()
            for aid,cid in ok:print('[LIE]',aid,cid)
            for aid,hostname,count in unmatched:print('[A VERIFIER]',aid,hostname,'candidats:',count)
        elif a.action=='link':
            if not a.confirm:raise PermissionError('Confirmation --confirm requise après vérification des deux machines')
            if not RX_AGENT.fullmatch(a.agent_id) or a.agent_id=='000':raise ValueError('ID Wazuh invalide')
            client=valid_client(a.client_id)
            wazuh=next((w for w in wazuh_agents() if str(w.get('id'))==a.agent_id),None)
            if not wazuh:raise ValueError('Agent Wazuh introuvable')
            w_os=' '.join(str(v) for v in (wazuh.get('os') or {}).values()).lower()
            if ('windows' in w_os)!=('windows' in client_os(client)):
                raise PermissionError('OS incompatible entre Wazuh et client Velociraptor')
            mapping=read_json(MAPPING,{})
            if a.client_id in [v for k,v in mapping.items() if k!=a.agent_id]:
                raise PermissionError('Client Velociraptor déjà lié à un autre agent Wazuh')
            if a.agent_id in read_json(LEASES,{}):
                raise PermissionError('Liaison d un agent en quarantaine interdite')
            print('Association confirmée Wazuh',a.agent_id,wazuh.get('name'),
                  '→ Velociraptor',a.client_id,client.get('hostname'))
            mapping[a.agent_id]=a.client_id
            atomic_json(MAPPING,mapping)
        elif a.action in ('collect','quarantine-status'):
            if not CONF.is_file():
                raise RuntimeError('API Velociraptor absente : exécuter edr doctor puis edr setup ou edr bootstrap avant cette action')
            cid=linked(a.agent_id);valid_client(cid)
            if a.action=='quarantine-status':
                print('Agent:',a.agent_id,'Client:',cid,'Labels:',labels_for(cid))
                print('Bail SOAR:',read_json(LEASES,{}).get(a.agent_id,'aucun'))
            else:
                rows=api_query(COLLECT,{'ClientId':cid})
                if not rows:raise RuntimeError('Aucun flow de collecte confirmé')
                flow_id=str((rows[0].get('collection') or {}).get('flow_id',''))
                if RX_FLOW.fullmatch(flow_id):
                    try: track_flow(a.agent_id,cid,flow_id)
                    except OSError:
                        print('AVERTISSEMENT: collecte acceptée mais suivi local non enregistré',file=sys.stderr)
                    print('Collecte demandée, agent:',a.agent_id,'flow_id:',flow_id,'état: queued (non vérifié)')
                    print('Suivi: aegismesh-soar edr flow-status --agent-id',a.agent_id,'--flow-id',flow_id)
                else:
                    print('Collecte acceptée par API mais flow_id absent ou invalide; vérifier Velociraptor')
        elif a.action=='allow-isolation':
            if not a.confirm:raise PermissionError('Confirmation --confirm requise')
            if not RX_AGENT.fullmatch(a.agent_id) or a.agent_id in ('000','006'):
                raise PermissionError('Agent EDR non autorisé; DC protégé')
            cid=linked(a.agent_id)
            valid_client(cid); check_in_wazuh={str(x.get('id')):x for x in wazuh_agents()}
            if a.agent_id not in check_in_wazuh:raise ValueError('Agent Wazuh non trouvé')
            # Configuration service merged atomically using existing helper.
            sys.path.insert(0,str(ROOT))
            from ops.edr_enable import enable_isolation_agent
            enable_isolation_agent(a.agent_id)
            print('Agent',a.agent_id,'autorisé, service SOAR rechargé')
        elif a.action=='enable-expiry':
            if not a.confirm:raise PermissionError('--confirm obligatoire')
            install_timer()
        elif a.action=='internal-isolate':
            print(json.dumps(request_quarantine(a.agent_id,a.decision_id),ensure_ascii=False))
        elif a.action=='release':
            if not a.confirm:raise PermissionError('--confirm obligatoire')
            print(json.dumps(release(a.agent_id),ensure_ascii=False))
        elif a.action=='attest':
            print(json.dumps(attest_link(a.agent_id,confirm=a.confirm),ensure_ascii=False,indent=2))
        elif a.action=='triage':
            print(json.dumps(request_triage(a.agent_id,confirm=a.confirm),ensure_ascii=False,indent=2))
        elif a.action=='quarantine-doctor':
            print(json.dumps(quarantine_monitoring_status(a.agent_id),ensure_ascii=False,indent=2))
        elif a.action=='release-expired':return release_expired()
    except (RuntimeError,ValueError,PermissionError,FileNotFoundError) as exc:
        print('ÉCHEC EDR:',str(exc)[:250],file=sys.stderr);return 2
    return 0

if __name__=='__main__':sys.exit(main())
