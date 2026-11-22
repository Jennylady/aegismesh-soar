"""Independent, scoped, one-off Velociraptor LAB quarantine.

No client event monitoring changes, no Quarantine label, no DC, no AI claim.
A separately installed local SYSTEM recovery task is REQUIRED as an
independent rollback if the EDR channel disconnects after IPsec enforcement.
"""
import datetime as dt
import json
import secrets
from pathlib import Path
from ops import edr_velociraptor as edr

AGENT='001'
CID='C.3c9cde1e0b930676'
HOST='win-lab-01'
TTL=180
PATH=Path('/var/lib/aegismesh-soar/edr-direct-lab-v4217.json')


def _identity(agent, *, recovery=False):
    if agent != AGENT: raise PermissionError('Isolation directe réservée au LAB 001; DC 006 interdit')
    if recovery:
        # Do not require the Wazuh agent to be ACTIVE while releasing IPsec:
        # the quarantine may itself have interrupted the Wazuh network path.
        cid = edr.linked(agent)
    else:
        from ops.edr_lab_v427 import _validate_target
        cid=_validate_target(agent, require_monitor=False)
    if cid != CID: raise PermissionError('Identité du client EDR différente de WIN-LAB-01')
    return cid


def _flow_id(rows, expected_client=None):
    """Identify a flow ID in documented Velociraptor collect_client outputs.

    Depending on the API/version, a collection object contains flow_id or
    session_id. Be strict: reject conflicting aliases and wrong endpoints.
    Never infer an ID by guessing from unrelated historical flows.
    """
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError('Réponse EDR ambiguë : une seule ligne structurée est requise')
    row = rows[0]
    collection = row.get('collection', row.get('Collection'))
    if isinstance(collection, str):
        try:
            collection = json.loads(collection)
        except (TypeError, ValueError):
            return None
    if not isinstance(collection, dict):
        return None
    values = []
    for record in (collection, row):
        for key in ('flow_id', 'FlowId', 'flowId', 'FlowID',
                    'session_id', 'SessionId', 'sessionId'):
            value = record.get(key)
            if value is not None:
                values.append(value)
    # Some versions wrap the flow identifier in the response context.
    nested = collection.get('context', collection.get('Context'))
    if isinstance(nested, dict):
        for key in ('flow_id', 'FlowId', 'session_id', 'SessionId'):
            value = nested.get(key)
            if value is not None:
                values.append(value)
    if any(not isinstance(v, str) or not edr.RX_FLOW.fullmatch(v) for v in values):
        raise RuntimeError('Identifiant de collecte Velociraptor invalide')
    if len(set(values)) > 1:
        raise RuntimeError('Identifiants de collecte Velociraptor contradictoires')
    if expected_client is not None:
        for record in (collection, row, collection.get('request'),
                       collection.get('Request')):
            if not isinstance(record, dict):
                continue
            for key in ('client_id', 'ClientId', 'clientId', 'ClientID'):
                if key in record and record[key] is not None and record[key] != expected_client:
                    raise RuntimeError('Collecte Velociraptor attribuée à un autre client')
    return values[0] if values else None


def _response_shape(rows):
    """Diagnostics limited to key names and types, never response values."""
    if len(rows) != 1 or not isinstance(rows[0], dict):
        return {'row_count': len(rows), 'row_type': 'unexpected'}
    row = rows[0]
    collection = row.get('collection', row.get('Collection'))
    if isinstance(collection, str):
        try:
            collection = json.loads(collection)
        except ValueError:
            pass
    return {'row_count': 1, 'row_fields': sorted(str(k) for k in row)[:20],
            'collection_type': type(collection).__name__,
            'collection_fields': sorted(str(k) for k in collection)[:30]
            if isinstance(collection, dict) else []}


def _recent_quarantine_flows(agent, cid):
    """Read-only candidates, NEVER proof of a specific failed dispatch."""
    try:
        rows = edr.api_query(edr.READ_FLOWS, {'ClientId': cid})
        matches = []
        for row in rows:
            try:
                flow = edr.normalize_flow(row, cid)
            except (ValueError, TypeError):
                continue
            names = flow.get('request', {}).get('artifacts', [])
            if names == ['Windows.Remediation.Quarantine']:
                matches.append({'flow_id': flow['flow_id'],
                                'state': flow['state'],
                                'creator': flow.get('creator', ''),
                                'attribution': 'candidate_only_not_verified'})
        return {'readback': 'ok', 'candidates': matches[:12],
                'note': 'Un candidat historique ne prouve pas une exécution du dernier essai'}
    except Exception as exc:
        return {'readback': 'unavailable', 'error_class': type(exc).__name__,
                'candidates': [], 'note': 'Pas une preuve d absence de collecte'}


def _read():
    return edr.read_json(PATH,{})


def doctor(agent):
    edr.require_root();cid=_identity(agent)
    return {'agent_id':agent,'client_id':cid,'mode':'direct_client_collection',
      'does_not_edit_client_monitoring':True,
      'recovery_task_confirmed_by_endpoint':False,
      'local_recovery_required':True,
      'existing_direct_lease':_read().get(agent),
      'recent_quarantine_flows':_recent_quarantine_flows(agent,cid),
      'network_effect_verified':False}


def start(agent, *, confirm=False, console_access=False, recovery_task_armed=False):
    edr.require_root()
    if not (confirm and console_access and recovery_task_armed):
        raise PermissionError('--confirm --console-access --recovery-task-armed obligatoires; installer d abord le secours local')
    cid=_identity(agent)
    if not edr.timer_active():
        raise PermissionError('Timer SOAR de retrait inactif : exécution refusée')
    with edr.lease_lock():
        if edr.read_json(edr.LEASES,{}):
            raise PermissionError('Bail EDR via label déjà présent : essai direct refusé')
        if _read():
            raise PermissionError('Collecte de quarantaine directe non terminée ou état ambigu')
        if any('Quarantine' in (c.get('labels') or []) for c in edr.api_clients()):
            raise PermissionError('Label Quarantine déjà présent : éviter les doubles politiques')
        if 'Quarantine' in edr.labels_for(cid):
            raise PermissionError('Quarantaine label existante : essai refusé')
        now=dt.datetime.now(dt.timezone.utc)
        row={'agent_id':agent,'client_id':cid,'lab_id':'direct-lab-'+secrets.token_hex(12),
             'source':'operator_direct_lab_not_ai','created_at':now.isoformat(),
             'expires_at':(now+dt.timedelta(seconds=TTL)).isoformat(),
             'state':'dispatching','flow_id':None}
        edr.atomic_json(PATH,{agent:row})
        try:
            rows=edr.api_query(edr.DIRECT_QUARANTINE_COLLECT,{'ClientId':cid})
            fid=_flow_id(rows,cid)
            if fid is None:
                row['state']='dispatch_unverified_requires_local_recovery'
                row['dispatch_response_shape']=_response_shape(rows)
                edr.atomic_json(PATH,{agent:row})
                raise RuntimeError('Velociraptor a reçu la demande, mais le flow_id est absent : secours local et contrôle requis')
            row['state']='dispatched_unverified';row['flow_id']=fid
            edr.atomic_json(PATH,{agent:row})
        except Exception:
            # Keep expiry lease: API may have dispatched before raising.
            row['state']='dispatch_uncertain_keep_recovery'
            edr.atomic_json(PATH,{agent:row})
            raise
    return {'status':'dispatched_unverified','lab_id':row['lab_id'],
      'flow_id':row['flow_id'],'expires_at':row['expires_at'],
      'endpoint_network_isolation_verified':False,
      'local_recovery_attested_not_verified':True,
      'next':'Mesurer LDAP sur Windows et vérifier flow / suppression automatique'}


def release(agent, *, confirm=False, internal=False):
    edr.require_root()
    if not (confirm or internal):raise PermissionError('--confirm requis')
    cid=_identity(agent,recovery=True)
    with edr.lease_lock():
        data=_read();row=data.get(agent)
        if not row or row.get('client_id')!=cid or row.get('source')!='operator_direct_lab_not_ai':
            raise PermissionError('Aucun bail direct LAB 001 : ne pas toucher aux politiques externes')
        rows=edr.api_query(edr.DIRECT_QUARANTINE_REMOVE,{'ClientId':cid})
        fid=_flow_id(rows,cid)
        if not fid:
            row['state']='release_dispatched_unverified'
            row['release_response_shape']=_response_shape(rows)
            data[agent]=row
            edr.atomic_json(PATH,data)
            raise RuntimeError('Retrait demandé sans flow_id vérifiable; conserver le secours local')
        # A flow being queued is NOT proof of policy removal. Keep a record.
        row['state']='release_dispatched_unverified';row['release_flow_id']=fid
        data[agent]=row;edr.atomic_json(PATH,data)
    return {'status':'release_dispatched_unverified','agent_id':agent,
       'flow_id':fid,'network_restoration_verified':False,
       'local_recovery_still_required':True}


def status(agent):
    edr.require_root();_identity(agent,recovery=True)
    return {'agent_id':agent,'client_id':CID,'direct_lab_lease':_read().get(agent),
      'network_effect_verified':False,'network_restoration_verified':False,
      'recent_quarantine_flows':_recent_quarantine_flows(agent,CID),
      'note':'Contrôler le journal local de secours et LDAP; flow candidat ne prouve pas l isolation'}


def clear(agent, *, confirm=False, endpoint_restored=False):
    """Only clears a lease after explicit operator-verified endpoint recovery.
    Never removes any IPsec policy or label.
    """
    edr.require_root();_identity(agent,recovery=True)
    if not (confirm and endpoint_restored):
        raise PermissionError('--confirm et --endpoint-restored requis APRES contrôle local: LDAP=True, IPsec absent et tâche de secours exécutée')
    with edr.lease_lock():
        data=_read(); row=data.get(agent)
        if not row: raise ValueError('Aucun bail direct')
        if row.get('state') not in ('release_dispatched_unverified','dispatch_uncertain_keep_recovery'):
            raise PermissionError('Retrait non encore demandé; exécuter direct-release')
        data.pop(agent,None);edr.atomic_json(PATH,data)
    return {'lease_cleared':True,'endpoint_recovery_reported_by_operator_not_verified':True}


def release_expired():
    """Called by existing EDR expiry timer; retains ambiguous leases for retry."""
    edr.require_root()
    data=_read();row=data.get(AGENT)
    if not row:return {'release_count':0,'release_failed':0}
    try:when=dt.datetime.fromisoformat(row['expires_at'])
    except (ValueError,KeyError):return {'release_count':0,'release_failed':1}
    if when.tzinfo is None or when>dt.datetime.now(dt.timezone.utc):
        return {'release_count':0,'release_failed':0}
    if row.get('state')=='release_dispatched_unverified':
        return {'release_count':0,'release_failed':0,'recovery_not_verified':True}
    try:
        result=release(AGENT,internal=True)
        return {'release_count':1,'release_failed':0,'restoration_verified':False,
                'release_flow_id':result['flow_id']}
    except Exception as exc:
        return {'release_count':0,'release_failed':1,'error_class':type(exc).__name__}
