"""Optional fail-closed escalation gate. Does not invent an incident or score.

It is deliberately independent from HTTP request data beyond already validated
fields, and never authorizes an action by itself. Existing endpoint, TTL,
allowlist and identity guards still run in the EDR adapter.
"""
import datetime as dt
import json
from pathlib import Path

FLOW_RECORDS = Path('/var/lib/aegismesh-soar/edr-flow-tracker.json')


def previous_verified_block(data, dbconn, *, now=None):
    now=now or dt.datetime.now(dt.timezone.utc)
    target=data.get('target') or {}
    agent=target.get('agent_id')
    with dbconn() as db:
        rows=db.execute("SELECT id,payload,tag,detail,action_status,updated_at FROM decisions "
                        "WHERE tag IN ('WINDOWS_BLOCK_IP','WAZUH_BLOCK_AGENT') "
                        "AND action_status='executed' ORDER BY updated_at DESC LIMIT 100").fetchall()
    for row in rows:
        try:
            prior=json.loads(row['payload']); detail=json.loads(row['detail'] or '{}')
            when=dt.datetime.fromisoformat(row['updated_at'].replace('Z','+00:00'))
            if when.tzinfo is None or not 0 <= (now-when).total_seconds() <= 900:continue
            if (prior.get('incident_id')==data.get('incident_id') and
                (prior.get('target') or {}).get('agent_id')==agent and
                detail.get('agent_execution_verified') is True):
                return row['id']
        except (ValueError,TypeError,KeyError):
            continue
    return None


def recent_edr_evidence(agent, *, path=FLOW_RECORDS, now=None):
    now=now or dt.datetime.now(dt.timezone.utc)
    if not path.is_file():return None
    contents=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(contents,dict):return None
    for flow,row in contents.items():
        try:
            when=dt.datetime.fromisoformat(row['last_checked'].replace('Z','+00:00'))
            if (row.get('agent_id')==agent and row.get('state')=='FINISHED' and
                int(row.get('result_rows',0))>0 and
                len(str(row.get('result_sha256','')))==64 and
                when.tzinfo is not None and 0 <= (now-when).total_seconds() <= 1800):
                return flow
        except (ValueError,KeyError,TypeError):pass
    return None


def guard_isolation(data, dbconn, *, flow_path=FLOW_RECORDS, now=None):
    """Optional progression: verified scoped block + completed EDR observation."""
    agent=(data.get('target') or {}).get('agent_id')
    if agent in ('000','006') or not isinstance(agent,str):
        raise PermissionError('Agent de contrôle/AD exclu de l isolement progressif')
    prior=previous_verified_block(data,dbconn,now=now)
    if not prior:
        raise PermissionError('Isolement: blocage IP préalable vérifié du même incident/agent requis')
    flow=recent_edr_evidence(agent,path=flow_path,now=now)
    if not flow:
        raise PermissionError('Isolement: collecte EDR FINISHED avec résultats récents vérifiables requise')
    return {'previous_block_decision':prior,'edr_flow':flow}
