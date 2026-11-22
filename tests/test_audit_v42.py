#!/usr/bin/env python3
"""Mocked V4.2 recovery tests: never contact real Docker, Shuffle or agents."""
import datetime as dt
from pathlib import Path
import sys
from unittest import mock
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ops import audit_v42 as audit

node={'HostConfig':{'NetworkMode':'tenzir-network','PortBindings':{}},
      'State':{'Status':'created'},'Config':{'Image':'tenzir/tenzir:stable'}}
with mock.patch.object(audit,'docker_object',side_effect=lambda kind,name: node if kind=='container' else None):
    assert audit.tenzir_status()['state']=='broken_missing_network'
    with mock.patch.object(audit,'checked') as checked, \
         mock.patch.object(audit,'command',return_value=mock.Mock(returncode=0,stdout='tenzir-node',stderr='')) as cmd, \
         mock.patch.object(audit,'tenzir_status',return_value={'state':'running','network_exists':True,'network_binding_verified':True}):
        with mock.patch.object(audit,'docker_object',side_effect=[node,None,{'Driver':'bridge','Name':'tenzir-network'}]):
            with mock.patch.object(audit.os,'geteuid',return_value=0):
                result=audit.repair_tenzir(confirm=True)
                assert result['node_state']=='running' and result['network_created']
                assert checked.call_args_list[0].args[0]==['docker','network','create','--driver','bridge','tenzir-network']
                assert cmd.call_args.args[0]==['docker','start','tenzir-node']

public=dict(node)
public={'HostConfig':{'NetworkMode':'tenzir-network',
                      'PortBindings':{'5160/tcp':[{'HostIp':'0.0.0.0','HostPort':'5160'}]}},
        'State':{'Status':'created'},'Config':{'Image':'tenzir/tenzir:stable'}}
with mock.patch.object(audit,'docker_object',return_value=public), \
     mock.patch.object(audit.os,'geteuid',return_value=0), \
     mock.patch.object(audit,'checked') as checked:
    try:audit.repair_tenzir(confirm=True);raise AssertionError('open port accepted')
    except audit.AuditError:pass
    checked.assert_not_called()

with mock.patch.object(audit,'docker_object',return_value=node), \
     mock.patch.object(audit,'checked') as checked:
    try:audit.repair_tenzir(confirm=False);raise AssertionError('confirm missing')
    except audit.AuditError:pass
    checked.assert_not_called()

calls=[]
def fake_request(url,token,payload=None):
    calls.append((url,payload))
    if url.endswith('/health'):return 200,{'status':'up'}
    if url.endswith('/v1/decisions'):
        assert payload['tag']=='OBSERVE' and payload['approved'] is False
        assert payload['evidence_ids']==[] and payload['target']=={}
        return 202,{'decision_id':payload['decision_id']}
    assert '/v1/decisions/am-' in url
    return 200,{'delivery':'action_executed','action_status':'executed',
                'execution_id':'exec-12345678',
                'detail':'{"effect":"record_only","external_action":false}'}
with mock.patch.object(audit.os,'geteuid',return_value=0), \
     mock.patch.object(audit,'env_config',return_value={'DECISION_TOKEN':'test-only',
        'SHUFFLE_WEBHOOK_URL':'http://127.0.0.1:3001/webhook','SOAR_BIND_HOST':'127.0.0.1'}), \
     mock.patch.object(audit,'request_json',side_effect=fake_request), \
     mock.patch.object(audit,'worker_names',return_value=['shuffle-worker-e2e']):
    check=audit.prove_worker(confirm=True,timeout=5)
    assert check['observe_callback_verified'] is True and check['worker_container_seen'] is True
    assert len(calls)==3

with mock.patch.object(audit,'env_config',return_value={'ENABLE_EDR_ISOLATION':'false',
        'ENABLE_PROGRESSIVE_GUARD':'true','EDR_ISOLATION_AGENT_IDS':''}):
    from ops import edr_velociraptor
    with mock.patch.object(edr_velociraptor,'read_json',return_value={}):
        state=audit.edr_inventory()
        assert state['guard_enabled'] and not state['enabled']
        assert not state['network_effect_proved'] and state['domain_controller_excluded']

with mock.patch.object(audit,'timer_status',return_value={audit.TIMER_EDR:{'active':True},
    audit.TIMER_RESP:{'active':True}}):
    assert all(x['active'] for x in audit.timer_status().values())

print('PASS: V4.2 Tenzir strict repair guards; OBSERVE-only E2E; no production actions; EDR evidence honest')

# Read-only block inventory must not create the response_checks table or modify
# decisions. The synthetic database is local; no real ban is ever attempted.
import sqlite3
import tempfile
from soar import bridge
with tempfile.TemporaryDirectory() as tmp:
    db_path=Path(tmp)/'decisions.sqlite3'
    with sqlite3.connect(db_path) as conn:
        conn.execute('CREATE TABLE decisions (id TEXT, tag TEXT, action_status TEXT, updated_at TEXT)')
        conn.execute('INSERT INTO decisions VALUES (?,?,?,?)',
            ('am-'+'a'*24,'F2B_BAN_SERVER','executed',dt.datetime.now(dt.timezone.utc).isoformat()))
        conn.commit()
    with mock.patch.object(audit.os,'geteuid',return_value=0), \
         mock.patch.object(audit,'env_config',return_value={'SOAR_DB_BACKEND':'sqlite','SOAR_DB':str(db_path)}):
        report=audit.block_inventory()
        assert report['actions']['F2B_BAN_SERVER'][0]['endpoint_proof']=='not_verified'
        assert report['actions']['F2B_BAN_SERVER'][0]['proof_is_historical'] is True
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM sqlite_master WHERE name='response_checks'").fetchone()[0]==0
print('PASS: block inventory read-only, absent endpoint proof remains not_verified')


# V4.2.1: actual Docker output can have NetworkMode=bridge, but stale
# NetworkSettings.Networks still names the missing tenzir-network.
bridge_stale={'Name':'/tenzir-node',
    'HostConfig':{'NetworkMode':'bridge','PortBindings':{}},
    'NetworkSettings':{'Networks':{'tenzir-network':{'NetworkID':'old-deleted-id'}}},
    'State':{'Status':'created'},'Config':{'Image':'tenzir/tenzir:stable'}}
with mock.patch.object(audit,'docker_object',side_effect=lambda kind,name: bridge_stale if kind=='container' else None):
    state=audit.tenzir_status()
    assert state['state']=='broken_missing_network' and state['stale_tenzir_network_reference']
    assert state['attached_networks']==['tenzir-network']
with mock.patch.object(audit,'docker_object',side_effect=[bridge_stale,None,{'Driver':'bridge','Name':'tenzir-network'}]), \
     mock.patch.object(audit,'checked') as checked, \
     mock.patch.object(audit,'tenzir_status',return_value={'state':'running','network_exists':True,'network_binding_verified':True}), \
     mock.patch.object(audit,'command',return_value=mock.Mock(returncode=0,stdout='tenzir-node',stderr='')) as cmd, \
     mock.patch.object(audit.os,'geteuid',return_value=0):
    result=audit.repair_tenzir(confirm=True)
    assert result['node_state']=='running'
    assert checked.call_args.args[0]==['docker','network','create','--driver','bridge','tenzir-network']
    assert cmd.call_args.args[0]==['docker','start','tenzir-node']
# A plain bridge with no tenzir-network attachment is still rejected.
uncertain={**bridge_stale,'NetworkSettings':{'Networks':{'bridge':{}}}}
with mock.patch.object(audit,'docker_object',return_value=uncertain), \
     mock.patch.object(audit,'checked') as checked, \
     mock.patch.object(audit.os,'geteuid',return_value=0):
    try:audit.repair_tenzir(confirm=True);raise AssertionError('ambiguous bridge accepted')
    except audit.AuditError:pass
    checked.assert_not_called()
# An orphaned network ID can still fail docker start. Never force-remove it.
with mock.patch.object(audit,'docker_object',side_effect=[bridge_stale,None,{'Driver':'bridge','Name':'tenzir-network'}]), \
     mock.patch.object(audit,'checked') as checked, \
     mock.patch.object(audit,'command',return_value=mock.Mock(returncode=1,stdout='',stderr='network old-id not found')), \
     mock.patch.object(audit.os,'geteuid',return_value=0):
    try:audit.repair_tenzir(confirm=True);raise AssertionError('failed start accepted')
    except audit.AuditError as e: assert 'sans suppression' in str(e)
    assert checked.call_count==1  # only network creation; no destructive action
print('PASS: V4.2.1 detects stale bridge network, refuses ambiguous states and stops on Docker start failure')
