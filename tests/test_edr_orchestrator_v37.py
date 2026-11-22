#!/usr/bin/env python3
"""Safety unit checks: no real Velociraptor requests or endpoint commands."""
import datetime as dt
import importlib.util
from pathlib import Path
import sys
from unittest import mock
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'soar'))
import bridge
from ops import edr_velociraptor as e

assert 'EDR_COLLECT' in bridge.TAGS
assert bridge.TAGS['EDR_ISOLATE']=='edr_quarantine'
bridge.ENV.clear()
d={'decision_id':'am-'+'a'*24,'tag':'EDR_ISOLATE','incident_id':'inc-1','approved':True,
   'confidence':0.99,'evidence_ids':['wazuh-1','sysmon-2'],'target':{'agent_id':'001'},
   'expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5)).isoformat()}
try:bridge.policy(d)
except PermissionError:pass
else:raise AssertionError('EDR isolation must be disabled by default')
bridge.ENV.update({'ENABLE_EDR_ISOLATION':'true','ENABLE_PROD_ACTIONS':'true'})
assert bridge.policy(d)=='edr_quarantine'
d['confidence']=0.91
try:bridge.policy(d)
except PermissionError:pass
else:raise AssertionError('EDR isolation needs >=.95')
d['confidence']=0.99
assert e.EXPIRY_TIMER.endswith('.timer')
d['tag']='EDR_COLLECT'
assert bridge.policy(d)=='edr_collection'
d['tag']='EDR_ISOLATE'
for target in ['000','006','abc']:
    try:
        with mock.patch.object(e,'read_env',return_value={'ENABLE_PROD_ACTIONS':'true','ENABLE_EDR_ISOLATION':'true','EDR_ISOLATION_AGENT_IDS':target}), mock.patch.object(e,'timer_active',return_value=True):
            e.check_allowed(target)
    except PermissionError:pass
    else:raise AssertionError('DC/manager/unknown not allowed')
try:e.api_query('SELECT * FROM arbitrary()')
except (PermissionError,ValueError):pass
else:raise AssertionError('Arbitrary VQL not denied')
for value in ('bad','C.nothex','C.abc'):
    try:e.valid_client(value)
    except ValueError:pass
    else:raise AssertionError('Invalid client ID accepted')
for op in ['set','remove']:
    assert 'Quarantine' in (e.SET_QUARANTINE if op=='set' else e.REMOVE_QUARANTINE)
with mock.patch.object(e,'api_clients',return_value=[
    {'client_id':'C.aabbccddeeff0011','hostname':'WIN-LAB-01','os':'windows'},
    {'client_id':'C.0123456789abcdef','hostname':'KALI-IKOM','os':'linux'}]), \
     mock.patch.object(e,'wazuh_agents',return_value=[
    {'id':'001','name':'win-lab-01'}, {'id':'002','name':'kali-ikom'},
    {'id':'006','name':'ad-aws'}]), \
     mock.patch.object(e,'read_json',return_value={}), \
     mock.patch.object(e,'atomic_json') as atomic:
    linked,missing=e.auto_link()
    assert len(linked)==2 and len(missing)==1
    assert dict(linked)['001']=='C.aabbccddeeff0011'
    atomic.assert_called_once()

# Even an authorized endpoint must have an active expiry service.
with mock.patch.object(e,'require_root'), mock.patch.object(e,'check_allowed',side_effect=PermissionError('timer unavailable')):
    try:e.request_quarantine('001','am-'+'a'*24)
    except PermissionError:pass
    else:raise AssertionError('Quarantine executed without expiry guard')
print('PASS: Velociraptor API VQL allowlist, strict Wazuh links, DC isolation exclusion, expiry guard and .95 policy; no live EDR action')
