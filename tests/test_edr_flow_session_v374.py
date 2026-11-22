#!/usr/bin/env python3
"""Regression using the live Velociraptor flows() `session_id` schema."""
from pathlib import Path
from unittest import mock
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ops import edr_velociraptor as e

C='C.3c9cde1e0b930676'
F='F.DC1APVLV8NO1Q'
K='F.DC1B583LF7L32'
# Fields reported by GCP, state absent, nested request retained.
live={'session_id':F,'client_id':C,'request':{'creator':'AEGISMESH_SOAR_API',
      'client_id':C,'artifacts':['Generic.Client.Info']},
      'active_time':1795320000000000,'execution_duration':0,
      'artifacts_with_results':['Generic.Client.Info/BasicInformation'],
      'outstanding_requests':0,'query_stats':[]}
n=e.normalize_flow(live,C)
assert n['flow_id']==F and n['state']=='UNKNOWN'
assert n['creator']=='AEGISMESH_SOAR_API'
assert n['request']['artifacts']==['Generic.Client.Info']
assert e.READ_FLOW_DETAILS in e.api_query.__code__.co_consts or 'READ_FLOW_DETAILS' in e.api_query.__code__.co_names

with mock.patch.object(e,'linked',return_value=C),mock.patch.object(e,'valid_client',return_value={'client_id':C}), \
     mock.patch.object(e,'read_json',return_value={}),mock.patch.object(e,'atomic_json'), \
     mock.patch.object(e,'api_query',side_effect=lambda q,env=None: (
       [live] if q in (e.READ_FLOWS,e.READ_FLOW) else
       [{'details':dict(live,state='FINISHED',total_collected_rows=1)}] if q==e.READ_FLOW_DETAILS else
       [{'Hostname':'WIN-LAB-01'}] if q==e.READ_FLOW_RESULTS else [])) as api:
    out=e.flow_status('001',F)
    assert out['collection_finished'] and out['state']=='FINISHED'
    assert out['state_source']=='get_flow()' and out['results_present']
    assert out['flow_id']==F and out['client_id']==C
    assert e.flow_list('001',only_soar=True)[0]['flow_id']==F
    assert any(x.args[0]==e.READ_FLOW_DETAILS for x in api.call_args_list)

# Missing state in both reads must remain unknown; do NOT collect results.
with mock.patch.object(e,'linked',return_value=C),mock.patch.object(e,'valid_client',return_value={'client_id':C}), \
     mock.patch.object(e,'read_json',return_value={}), \
     mock.patch.object(e,'api_query',side_effect=lambda q,env=None: (
       [live] if q in (e.READ_FLOWS,e.READ_FLOW) else
       [{'details':live}] if q==e.READ_FLOW_DETAILS else
       (_ for _ in ()).throw(AssertionError('Results must not be read')))):
    out=e.flow_status('001',F,persist=False)
    assert out['state']=='UNKNOWN' and not out['collection_finished'] and not out['results_present']

# Cross-client attribution, nested divergence, duplicate aliases, and bad flow IDs fail closed.
for bad in (dict(live, client_id='C.aaaaaaaaaaaaaaab'),
            dict(live,request=dict(live['request'],client_id='C.aaaaaaaaaaaaaaab')),
            dict(live,request=dict(live['request'],flow_id=K)),
            dict(live,flow_id=K),
            dict(live,session_id='F.bad;injection')):
    try:e.normalize_flow(bad,C)
    except (PermissionError,ValueError):pass
    else:raise AssertionError('Invalid flow attribution accepted')

with mock.patch.object(e,'api_query',return_value=[dict(live,session_id=K)]):
    try:e.matching_flow(C,F)
    except ValueError:pass
    else:raise AssertionError('Wrong flow accepted')

# Explicit running/error state does not require a fallback.
for state in ('RUNNING','ERROR'):
    assert e.flow_state(e.normalize_flow(dict(live,state=state),C))==state
print('PASS: actual session_id flow schema, get_flow fallback, strict attribution, unknown fail-closed; no live actions')
