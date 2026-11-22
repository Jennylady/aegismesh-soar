#!/usr/bin/env python3
"""Regression: Velociraptor flows() sends CamelCase fields in live deployments."""
from pathlib import Path
from unittest import mock
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ops import edr_velociraptor as e

C='C.3c9cde1e0b930676'
F='F.DC1APVLV8NO1Q'
G='F.DC1B583LF7L32'
camel={'ClientId':C,'FlowId':F,'State':'FINISHED','Creator':'AEGISMESH_SOAR_API',
       'Request':{'Artifacts':['Generic.Client.Info'],'Creator':'AEGISMESH_SOAR_API'},
       'TotalCollectedRows':2}
assert e.normalize_flow(camel,C)=={
    'client_id':C,'flow_id':F,'state':'FINISHED','creator':'AEGISMESH_SOAR_API',
    'request':{'artifacts':['Generic.Client.Info'],'creator':'AEGISMESH_SOAR_API'},
    'total_collected_rows':2}
# Existing tests and old VQL plugin outputs can still use snake_case.
snake={'client_id':C,'flow_id':F,'state':'RUNNING','creator':'AEGISMESH_SOAR_API',
       'request':{'artifacts':['Generic.Client.Info']},'total_collected_rows':0}
assert e.normalize_flow(snake,C)['state']=='RUNNING'

with mock.patch.object(e,'linked',return_value=C), \
     mock.patch.object(e,'valid_client',return_value={'client_id':C}), \
     mock.patch.object(e,'read_json',return_value={}), \
     mock.patch.object(e,'atomic_json') as persist, \
     mock.patch.object(e,'api_query',side_effect=lambda q,env=None:
        [camel] if q in (e.READ_FLOWS,e.READ_FLOW) else
        [{'Name':'WIN-LAB-01'}] if q==e.READ_FLOW_RESULTS else []):
    cid, rows = e.get_agent_flow_rows('001')
    assert cid==C and rows[0]['flow_id']==F
    status=e.flow_status('001',F)
    assert status['collection_finished'] and status['results_present']
    assert status['result_rows_sampled']==1 and status['total_collected_rows']==2
    assert len(status['sample_sha256'])==64
    assert e.flow_list('001',only_soar=True)[0]['flow_id']==F
    persist.assert_called_once()

# Authentication to API does not bypass client/flow attribution.
for bad in [dict(camel, ClientId='C.aaaaaaaaaaaaaaab'),
            dict(camel, flow_id=G),
            {'Other':'unexpected'},
            dict(camel,FlowId='F.bad;injection')]:
    try:e.normalize_flow(bad,C)
    except (PermissionError,ValueError):pass
    else:raise AssertionError('Invalid or cross-client flow accepted')

with mock.patch.object(e,'linked',return_value=C), \
     mock.patch.object(e,'valid_client',return_value={'client_id':C}), \
     mock.patch.object(e,'api_query',return_value=[dict(camel,FlowId=G)]):
    try:e.matching_flow(C,F)
    except ValueError:pass
    else:raise AssertionError('Incorrect flow accepted')

assert e.flow_state(e.normalize_flow({'FlowId':G,'ClientId':C,'State':'ERROR'},C))=='ERROR'
print('PASS: Velociraptor FlowId/ClientId/Request CamelCase, snake_case, strict attribution; no live actions')
