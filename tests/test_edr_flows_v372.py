#!/usr/bin/env python3
"""EDR tracking tests with read-only mock API; never contacts Docker/Velociraptor."""
import sys
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ops import edr_velociraptor as e

C='C.3c9cde1e0b930676'
F='F.DC1APVLV8NO1Q'
G='F.DC1B583LF7L32'
records={}
flow_row={'client_id':C,'flow_id':F,'state':'FINISHED','creator':'AEGISMESH_SOAR_API',
          'request':{'artifacts':['Generic.Client.Info']}}

# The read-only queries are locked into explicit, pre-approved VQL constants.
assert e.READ_FLOWS in e.api_query.__code__.co_consts or 'READ_FLOWS' in e.api_query.__code__.co_names
with mock.patch.object(e,'CONF',Path('/not-present')):
    for q in ('SELECT * FROM scope()', 'SELECT * FROM flow_results(client_id="attacker")'):
        try:e.api_query(q)
        except PermissionError:pass
        else:raise AssertionError('Arbitrary VQL not blocked')
    for value in ('F.foo\' UNION 1','F.bad\n','X.'+'1'*15):
        try:e.api_query(e.READ_FLOW,{'ClientId':C,'FlowId':value},cfg={'mode':'docker','api_config':'/a','container':'velociraptor'})
        except ValueError:pass
        else:raise AssertionError('Unsafe flow_id accepted')

# Exact client and flow must match real records. No agent spoof / unrelated proof.
with mock.patch.object(e,'linked',return_value=C), \
     mock.patch.object(e,'valid_client',return_value={'client_id':C}), \
     mock.patch.object(e,'read_json',return_value={}), \
     mock.patch.object(e,'atomic_json') as save, \
     mock.patch.object(e,'api_query',side_effect=lambda q,env=None: (
         [flow_row] if q in (e.READ_FLOW,e.READ_FLOWS) else [{'Hostname':'WIN-LAB-01'}] if q==e.READ_FLOW_RESULTS else [])) as api:
    result=e.flow_status('001',F)
    assert result['state']=='FINISHED' and result['collection_finished'] is True and result['results_present'] is True
    assert result['result_rows_sampled']==1 and len(result['sample_sha256'])==64
    assert api.call_count==3, api.call_args_list
    assert api.call_args_list[-1].args[0]==e.READ_FLOW_RESULTS
    save.assert_called_once()

# Non-finished states must not fetch rows or report completed.
for state in ('RUNNING','ERROR','UNKNOWN'):
    with mock.patch.object(e,'linked',return_value=C),mock.patch.object(e,'valid_client',return_value={'client_id':C}), \
         mock.patch.object(e,'api_query',side_effect=lambda q,env=None: ([dict(flow_row,state=state)] if q in (e.READ_FLOWS,e.READ_FLOW) else (_ for _ in ()).throw(AssertionError('Result requested on incomplete flow')))), \
         mock.patch.object(e,'read_json',return_value={}):
        out=e.flow_status('001',F,persist=False)
        assert not out['collection_finished'] and not out['results_present'] and out['result_rows_sampled'] is None

# A flow for another client, even with a matching ID, cannot verify agent 001.
with mock.patch.object(e,'api_query',return_value=[dict(flow_row,client_id='C.aaaaaaaaaaaabbbb')]):
    try:e.matching_flow(C,F)
    except ValueError:pass
    else:raise AssertionError('Cross-client flow accepted')

# Enumerations are bounded and filtered when requested.
with mock.patch.object(e,'read_json',return_value={'001':C}), mock.patch.object(e,'linked',return_value=C), \
     mock.patch.object(e,'valid_client',return_value={'client_id':C}), \
     mock.patch.object(e,'api_query',return_value=[flow_row,dict(flow_row,flow_id=G,creator='other')]):
    assert len(e.flow_list('001',only_soar=True))==1
    assert len(e.flow_list('001',only_soar=False))==2

for invalid in ('', 'am-fake','F.','F.hack;touch'):
    try:e.validate_flow_id(invalid)
    except ValueError:pass
    else:raise AssertionError('Invalid flow ID accepted')

print('PASS: EDR read-only flow status, strict agent/client/flow matching, terminal states, bounded results, VQL allowlist; no live EDR action')
