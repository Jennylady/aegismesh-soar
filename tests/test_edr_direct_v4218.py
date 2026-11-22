#!/usr/bin/env python3
"""V4.2.18: validate server response formats and read-only diagnostics."""
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops import edr_direct_v4217 as d
from ops import edr_velociraptor as edr

C=d.CID
for response in (
    {'collection': {'flow_id':'F.123456ABCDE'}},
    {'collection': {'FlowId':'F.123456ABCDE'}},
    {'collection': {'session_id':'F.123456ABCDE'}},
    {'collection': {'SessionId':'F.123456ABCDE'}},
    {'collection': '{"session_id":"F.123456ABCDE"}'},
    {'collection': {'flow_id':'F.123456ABCDE','session_id':'F.123456ABCDE'}},
    {'collection': {'session_id':'F.123456ABCDE', 'request': {'client_id':C}}},
):
    assert d._flow_id([response],C)=='F.123456ABCDE', response
for response in (
    {'collection': {'session_id':'F.123456ABCDE','flow_id':'F.ZYXWVUTSRQ1'}},
    {'collection': {'flow_id':'not-a-flow'}},
    {'collection': {'flow_id':'F.123456ABCDE','client_id':'C.ffffffffffffffff'}},
    {'collection': {'flow_id':'F.123456ABCDE','request':{'client_id':'C.ffffffffffffffff'}}},
):
    try: d._flow_id([response],C)
    except RuntimeError: pass
    else: raise AssertionError('Unsafe response accepted: '+str(response))
assert d._flow_id([{'collection': None}],C) is None
assert d._flow_id([{'collection': {}}],C) is None
assert d._response_shape([{'collection':None}])['collection_type']=='NoneType'
assert 'F.123456ABCDE' not in str(d._response_shape([{'collection': {'session_id':'F.123456ABCDE'}}]))
try: d._flow_id([{'collection':{}},{'collection':{}}],C)
except RuntimeError:pass
else:raise AssertionError('Multiple rows accepted')

# No attribution of an old/manual quarantine flow to an unverified dispatch.
raw=[{'FlowId':'F.123456ABCDE', 'ClientId':C,
      'Request': {'Artifacts':['Windows.Remediation.Quarantine']}},
     {'FlowId':'F.987654ABCDE', 'ClientId':C,
      'Request': {'Artifacts':['Generic.Client.Info']}}]
with patch.object(edr,'api_query',return_value=raw):
    found=d._recent_quarantine_flows('001',C)
    assert found['readback']=='ok'
    assert len(found['candidates'])==1
    assert found['candidates'][0]['attribution']=='candidate_only_not_verified'
with patch.object(edr,'api_query',side_effect=RuntimeError('offline')):
    found=d._recent_quarantine_flows('001',C)
    assert found['readback']=='unavailable' and not found['candidates']

# Clearing a lease requires BOTH explicit acknowledgment flags.
from tempfile import TemporaryDirectory
with TemporaryDirectory() as tmp:
    path=Path(tmp)/'direct.json'
    import json
    path.write_text(json.dumps({'001':{'client_id':C,'source':'operator_direct_lab_not_ai',
        'state':'dispatch_uncertain_keep_recovery'}}))
    with patch.object(d,'PATH',path),patch.object(d,'_identity',return_value=C),         patch.object(edr,'require_root'),patch.object(edr,'lease_lock',return_value=__import__('contextlib').nullcontext()),         patch.object(edr,'atomic_json',side_effect=lambda p, obj: p.write_text(json.dumps(obj))):
        for opts in ({'confirm':True},{'endpoint_restored':True},{}):
            try:d.clear('001',**opts)
            except PermissionError:pass
            else:raise AssertionError('Lease improperly cleared')
        assert d.clear('001',confirm=True,endpoint_restored=True)['lease_cleared']
        assert json.loads(path.read_text())=={}
print('PASS V4.2.18: flow schema aliases, ownership, read-only flow candidates and clear safeguards')
