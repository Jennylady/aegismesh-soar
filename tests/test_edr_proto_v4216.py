#!/usr/bin/env python3
"""V4.2.16: Protobuf default-valued extras allowed, custom settings fail closed."""
import sys, copy
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr

MON='Windows.Remediation.QuarantineMonitor'
DEFAULTS={'max_batch_wait':0,'max_batch_rows':0,'resources':{},'max_wait':'','urgent':False,'unset':None,'windows':[]}
report=lab._quarantine_proto_extras_v4216({'artifacts':[MON],**DEFAULTS})
assert report['safe_default_only'] is True
assert report['nondefault_extra_keys']==[]
assert set(report['extra_keys'])==set(DEFAULTS)

for setting in ({'max_batch_wait':100}, {'custom':{'limit':20}}, {'custom':['one']}, {'secret':'value'}, {'max_batch_rows':-1}):
    report=lab._quarantine_proto_extras_v4216({'artifacts':[MON],**setting})
    assert report['safe_default_only'] is False
    assert len(report['nondefault_extra_keys']) == 1
    assert 'value' not in str(report)

class Lock:
    def __enter__(self):return self
    def __exit__(self,*_):return False

class API:
    def __init__(self, extras):
        self.state={'artifacts':{'artifacts':['Generic.Client.Stats']},
          'label_events':[{'label':'Quarantine','artifacts':{'artifacts':[MON],**copy.deepcopy(extras)}}]}
        self.calls=[]
    def __call__(self,q):
        self.calls.append(q)
        if q==edr.READ_MONITORING:
            return [{'monitoring':copy.deepcopy(self.state)}]
        if q==edr.RM_QUARANTINE_MONITOR:
            self.state['label_events']=[]
            return [{'result':True}]
        if q==edr.ADD_QUARANTINE_WG_MONITOR:
            self.state['label_events']=[{'label':'Quarantine','artifacts':{'artifacts':[MON],
                'specs':[{'artifact':MON,'parameters':{'env':[{'key':'RuleLookupTable','value':edr.WG_LAB_RULE_TABLE}]}}]}}]
            return [{'result':True}]
        raise AssertionError(q)

for extras, permitted in [(DEFAULTS,True),({'max_batch_wait':200},False)]:
    api=API(extras)
    with (patch.object(edr,'require_root'),
          patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
          patch.object(lab,'_read_monitoring_assignments',return_value={'global':False,'labels':['Quarantine']}),
          patch.object(edr,'lease_lock',return_value=Lock()),
          patch.object(edr,'read_json',return_value={}),
          patch.object(edr,'api_clients',return_value=[]),
          patch.object(edr,'labels_for',return_value=[]),
          patch.object(edr,'atomic_json') as backup,
          patch.object(edr,'api_query',side_effect=api)):
        report=lab.transport_inspect('001')
        metadata=report['groups'][0]['proto_metadata']
        assert metadata['safe_default_only']==permitted
        assert report['read_only'] is True
        if permitted:
            output=lab.transport_repair('001',confirm=True)
            assert output['wg_exception_configured'] is True
            assert edr.RM_QUARANTINE_MONITOR in api.calls
            assert edr.ADD_QUARANTINE_WG_MONITOR in api.calls
            backup.assert_called_once()
        else:
            try:lab.transport_repair('001',confirm=True)
            except PermissionError as ex:
                assert 'max_batch_wait' in str(ex)
            else:raise AssertionError('Nondefault metadata was deleted')
            assert edr.RM_QUARANTINE_MONITOR not in api.calls
            assert edr.ADD_QUARANTINE_WG_MONITOR not in api.calls
            backup.assert_not_called()

assert edr.WG_LAB_TRANSPORT_IP=='136.116.89.163'
assert '10.77.77.1,,8000,tcp' in edr.WG_LAB_RULE_TABLE
print('PASS V4.2.16: protobuf metadata inspection and safe scoped repair; mocked only')
