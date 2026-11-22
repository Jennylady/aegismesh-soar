#!/usr/bin/env python3
"""V4.2.15: controlled Quarantine-only rm/add and rollback tests (all mocked)."""
import copy, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr

MON = 'Windows.Remediation.QuarantineMonitor'
BEFORE = {
  'artifacts': {'artifacts':['Generic.Client.Stats']},
  'label_events': [
    {'label':'Other','artifacts':{'artifacts':['Windows.Events.Security']}},
    {'label':'Quarantine','artifacts':{'artifacts':[MON]}},
  ],
}
class Lock:
    def __enter__(self): return self
    def __exit__(self,*_): return False
class API:
    def __init__(self, mode='success'):
        self.state=copy.deepcopy(BEFORE)
        self.mode=mode
        self.calls=[]
    def __call__(self,q):
        self.calls.append(q)
        if q==edr.READ_MONITORING:
            return [{'monitoring':copy.deepcopy(self.state)}]
        if q==edr.RM_QUARANTINE_MONITOR:
            if self.mode=='rm_fail':raise RuntimeError('denied')
            self.state['label_events']=[x for x in self.state['label_events'] if x['label']!='Quarantine']
            return [{'result': True}]
        if q==edr.ADD_QUARANTINE_WG_MONITOR:
            if self.mode=='add_fail': raise RuntimeError('denied add')
            self.state['label_events'].append({'label':'Quarantine', 'artifacts':{
                'artifacts':[MON], 'specs':[{'artifact':MON, 'parameters':{
                'env':[{'key':'RuleLookupTable','value':edr.WG_LAB_RULE_TABLE}]}}]}})
            return [{'result': True}]
        if q==edr.ADD_QUARANTINE_MONITOR:
            self.state['label_events'].append({'label':'Quarantine', 'artifacts':{'artifacts':[MON]}})
            return [{'result': True}]
        raise AssertionError('Unexpected VQL: '+q[:140])

# Mock only the system boundary. All actual safety and repair code is exercised.
for mode in ('success','add_fail','rm_fail'):
    api=API(mode)
    with (patch.object(edr,'require_root'),
          patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
          patch.object(lab,'_read_monitoring_assignments',return_value={'global':False,'labels':['Quarantine']}),
          patch.object(edr,'lease_lock',return_value=Lock()),
          patch.object(edr,'read_json',return_value={}),
          patch.object(edr,'api_clients',return_value=[]),
          patch.object(edr,'labels_for',return_value=[]),
          patch.object(edr,'atomic_json') as backup,
          patch.object(edr,'api_query',side_effect=api)):
        if mode=='success':
            result=lab.transport_repair('001',confirm=True)
            assert result['wg_exception_configured'] is True
            assert result['endpoint_network_isolation_verified'] is False
            assert edr.ADD_QUARANTINE_WG_MONITOR in api.calls
            assert edr.ADD_QUARANTINE_MONITOR not in api.calls
            assert lab.transport_status('001')['wg_exception_configured'] is True
        else:
            try:lab.transport_repair('001',confirm=True)
            except RuntimeError as e:
                assert ('restauré' in str(e) or 'restauration' in str(e))
            else:raise AssertionError('Failure must be surfaced')
            assert lab._rule_table(lab._quarantine_spec(api.state)) is None
            if mode=='add_fail':
                assert edr.ADD_QUARANTINE_MONITOR in api.calls
            if mode=='rm_fail':
                assert edr.ADD_QUARANTINE_MONITOR not in api.calls
        assert api.state['artifacts']==BEFORE['artifacts']
        assert api.state['label_events'][0]==BEFORE['label_events'][0]
        backup.assert_called_once()
        assert str(backup.call_args.args[0]).endswith('edr-quarantine-monitor-backup-v4215.json')
        assert not any('label(' in q or 'collect_client(' in q for q in api.calls)

# No changes without consent and never to the Domain Controller 006.
with patch.object(edr,'require_root'):
    for agent, confirm in [('001',False),('006',True)]:
        try:lab.transport_repair(agent,confirm=confirm)
        except PermissionError:pass
        else:raise AssertionError('Missing confirmation / DC guard bypass')

# Active lab quarantine blocks any mutation.
api=API()
with (patch.object(edr,'require_root'), patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
      patch.object(edr,'lease_lock',return_value=Lock()),
      patch.object(edr,'read_json',return_value={'001':{'decision_id':'lab-xyz'}}),
      patch.object(edr,'api_query',side_effect=api)):
    try:lab.transport_repair('001',confirm=True)
    except PermissionError: pass
    else: raise AssertionError('Active lease bypass')
assert api.calls==[]

# Any extra artifact in Quarantine means no removal or re-addition.
api=API()
api.state['label_events'][1]['artifacts']['artifacts'].append('Other.Event')
with (patch.object(edr,'require_root'), patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
      patch.object(lab,'_read_monitoring_assignments',return_value={'global':False,'labels':['Quarantine']}),
      patch.object(edr,'lease_lock',return_value=Lock()), patch.object(edr,'read_json',return_value={}),
      patch.object(edr,'api_clients',return_value=[]),patch.object(edr,'labels_for',return_value=[]),
      patch.object(edr,'api_query',side_effect=api)):
    try:lab.transport_repair('001',confirm=True)
    except PermissionError:pass
    else:raise AssertionError('Other artifact unexpectedly removed')
    assert edr.RM_QUARANTINE_MONITOR not in api.calls

# Empty protobuf label_events may be omitted after removing last label group.
with patch.object(edr,'api_query',return_value=[{'monitoring':{'artifacts':{'artifacts':[]}}}]):
    assert lab._read_monitor_table_v4215()['label_events']==[]

assert '10.77.77.1,,8000,tcp,yes,VelociraptorFrontEnd' in edr.WG_LAB_RULE_TABLE
assert '136.116.89.163,,51820,udp,yes,AEGISMESHWireGuardUnderlay' in edr.WG_LAB_RULE_TABLE
assert edr.RM_QUARANTINE_MONITOR in edr.RM_QUARANTINE_MONITOR
assert 'label=\'Quarantine\'' in edr.RM_QUARANTINE_MONITOR
assert edr.ADD_QUARANTINE_WG_MONITOR in edr.ADD_QUARANTINE_WG_MONITOR
print('PASS V4.2.15: scoped remove/add, rollback, DC/lease/multi-artifact guards; no real actions')
