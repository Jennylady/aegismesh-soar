#!/usr/bin/env python3
"""V4.2.12: regression tests for updating an EXISTING monitoring artifact.

Never runs a real API query or changes an endpoint. The Velociraptor response is
modelled after the observed get_client_monitoring: names list with specs absent.
"""
import copy
import json
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr

NAME = 'Windows.Remediation.QuarantineMonitor'
OTHER = 'Windows.Events.Security'

def baseline(*, group_index=1, specs=None):
    q = {'label':'Quarantine','artifacts': {'artifacts': [NAME]}}
    if specs is not None:
        q['artifacts']['specs'] = copy.deepcopy(specs)
    groups = [{'label': 'Monitoring', 'artifacts': {'artifacts': [OTHER]}}]
    if group_index == 0:
        groups.insert(0, q)
    else:
        groups.append(q)
    return {
        'artifacts': {'artifacts': ['Generic.Client.Stats']},
        'label_events': groups,
        'custom_field': {'untouched': True}
    }

class Lock:
    def __enter__(self): return self
    def __exit__(self, *args): return False

class FakeVelociraptor:
    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, query):
        self.calls.append(query)
        if query == edr.READ_MONITORING:
            return [{'monitoring':copy.deepcopy(self.table)}]
        is_preview = query in edr.WG_MONITOR_PREVIEW_QUERIES.values()
        pool = edr.WG_MONITOR_PREVIEW_QUERIES if is_preview else edr.WG_MONITOR_PATCH_QUERIES
        assert query in pool.values(), 'unexpected VQL'
        index, append = next(k for k,v in pool.items() if v == query)
        table = copy.deepcopy(self.table) if is_preview else self.table
        specs = table['label_events'][index]['artifacts'].setdefault('specs', [])
        assert append == bool(specs)
        specs.append({'artifact': NAME, 'parameters': {'env': [{'key':'RuleLookupTable','value': edr.WG_LAB_RULE_TABLE}]}})
        return [{'monitoring': table}] if is_preview else [{'result': True}]

for index in (0,1):
    for original_specs in (None, [{'artifact': 'Other.Event', 'parameters': {'env': [{'key':'Severity','value':'high'}]}}]):
        original = baseline(group_index=index, specs=original_specs)
        api = FakeVelociraptor(copy.deepcopy(original))
        with (patch.object(edr,'require_root'),
              patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
              patch.object(edr,'lease_lock',return_value=Lock()),
              patch.object(edr,'read_json',return_value={}),
              patch.object(edr,'api_clients',return_value=[]),
              patch.object(edr,'labels_for',return_value=[]),
              patch.object(edr,'api_query',side_effect=api)):
            assert lab.transport_status('001')['wg_exception_configured'] is False
            result = lab.transport_ensure('001',confirm=True)
            assert result['status'] == 'configured_no_quarantine_started'
            assert result['wg_exception_configured'] is True
            assert lab.transport_ensure('001',confirm=True)['status'] == 'already_configured'
            assert api.table['artifacts'] == original['artifacts']
            assert api.table['custom_field'] == original['custom_field']
            assert len(api.table['label_events']) == len(original['label_events'])
            other_idx = 1-index
            assert api.table['label_events'][other_idx] == original['label_events'][other_idx]
            assert api.table['label_events'][index]['artifacts']['artifacts'] == [NAME]
            assert len([s for s in api.table['label_events'][index]['artifacts']['specs'] if s.get('artifact') == NAME]) == 1
            assert api.calls.count(edr.WG_MONITOR_PATCH_QUERIES[(index, bool(original_specs))]) == 1
            assert api.calls.count(edr.WG_MONITOR_PREVIEW_QUERIES[(index, bool(original_specs))]) == 1

# No arbitrary VQL: only fixed, bounded group indexes and fixed allowlisted values.
for bad_index in (-1,16,99, '1'):
    try: edr._wg_monitor_patch_vql(bad_index)
    except PermissionError: pass
    else: raise AssertionError('unsafe monitoring index accepted')
for index in (0,1,15):
    for append in (False,True):
        query = edr.WG_MONITOR_PATCH_QUERIES[(index,append)]
        assert query.startswith('SELECT set_client_monitoring(value=patch(item=get_client_monitoring()')
        assert f'/label_events/{index}/artifacts/specs' in query
        assert '136.116.89.163' in query and '51820,udp' in query
        assert 'SELECT patch(item=get_client_monitoring()' in edr.WG_MONITOR_PREVIEW_QUERIES[(index,append)]
        assert 'Block,any,,,any,,,,yes,All other traffic' in query

# Refuse unexpected existing custom parameters before mutation.
state = baseline(group_index=1, specs=[{'artifact': NAME, 'parameters': {'env': [{'key':'ReloadPeriod','value':'90'}]}}])
api=FakeVelociraptor(state)
with (patch.object(edr,'require_root'),
      patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
      patch.object(edr,'lease_lock',return_value=Lock()),
      patch.object(edr,'read_json',return_value={}),
      patch.object(edr,'api_clients',return_value=[]),
      patch.object(edr,'labels_for',return_value=[]),
      patch.object(edr,'api_query',side_effect=api)):
    try: lab.transport_ensure('001',confirm=True)
    except PermissionError: pass
    else: raise AssertionError('custom monitor silently replaced')
    assert not any(q in edr.WG_MONITOR_PATCH_QUERIES.values() for q in api.calls)

# Guard rails: active leases and quarantine labels prevent changes.
for leases, labels in (({'001': {'source':'operator_lab_real'}},[]),({},['Quarantine'])):
    api=FakeVelociraptor(baseline())
    with (patch.object(edr,'require_root'),
          patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
          patch.object(edr,'lease_lock',return_value=Lock()),
          patch.object(edr,'read_json',return_value=leases),
          patch.object(edr,'api_clients',return_value=[]),
          patch.object(edr,'labels_for',return_value=labels),
          patch.object(edr,'api_query',side_effect=api)):
        try: lab.transport_ensure('001',confirm=True)
        except PermissionError: pass
        else: raise AssertionError('quarantine guard bypassed')
        assert not any(q in edr.WG_MONITOR_PATCH_QUERIES.values() for q in api.calls)

print('PASS V4.2.12: targeted set_client_monitoring patch, preserve other groups, strict readback, safety guards')
