#!/usr/bin/env python3
"""V4.2.11 regression: read real protobuf shapes; no endpoint contact."""
from pathlib import Path
from unittest.mock import patch
import json, sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr

NAME = 'Windows.Remediation.QuarantineMonitor'

def monitor(names=None, specs=None, label='Quarantine'):
    return [{'monitoring': {
        'label_events': [{'label':label,
                         'artifacts': {'artifacts':names or [], 'specs':specs or []}}],
        'artifacts': {'artifacts': ['Other.Service'], 'specs': []}
    }}]

def expected_fail(payload):
    with patch.object(edr, 'api_query', return_value=payload):
        try: lab._quarantine_spec()
        except (RuntimeError, ValueError, PermissionError): pass
        else: raise AssertionError('Unexpected monitor accepted')

# Proto model: configured monitor with DEFAULT parameters appears only in
# artifacts.artifacts; no Artifacts.specs entry is required.
with patch.object(edr, 'api_query', return_value=monitor(names=[NAME])):
    assert lab._quarantine_spec()=={'artifact': NAME}
    assert lab._rule_table(lab._quarantine_spec()) is None
    assert lab.monitor_assigned_to_quarantine()
# Spec-only (earlier edition), both forms, and JSON-string server response.
spec={'artifact': NAME, 'parameters': {'env': [{'key': 'RuleLookupTable', 'value': edr.WG_LAB_RULE_TABLE}]}}
for payload in (monitor(specs=[spec]),monitor(names=[NAME],specs=[spec]),
                [{'monitoring': json.dumps(monitor(names=[NAME],specs=[spec])[0]['monitoring'])}]):
    with patch.object(edr, 'api_query', return_value=payload):
        assert lab._quarantine_spec()==spec
        assert lab._rule_table(lab._quarantine_spec()) == edr.WG_LAB_RULE_TABLE
        assert lab.monitor_assigned_to_quarantine()
# Duplicates, unexpected type, missing and unrelated labels always fail closed.
for bad in (monitor(names=[NAME,NAME]), monitor(specs=[spec,spec]),
            monitor(names=['Other']), monitor(names=[NAME],label='Other'),
            monitor(names=[NAME],specs='broken'),monitor(names='broken'),
            [{'monitoring': {'label_events': []}}],
            [{'monitoring': '{not-json'}], []):
    expected_fail(bad)

# The V4.2.10 bug: start can be called even after transport-ensure fails.
# V4.2.11 must refuse before any label or lease mutation.
with (patch.object(edr,'require_root'),
      patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
      patch.object(lab,'_quarantine_spec',return_value={'artifact': NAME}),
      patch.object(edr,'lease_lock') as lock,
      patch.object(edr,'modify_label') as label,
      patch.object(edr,'atomic_json') as save):
    try: lab.start('001',confirm=True,console_access=True)
    except PermissionError as exc:
        assert 'WireGuard' in str(exc)
    else: raise AssertionError('Quarantine accepted without WG transport')
    lock.assert_not_called();label.assert_not_called();save.assert_not_called()

# After a successful transport update, the normal dry-run tests may continue.
print('PASS V4.2.11: name-only, spec-only, dual proto representations; duplicates blocked; quarantine fails closed without transport')
# Transport inspect returns only counts, never raw RuleLookupTable contents.
with patch.object(edr, 'require_root'), patch.object(lab, '_validate_target', return_value=lab.LAB_CLIENT), patch.object(edr,'api_query',return_value=monitor(names=[NAME])):
    shape=lab.transport_inspect('001')
    assert shape['quarantine_group_count']==1
    assert shape['groups'][0]['name_matches_count']==1
    assert shape['groups'][0]['spec_matches_count']==0
    assert 'RuleLookupTable' not in json.dumps(shape)

# Existing non-transport custom parameters must not be overwritten by ensure.
class DummyLock:
    def __enter__(self): return self
    def __exit__(self, *_): return False
with (patch.object(edr,'require_root'),
      patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
      patch.object(edr,'lease_lock',return_value=DummyLock()),
      patch.object(edr,'read_json',return_value={}),
      patch.object(edr,'api_clients',return_value=[]),
      patch.object(edr,'labels_for',return_value=[]),
      patch.object(lab,'_read_monitoring_assignments',return_value={'global': False}),
      patch.object(lab,'_quarantine_spec',return_value={'artifact':NAME, 'parameters': {'env':[{'key':'ReloadPeriod','value':'90'}]}}),
      patch.object(edr,'api_query') as api):
    try: lab.transport_ensure('001',confirm=True)
    except PermissionError as exc:
        assert 'paramètres' in str(exc)
    else: raise AssertionError('Other custom parameters overwritten')
    api.assert_not_called()
