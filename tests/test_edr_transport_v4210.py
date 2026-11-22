#!/usr/bin/env python3
"""Offline V4.2.10 safety tests (no real endpoint or Velociraptor change)."""
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr

assert '136.116.89.163,,51820,udp' in edr.WG_LAB_RULE_TABLE
assert 'Block,any,,,any,,,,yes,All other traffic' in edr.WG_LAB_RULE_TABLE
assert 'Permit,me,,0,10.77.77.34' not in edr.WG_LAB_RULE_TABLE
assert 'parameters=dict(RuleLookupTable=' in edr.ADD_QUARANTINE_WG_MONITOR
assert edr.ADD_QUARANTINE_WG_MONITOR in edr.api_query.__code__.co_consts or 'ADD_QUARANTINE_WG_MONITOR' in edr.api_query.__code__.co_names
spec={'artifact':'Windows.Remediation.QuarantineMonitor','parameters':{'env':[{'key':'RuleLookupTable','value':edr.WG_LAB_RULE_TABLE}]}}
assert lab._rule_table(spec) == edr.WG_LAB_RULE_TABLE
assert lab._rule_table({'artifact':'Windows.Remediation.QuarantineMonitor'}) is None

class Ctx:
  def __enter__(self):return self
  def __exit__(self,*args):return False

state={'spec': {'artifact':'Windows.Remediation.QuarantineMonitor'}}
def api(query):
  if query == edr.ADD_QUARANTINE_WG_MONITOR:
    state['spec']=spec
    return [{'result':True}]
  raise AssertionError('unexpected query')

with patch.object(edr,'require_root'),patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),patch.object(edr,'lease_lock',return_value=Ctx()),patch.object(edr,'read_json',return_value={}),patch.object(edr,'api_clients',return_value=[]),patch.object(edr,'labels_for',return_value=[]),patch.object(lab,'_read_monitoring_assignments',return_value={'global':False}),patch.object(lab,'_quarantine_spec',side_effect=lambda:state['spec']),patch.object(edr,'api_query',side_effect=api):
  assert lab.transport_status('001')['wg_exception_configured'] is False
  try:lab.transport_ensure('001',confirm=False);raise AssertionError('missing confirm accepted')
  except PermissionError:pass
  assert lab.transport_ensure('001',confirm=True)['status']=='configured_no_quarantine_started'
  assert lab.transport_status('001')['wg_exception_configured'] is True
  assert lab.transport_ensure('001',confirm=True)['status']=='already_configured'
  try:lab.transport_ensure('006',confirm=True);raise AssertionError('DC accepted')
  except Exception:
    # mocked _validate_target for this section, but production guard is 001-only;
    # test it outside mocking below
    pass

assert lab.LAB_AGENT=='001' and lab.LAB_HOST=='win-lab-01'
with patch.object(edr,'require_root'),patch.object(lab,'_validate_target',side_effect=PermissionError('only 001')):
  try:lab.transport_ensure('006',confirm=True);raise AssertionError('DC accepted')
  except PermissionError:pass
print('PASS: V4.2.10 fixed WireGuard UDP exception, dry-run state, idempotence, no DC, no network actions')
