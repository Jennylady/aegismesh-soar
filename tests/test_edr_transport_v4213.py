#!/usr/bin/env python3
"""Mocked VQL patch-preview tests; no live Velociraptor or endpoint access."""
from pathlib import Path
from unittest.mock import patch
import copy, sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr
N='Windows.Remediation.QuarantineMonitor'
base={'artifacts':{'artifacts':['Generic.Client.Stats']},'label_events':[
    {'label':'Quarantine', 'artifacts': {'artifacts':[N]}}
]}
class Lock:
    def __enter__(self): return self
    def __exit__(self,*args): return False
class PreviewFake:
    def __init__(self, fail): self.calls=[];self.fail=fail
    def __call__(self, query):
        self.calls.append(query)
        if query==edr.READ_MONITORING:
            return [{'monitoring': copy.deepcopy(base)}]
        if query == edr.WG_MONITOR_PREVIEW_QUERIES[(0,False)]:
            if self.fail: return [{'monitoring':None}]
            c=copy.deepcopy(base)
            c['label_events'][0]['artifacts']['specs']=[{
              'artifact':N,'parameters':{'env':[{'key':'RuleLookupTable','value':edr.WG_LAB_RULE_TABLE}]}}]
            return [{'monitoring':c}]
        if query == edr.WG_MONITOR_PATCH_QUERIES[(0,False)]:
            return [{'result':True}] # simulates nonpersistent server
        raise AssertionError('unexpected VQL')
for fail in (False,True):
    api=PreviewFake(fail)
    with (patch.object(edr,'require_root'),
          patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
          patch.object(edr,'api_query',side_effect=api),
          patch.object(edr,'lease_lock',return_value=Lock()),
          patch.object(edr,'read_json',return_value={}),
          patch.object(edr,'api_clients',return_value=[]),
          patch.object(edr,'labels_for',return_value=[])):
        result=lab.transport_diagnose('001')
        assert result['read_only'] and not result['server_write_attempted']
        assert result['patch_preview_valid'] is (not fail)
        assert not any(q in edr.WG_MONITOR_PATCH_QUERIES.values() for q in api.calls)
        try: lab.transport_ensure('001',confirm=True)
        except RuntimeError as e:
            if fail: assert 'Prévisualisation' in str(e)
            else: assert 'NON persistée' in str(e)
        else: raise AssertionError('Unsafe acceptance of unconfirmed write')
        if fail: assert not any(q in edr.WG_MONITOR_PATCH_QUERIES.values() for q in api.calls)
print('PASS V4.2.13: server VQL patch-preview read-only, persistence failures fail-closed')
