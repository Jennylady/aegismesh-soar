#!/usr/bin/env python3
"""Test full V4.2.14 fallback, read-only validation, and write safety."""
import copy,sys,json
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr
N='Windows.Remediation.QuarantineMonitor'
base={'artifacts':{'artifacts':['Generic.Client.Stats']},'label_events':[
 {'label':'Monitoring','artifacts':{'artifacts':['Windows.Events.Security']}},
 {'label':'Quarantine','artifacts':{'artifacts':[N]}}]}
spec={'artifact':N,'parameters':{'env':[{'key':'RuleLookupTable','value':edr.WG_LAB_RULE_TABLE}]}}
class Lock:
 def __enter__(self): return self
 def __exit__(self,*args): return False
class API:
 def __init__(self,fail_typed=False): self.state=copy.deepcopy(base);self.calls=[];self.fail_typed=fail_typed
 def __call__(self,q):
  self.calls.append(q)
  if q==edr.READ_MONITORING: return [{'monitoring':copy.deepcopy(self.state)}]
  if q==edr.WG_MONITOR_PREVIEW_QUERIES[(1,False)]:
   bad=copy.deepcopy(self.state);bad['label_events'][1]['artifacts']['specs']={'unexpected':'map'}
   return [{'monitoring':bad}]
  if q==edr.WG_MONITOR_JSON_PREVIEW_QUERIES[(1,False)]:
   if self.fail_typed:return [{'monitoring':None}]
   good=copy.deepcopy(self.state);good['label_events'][1]['artifacts']['specs']=[copy.deepcopy(spec)]
   return [{'monitoring':good}]
  if q==edr.WG_MONITOR_JSON_PATCH_QUERIES[(1,False)]:
   if self.fail_typed:raise AssertionError('write should have been blocked')
   self.state['label_events'][1]['artifacts']['specs']=[copy.deepcopy(spec)]
   return [{'result':True}]
  raise AssertionError('unexpected query '+q[:100])
for fail in (False,True):
 api=API(fail)
 with (patch.object(edr,'require_root'),patch.object(lab,'_validate_target',return_value=lab.LAB_CLIENT),
       patch.object(edr,'lease_lock',return_value=Lock()),patch.object(edr,'read_json',return_value={}),
       patch.object(edr,'api_clients',return_value=[]),patch.object(edr,'labels_for',return_value=[]),
       patch.object(edr,'api_query',side_effect=api)):
  d=lab.transport_diagnose('001')
  assert d['read_only'] and not d['server_write_attempted']
  assert d['patch_preview_valid']==(not fail)
  assert any(q in edr.WG_MONITOR_JSON_PREVIEW_QUERIES.values() for q in api.calls)
  assert not any(q in edr.WG_MONITOR_JSON_PATCH_QUERIES.values() for q in api.calls)
  assert 'RuleLookupTable' not in json.dumps(d)
  if fail:
   try:lab.transport_ensure('001',confirm=True)
   except RuntimeError as e: assert 'Prévisualisation' in str(e)
   else:raise AssertionError('invalid preview accepted')
   assert not any(q in edr.WG_MONITOR_JSON_PATCH_QUERIES.values() for q in api.calls)
  else:
   assert d['patch_variant']=='json_rfc6902'
   assert d['legacy_preview_failures'][0]['shape']['specs_type']=='dict'
   original=copy.deepcopy(api.state['label_events'][0])
   r=lab.transport_ensure('001',confirm=True)
   assert r['wg_exception_configured'] is True and r['patch_variant']=='json_rfc6902'
   assert api.state['label_events'][0]==original
   assert sum(q==edr.WG_MONITOR_JSON_PATCH_QUERIES[(1,False)] for q in api.calls)==1
for bad in (-1,16,99,'1'):
 try:edr._wg_monitor_json_patch_vql(bad)
 except PermissionError:pass
 else:raise AssertionError('unsafe index')
for append in (False,True):
 q=edr.WG_MONITOR_JSON_PREVIEW_QUERIES[(1,append)]
 assert 'parse_json_array(data=' in q and 'set_client_monitoring' not in q
 assert '136.116.89.163' in q and '51820' in q
print('PASS V4.2.14: typed JSON RFC6902 preview and strict readback; no write unless valid')
