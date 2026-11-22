#!/usr/bin/env python3
"""V4.2.17: mocks may only emulate the Velociraptor/OS boundary."""
import sys, tempfile, datetime as dt, copy
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ops import edr_direct_v4217 as direct
from ops import edr_velociraptor as edr

assert 'Windows.Remediation.Quarantine' in edr.DIRECT_QUARANTINE_COLLECT
assert 'RuleLookupTable' in edr.DIRECT_QUARANTINE_COLLECT
assert '136.116.89.163' in edr.DIRECT_QUARANTINE_COLLECT
assert '51820,udp' in edr.DIRECT_QUARANTINE_COLLECT
assert '10.77.77.1,,8000,tcp' in edr.DIRECT_QUARANTINE_COLLECT
assert 'RemovePolicy=TRUE' in edr.DIRECT_QUARANTINE_REMOVE
assert edr.DIRECT_QUARANTINE_COLLECT != edr.DIRECT_QUARANTINE_REMOVE
assert all(token not in edr.DIRECT_QUARANTINE_COLLECT for token in ('add_client_monitoring','set_client_monitoring','label('))

class Lock:
    def __enter__(self): return self
    def __exit__(self,*_): return False
class API:
    def __init__(self, start_returns=True):self.calls=[];self.start_returns=start_returns
    def __call__(self,q,env):
        self.calls.append((q,env))
        if q==edr.DIRECT_QUARANTINE_COLLECT:
            return [{'collection':{'flow_id':'F.ABCDEF12345'}}] if self.start_returns else [{'collection':None}]
        if q==edr.DIRECT_QUARANTINE_REMOVE:
            return [{'collection':{'flow_id':'F.123456ABCDE'}}]
        raise AssertionError('Unexpected query '+str(q)[:120])

with tempfile.TemporaryDirectory() as tmp:
    path=Path(tmp)/'lab.json'
    api=API()
    def save(p,v):
        assert p==path
        p.write_text(__import__('json').dumps(v))
    def read(p,default):
        if p==path:
            return __import__('json').loads(p.read_text()) if p.exists() else default
        if p==edr.LEASES:return {}
        raise AssertionError(p)
    with (patch.object(direct,'PATH',path),patch.object(edr,'require_root'),
          patch.object(direct,'_identity',return_value=direct.CID),
          patch.object(edr,'timer_active',return_value=True),
          patch.object(edr,'lease_lock',return_value=Lock()),
          patch.object(edr,'read_json',side_effect=read),
          patch.object(edr,'atomic_json',side_effect=save),
          patch.object(edr,'api_clients',return_value=[]),
          patch.object(edr,'labels_for',return_value=[]),
          patch.object(edr,'api_query',side_effect=api)):
        for kwargs in ({},{'confirm':True,'console_access':True}):
            try:direct.start('001',**kwargs)
            except PermissionError:pass
            else:raise AssertionError('Unsafe start accepted')
        assert not api.calls
        started=direct.start('001',confirm=True,console_access=True,recovery_task_armed=True)
        assert started['status']=='dispatched_unverified'
        assert started['endpoint_network_isolation_verified'] is False
        assert started['flow_id']=='F.ABCDEF12345'
        assert len(api.calls)==1
        assert api.calls[0][1]=={'ClientId':direct.CID}
        assert direct.status('001')['direct_lab_lease']['state']=='dispatched_unverified'
        try:direct.start('001',confirm=True,console_access=True,recovery_task_armed=True)
        except PermissionError:pass
        else:raise AssertionError('Duplicate start accepted')
        r=direct.release('001',confirm=True)
        assert r['status']=='release_dispatched_unverified'
        assert r['network_restoration_verified'] is False
        assert len(api.calls)==2
        assert 'RemovePolicy=TRUE' in api.calls[-1][0]
        assert direct.clear('001',confirm=True)['lease_cleared'] is True
        assert not read(path,{})

# Unverified start retains lease to allow expiry even when API result is unclear
with tempfile.TemporaryDirectory() as tmp:
    path=Path(tmp)/'lab.json';api=API(False)
    def save(p,v):p.write_text(__import__('json').dumps(v))
    def read(p,d):return __import__('json').loads(p.read_text()) if p.exists() else d
    with (patch.object(direct,'PATH',path),patch.object(edr,'require_root'),
          patch.object(direct,'_identity',return_value=direct.CID),
          patch.object(edr,'timer_active',return_value=True),
          patch.object(edr,'lease_lock',return_value=Lock()),
          patch.object(edr,'read_json',side_effect=read),
          patch.object(edr,'atomic_json',side_effect=save),
          patch.object(edr,'api_clients',return_value=[]),
          patch.object(edr,'labels_for',return_value=[]),
          patch.object(edr,'api_query',side_effect=api)):
        try:direct.start('001',confirm=True,console_access=True,recovery_task_armed=True)
        except RuntimeError:pass
        else:raise AssertionError('Unverified flow treated as success')
        assert read(path,{})['001']['state']=='dispatch_uncertain_keep_recovery'

# Real agent guard must never permit Domain Controller 006 even if side-effects are mocked.
try:direct._identity('006')
except PermissionError:pass
else:raise AssertionError('Domain Controller not denied')
# Agent scope is checked before root/operation in the public functions.
with patch.object(edr,'require_root'):
    try:direct.doctor('006')
    except PermissionError:pass
    else:raise AssertionError('Doctor DC accepted')

print('PASS V4.2.17: direct LAB EDR flow, rollback, timer and DC guard (mocked)')

# Existing expiry timer must also call dedicated direct expiry, while preserving
# the old label-based release contract. No network operation in this test.
with (patch.object(edr,'require_root'),
      patch.object(edr,'read_json',return_value={}),
      patch.object(direct,'release_expired',return_value={
           'release_count':1,'release_failed':0,'restoration_verified':False}),
      patch('builtins.print') as output):
    assert edr.release_expired()==0
    assert any('direct_lab' in str(x) for x in output.call_args_list)

# Inspect the locally scheduled rollback content. It must be hostname+role
# guarded, strictly scoped to the known IPsec policy and SYSTEM identity.
script=Path(__file__).resolve().parents[1]/'ops/wazuh/windows/Arm-AegisMeshLabIpsecRecovery-v4217.ps1'
pst=script.read_text()
assert 'WIN-LAB-01' in pst and 'DomainRole -ne 1' in pst
assert "name=VelociraptorQuarantine" in pst
assert "-UserId 'SYSTEM'" in pst
assert 'Unregister-ScheduledTask' in pst and 'LastRunTime' in pst
assert 'ad.ikom.mg' not in pst and '10.77.77.34' not in pst
print('PASS V4.2.17: local recovery and expiry timer integration (mocked)')
