#!/usr/bin/env python3
"""V4.2.19 least-privilege ACL window tests; no real Docker/systemd calls."""
import sys,datetime as dt
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ops import edr_acl_v4219 as acl
from ops import edr_velociraptor as edr

assert acl.PRINCIPAL=='AEGISMESH_SOAR_API'
assert acl.WINDOW_SECONDS==720
assert 'edr-acl-expiry' in acl.TIMER
assert 'EXECVE' not in (Path(__file__).resolve().parents[1]/'ops/edr_setup_v371.py').read_text().split("API_NAME='AEGISMESH_SOAR_API'")[1].split("def run")[0]
for invalid in ({'roles':['administrator','api']}, {'roles':['api']}, {'roles':['api','investigator'],'server_admin':True}, {'roles':['api','investigator'],'execve':True}):
    try:acl._baseline(invalid)
    except PermissionError:pass
    else:raise AssertionError('unsafe policy accepted: '+str(invalid))
acl._baseline({'roles':['api','investigator'],'max_upload_bytes':0})

class ACLBackend:
    def __init__(self):
        self.policy={'roles':['api','investigator']};self.effective={'collect_client':True,'execve':False,'network':False};self.events=[];self.saved={}
    def policy_read(self,c,m,effective=False):return self.effective.copy() if effective else self.policy.copy()
    def grant(self,c,m,p):
        self.events.append('grant');self.policy.update(p)
    def replace(self,c,m,p):
        self.events.append('restore');self.policy=p.copy()
    def restart(self,c):
        self.events.append('restart')
        self.effective['execve']=self.policy.get('execve',False)
        self.effective['network']=self.policy.get('network',False)
    def save(self,path,obj):
        assert path==acl.STATE
        self.saved=obj.copy()
    def read(self):return self.saved.copy()

backend=ACLBackend()
patches=[
 patch.object(edr,'require_root'),
 patch.object(acl,'_container',return_value=({'container':'velo'}, {'binary':'/usr/bin/velociraptor','server_config':'/config/server.yaml'})),
 patch.object(acl,'_show',side_effect=backend.policy_read),
 patch.object(acl,'_grant',side_effect=backend.grant),
 patch.object(acl,'_replace',side_effect=backend.replace),
 patch.object(acl,'_restart',side_effect=backend.restart),
 patch.object(acl,'_read',side_effect=backend.read),
 patch.object(edr,'atomic_json',side_effect=backend.save),
 patch.object(acl,'_timer_files',side_effect=lambda:backend.events.append('timer')),
 patch('ops.edr_direct_v4217._read',return_value={}),
 patch.object(edr,'read_json',return_value={}),
 ]
with patches[0],patches[1],patches[2],patches[3],patches[4],patches[5],patches[6],patches[7],patches[8],patches[9],patches[10]:
    for opts in ({},{'confirm':True},{'allow_restart':True}):
        try:acl.enable(**opts)
        except PermissionError:pass
        else:raise AssertionError('grant accepted without both guards')
    assert not backend.events
    result=acl.enable(confirm=True,allow_restart=True)
    assert result['status']=='temporary_acl_verified' and result['rollback_timer_enabled']
    assert backend.events[:3]==['timer','grant','restart']
    assert backend.policy=={'roles':['api','investigator'],'execve':True,'network':True}
    assert backend.saved['original_policy']=={'roles':['api','investigator']}
    assert acl.require_active_lab_acl()
    stat=acl.info();assert stat['temporary_acl_active']
    for opts in ({},{'confirm':True}):
        try:acl.restore(**opts)
        except PermissionError:pass
        else:raise AssertionError('restore accepted without guards')
    res=acl.restore(confirm=True,allow_restart=True)
    assert res['status']=='original_acl_restored' and backend.saved=={}
    assert backend.policy=={'roles':['api','investigator']}
    assert backend.effective['execve'] is False and backend.effective['network'] is False

# Expiration happens without explicit permission to restart, guarded by expiry.
backend2=ACLBackend();backend2.policy={'roles':['api','investigator'],'execve':True,'network':True}
backend2.effective.update({'execve':True,'network':True})
backend2.saved={'principal':acl.PRINCIPAL,'original_policy':{'roles':['api','investigator']},
   'expires_at':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=3)).isoformat()}
with (patch.object(edr,'require_root'),
      patch.object(acl,'_container',return_value=({'container':'velo'}, {'binary':'v','server_config':'c'})),
      patch.object(acl,'_show',side_effect=backend2.policy_read),
      patch.object(acl,'_replace',side_effect=backend2.replace),
      patch.object(acl,'_restart',side_effect=backend2.restart),
      patch.object(acl,'_read',side_effect=backend2.read),
      patch.object(edr,'atomic_json',side_effect=backend2.save)):
    assert acl.expire()['auto'] is True
    assert backend2.saved=={} and not backend2.effective['execve']

for name in (acl.TIMER,acl.SERVICE):
    u=(Path(__file__).resolve().parents[1]/'ops/systemd'/name).read_text()
    assert acl.OWNER in u and 'ExecStart=/usr/bin/python3' in (Path(__file__).resolve().parents[1]/'ops/systemd'/acl.SERVICE).read_text()
assert 'require_active_lab_acl()' in (Path(__file__).resolve().parents[1]/'ops/edr_direct_v4217.py').read_text()
assert "subargs[0]=='lab-acl'" in (Path(__file__).resolve().parents[1]/'bin/aegismesh-soar').read_text()
print('PASS V4.2.19: verified, time-bounded ACL elevation, targeted account, independent expiry and exact restore (mocked)')
