#!/usr/bin/env python3
"""EDR Docker onboarding mocked end-to-end. No real docker, credentials or services."""
from pathlib import Path
import sys
from unittest import mock
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ops import edr_setup_v371 as s
from ops import edr_velociraptor as edr

with mock.patch.object(edr,'discovered',return_value=['aegismesh-velociraptor']):
    assert s.selected_container()=='aegismesh-velociraptor'
    try:s.selected_container('NOM_REEL')
    except FileNotFoundError:pass
    else:raise AssertionError('Fake name accepted')

with mock.patch.object(s,'mounts',return_value=[
    {'Type':'tmpfs','Destination':'/run','RW':True},
    {'Type':'bind','Destination':'/etc/velociraptor','RW':False},
    {'Type':'volume','Destination':'/datastore','RW':True},
]), mock.patch.object(s,'run',return_value=SimpleNamespace(returncode=0)):
    assert s.persistent_destination('aegismesh-velociraptor')=='/datastore'

with mock.patch.object(s,'mounts',return_value=[
    {'Type':'bind','Destination':'/etc/velociraptor','RW':False},
]), mock.patch.object(s,'run',return_value=SimpleNamespace(returncode=0)):
    assert s.persistent_destination('aegismesh-velociraptor') is None

meta={'container':'aegismesh-velociraptor','binary':'/usr/local/bin/velociraptor',
      'server_config':'/etc/velociraptor/server.config.yaml',
      'api_configs':['/datastore/aegismesh-soar-api-client.yaml'],
      'persistent_directory':'/datastore'}

with mock.patch.object(edr,'api_query',return_value=[{'hostname':'win-lab-01'}]) as api, \
     mock.patch.object(edr,'atomic_json') as save:
    assert s.connect_existing(meta)=='/datastore/aegismesh-soar-api-client.yaml'
    assert api.call_count==2
    save.assert_called_once()

with mock.patch.object(edr,'api_query',side_effect=RuntimeError('connection refused')), \
     mock.patch.object(edr,'atomic_json') as save:
    try:s.connect_existing(meta)
    except RuntimeError:pass
    else:raise AssertionError('Dead API registered')
    save.assert_not_called()

try:s.bootstrap(meta,allow_restart=False)
except PermissionError:pass
else:raise AssertionError('Unsafe restart without confirmation')

badmeta=dict(meta,persistent_directory=None)
try:s.bootstrap(badmeta,allow_restart=True)
except RuntimeError as e:assert 'persistant' in str(e)
else:raise AssertionError('Secret allowed in ephemeral layer')

calls=[]
def fake_run(args,timeout=12):
    calls.append(args)
    return SimpleNamespace(returncode=0,stdout='')

with mock.patch.object(s,'in_container_exists',side_effect=[False,True]), \
     mock.patch.object(s,'run',side_effect=fake_run), \
     mock.patch.object(edr,'api_query',return_value=[{'a':1}]) as api, \
     mock.patch.object(edr,'atomic_json') as save:
    out=s.bootstrap(meta,allow_restart=True)
    assert out=='/datastore/aegismesh-soar-api-client.yaml'
    assert any(x[:2]==['docker','restart'] for x in calls)
    assert any(x[:3]==['docker','exec','--user'] and 'acl' in x and 'api,investigator' in x for x in calls)
    assert any(x[:3]==['docker','exec','--user'] and 'umask 077; exec "$@"' in x for x in calls)
    assert api.call_count==2
    save.assert_called_once()

with mock.patch.object(edr,'CONF',Path('/does/not/exist')):
    try:edr.api_query(edr.READ_CLIENTS)
    except RuntimeError as exc:assert 'edr doctor' in str(exc)
    else:raise AssertionError('Missing mTLS produced no actionable error')

print('PASS: Velociraptor auto-discovery, persistent Docker volume, explicit restart, scoped API role and fail-closed onboarding; no live action')
