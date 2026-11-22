#!/usr/bin/env python3
"""V4.2.5: nft JSON fixture based on read-only 22 Nov GCP output; NO real nft/Fail2ban calls."""
import copy
import json
import pathlib
import sys
from unittest import mock
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent/'soar'))
import bridge

IP='198.51.100.42'

BASE={'nftables':[
 {'metainfo':{'version':'1.0.9','json_schema_version':1}},
 {'table':{'family':'inet','name':'aegismesh_soar_gcp','handle':17}},
 {'set':{'family':'inet','name':'aegismesh_block_v4','table':'aegismesh_soar_gcp', 'type':'ipv4_addr','handle':2}},
 {'chain':{'family':'inet','table':'aegismesh_soar_gcp','name':'aegismesh_input', 'handle':1,'type':'filter','hook':'input','prio':-1,'policy':'accept'}},
 {'rule':{'family':'inet','table':'aegismesh_soar_gcp','chain':'aegismesh_input','handle':3,
          'expr':[{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':443}},
                  {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'@aegismesh_block_v4'}},
                  {'drop':None}]}}
]}

def call_nft(obj,ip=IP,rc=0):
    response=mock.Mock(returncode=rc,stdout=json.dumps(obj) if not isinstance(obj,str) else obj)
    with mock.patch.object(bridge.subprocess,'run',return_value=response) as run:
        answer=bridge.f2b_nft_confirmed(ip)
        run.assert_called_once_with(['nft','-j','list','table','inet','aegismesh_soar_gcp'],
                                    capture_output=True,text=True,timeout=10)
        return answer

def denied(obj,ip=IP):
    try:call_nft(obj,ip=ip)
    except RuntimeError:return
    raise AssertionError('Règle absente, corrompue ou inattendue acceptée')

assert call_nft(BASE) is False
for entry in [IP,{'elem':{'val':IP,'expires':115}},'198.51.100.420']:
    obj=copy.deepcopy(BASE);obj['nftables'][2]['set']['elem']=[entry]
    assert call_nft(obj) is (entry!='198.51.100.420')
obj=copy.deepcopy(BASE);obj['nftables'][2]['set']['elem']=['198.51.100.4']
assert not call_nft(obj)
for tweak in (
    lambda o:o['nftables'][2]['set'].update(name='aegismesh_soar_gcp'),
    lambda o:o['nftables'][2]['set'].update(table='other'),
    lambda o:o['nftables'][2]['set'].update(type='ipv6_addr'),
    lambda o:o['nftables'][3]['chain'].update(hook='output'),
    lambda o:o['nftables'][4]['rule']['expr'][0]['match'].update(right=80),
    lambda o:o['nftables'][4]['rule']['expr'][1]['match'].update(right='@other'),
    lambda o:o['nftables'][4]['rule']['expr'].__setitem__(-1,{'accept':None}),
):
    obj=copy.deepcopy(BASE);tweak(obj);denied(obj)
denied({'nftables':[]})
denied('invalid json')
with mock.patch.object(bridge.subprocess,'run',return_value=mock.Mock(returncode=1,stdout='')):
    try:bridge.f2b_nft_confirmed(IP)
    except RuntimeError:pass
    else:raise AssertionError('nft command failure falsely reported unbanned')

# Isolated fake jail: all state changes in memory. No actual firewall interaction.
banned=set()
changes=[]
def action(jail,operation,ip):
    assert jail=='aegismesh-soar-gcp' and ip==IP
    changes.append(operation)
    if operation=='banip':banned.add(ip)
    elif operation=='unbanip':banned.discard(ip)
    else:raise AssertionError(operation)
with mock.patch.object(bridge,'f2b_get_bans',side_effect=lambda jail:set(banned)), \
     mock.patch.object(bridge,'f2b_set',side_effect=action), \
     mock.patch.object(bridge,'f2b_nft_confirmed',side_effect=lambda ip:ip in banned):
    out=bridge.fail2ban_action({'target':{'ip':IP}},test=True)
    assert out['nftables_verified_during_ban'] and out['nftables_removed_verified']
    assert out['port']==443 and not banned and changes==['banip','unbanip']

# A broken nft action must NEVER claim success and must clean up the test ban.
changes.clear()
with mock.patch.object(bridge,'f2b_get_bans',side_effect=lambda jail:set(banned)), \
     mock.patch.object(bridge,'f2b_set',side_effect=action), \
     mock.patch.object(bridge,'f2b_nft_confirmed',return_value=False):
    try:bridge.fail2ban_action({'target':{'ip':IP}},test=True)
    except RuntimeError:pass
    else:raise AssertionError('Test ban without nft proof succeeded')
assert not banned and changes==['banip','unbanip']

# Production: nft malformed/unavailable after ban must roll back newly created jail ban.
changes.clear()
with mock.patch.object(bridge,'f2b_get_bans',side_effect=lambda jail:set(banned)), \
     mock.patch.object(bridge,'f2b_set',side_effect=action), \
     mock.patch.object(bridge,'f2b_bantime_seconds',return_value=120), \
     mock.patch.object(bridge,'ipcheck',side_effect=lambda ip,test:IP), \
     mock.patch.object(bridge,'f2b_nft_confirmed',side_effect=RuntimeError('unreadable')):
    try:bridge.fail2ban_action({'target':{'ip':IP}},test=False)
    except RuntimeError:pass
    else:raise AssertionError('Production ban without nft evidence succeeded')
assert not banned and changes==['banip','unbanip']
print('PASS: V4.2.5 exact nft JSON layout, membership, 443/drop, fail-closed and ban/unban rollback (mocked)')
