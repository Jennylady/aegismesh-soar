#!/usr/bin/env python3
"""Cross-platform regression: no real Wazuh, Windows, Shuffle or firewall actions."""
import importlib.util
import ipaddress
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('bridge_windows36',ROOT/'soar/bridge.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
ID='am-0123456789abcdef01234567'
base={'decision_id':ID,'tag':'WINDOWS_BLOCK_IP','incident_id':'INC-EDR-9',
      'target':{'agent_id':'001','ip':'8.8.4.4'},'approved':True,
      'confidence':.99,'evidence_ids':['real-alert-A','real-alert-B']}
b.ENV={'ENABLE_PROD_ACTIONS':'true','PROTECTED_CIDRS':'153.67.85.205/32',
       'WAZUH_WINDOWS_AGENT_IDS':'001','WAZUH_WINDOWS_DC_AGENT_IDS':'006'}
assert b.policy(base)=='windows_firewall_block'
assert b.TAGS['EDR_ISOLATE']=='not_implemented'
with patch.object(b,'current_ssh_management_peers',return_value={ipaddress.ip_address('1.1.1.1')}),\
     patch.object(b,'wazuh_auth_token',return_value='mock-jwt'),\
     patch.object(b,'wazuh_agent_record',side_effect=lambda aid,token:{'id':aid,'status':'active', 'os':{'name':'Windows Server 2022' if aid=='006' else 'Microsoft Windows'}}),\
     patch.object(b,'wazuh_evidence',return_value='') as evidence,\
     patch.object(b,'wazuh_api_request',return_value={'error':0,'data':{'total_affected_items':1}}) as call:
    obj=b.wazuh_block_windows(base)
    assert obj['effect']=='wazuh_ar_dispatched' and not obj['agent_execution_verified']
    body=call.call_args.args[2]
    assert body['command']=='!aegismesh-soar-firewall.cmd'
    assert body['alert']['data']=={'srcip':'8.8.4.4','decision_id':ID,'dc_approved':False}
    assert evidence.call_args.args == ('001',ID,'winblock')
    b.wazuh_block_windows({**base,'target':{'agent_id':'006','ip':'8.8.4.4'}})
    assert call.call_args.args[2]['alert']['data']['dc_approved'] is True
    for bad in ['10.77.77.34','192.168.96.1','198.51.100.42','153.67.85.205','1.1.1.1']:
        try: b.wazuh_block_windows({**base,'target':{'agent_id':'001','ip':bad}})
        except PermissionError: pass
        else: raise AssertionError('Unsafe target permitted: '+bad)
    for agent in ('000','002','007'):
        try: b.wazuh_block_windows({**base,'target':{'agent_id':agent,'ip':'8.8.4.4'}})
        except PermissionError: pass
        else: raise AssertionError('Unexpected agent permitted: '+agent)
    with patch.object(b,'wazuh_agent_record',return_value={'id':'001','status':'active','os':{'name':'Kali GNU/Linux'}}):
        try: b.wazuh_block_windows(base)
        except PermissionError: pass
        else: raise AssertionError('Linux accepted by Windows action')
    with patch.object(b,'current_ssh_management_peers',side_effect=PermissionError('SSH unavailable')):
        try: b.wazuh_block_windows(base)
        except PermissionError: pass
        else: raise AssertionError('Accepted when admin peer inventory failed')
    b.ENV['WAZUH_WINDOWS_DC_AGENT_IDS']=''
    try: b.wazuh_block_windows({**base,'target':{'agent_id':'006','ip':'8.8.4.4'}})
    except PermissionError: pass
    else: raise AssertionError('DC accepted without explicit DC authorization')

# Verify the existing strict evidence link also recognizes a Windows firewall proof.
from tempfile import TemporaryDirectory
import json
with TemporaryDirectory() as temp:
    path=Path(temp)/'alerts.json'
    path.write_text(json.dumps({'agent':{'id':'001'},'full_log':
        'AEGISMESH-SOAR-WINBLOCK decision_id='+ID+' status=blocked ttl=120'})+'\n')
    assert b.wazuh_evidence('001',ID,'winblock',sources=[str(path)]) == str(path)
    assert not b.wazuh_evidence('006',ID,'winblock',sources=[str(path)])
    assert not b.wazuh_evidence('001','am-9876543210abcdef98765432','winblock',sources=[str(path)])
    with path.open('a') as f:
        f.write(json.dumps({'agent':{'id':'001'},'full_log':
            'AEGISMESH-SOAR-WINUNBLOCK decision_id='+ID+' status=removed'})+'\n')
    assert b.wazuh_evidence('001',ID,'winunblock',sources=[str(path)]) == str(path)
    assert not b.wazuh_evidence('006',ID,'winunblock',sources=[str(path)])
ps=(ROOT/'ops/wazuh/windows/aegismesh-soar-firewall.ps1').read_text()
cleanup=(ROOT/'ops/wazuh/windows/aegismesh-soar-firewall-cleanup.ps1').read_text()
installer=(ROOT/'ops/wazuh/windows/Install-AegisMeshFirewall.ps1').read_text()
assert 'New-ScheduledTaskTrigger -Once' in ps and 'Register-ScheduledTask' in ps
assert ps.index('Register-ScheduledTask') < ps.index('New-NetFirewallRule')
assert 'Get-NetFirewallAddressFilter' in ps and 'Get-NetFirewallRule -PolicyStore ActiveStore' in ps
assert 'Get-NetTCPConnection' in ps and 'DomainRole' in ps and 'dc_approved' in ps
assert "-Direction $item[1]" in ps and "-RemoteAddress $address" in ps
assert 'Remove-NetFirewallRule' in cleanup and 'DecisionId' in cleanup
assert '-DomainController' in installer and 'DomainRole' in installer
assert 'AEGISMESH-SOAR-WINBLOCK' in (ROOT/'ops/wazuh/rules/aegismesh-soar-evidence.xml').read_text()
assert "'WINDOWS_BLOCK_IP'" in (ROOT/'soar/soarctl.py').read_text()
assert "'windows-dc-agent'" in (ROOT/'bin/aegismesh-soar').read_text()
print('PASS: Windows scoped firewall 120s, DC opt-in, authenticated Wazuh dispatch, strict evidence; no live actions')
