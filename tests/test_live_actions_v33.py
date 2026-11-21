#!/usr/bin/env python3
"""No real network, auth, firewall changes, or agent responses."""
from pathlib import Path
import importlib.util
import ipaddress
import sys
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'soar'))
import bridge

cfg=dict(bridge.ENV)
try:
    target={'ip':'8.8.4.4','agent_id':'002'}
    data={'decision_id':'am-secure-case123','incident_id':'INC-459','tag':'WAZUH_BLOCK_AGENT',
          'target':target,'approved':True,'evidence_ids':['wazuh-10','wazuh-11'],'confidence':0.96}
    # Fail closed before policy is explicitly activated.
    try:
        bridge.policy(data)
        raise AssertionError('AR production permitted without enable')
    except PermissionError: pass
    bridge.ENV.update({'ENABLE_PROD_ACTIONS':'true','PROTECTED_CIDRS':'136.116.89.163/32',
                       'WAZUH_PROD_AGENT_IDS':'002','WAZUH_USER':'mock','WAZUH_PASSWORD':'mock'})
    assert bridge.policy(data)=='wazuh_block'
    with mock.patch.object(bridge,'wazuh_auth_token',return_value='jwt'),\
         mock.patch.object(bridge,'wazuh_agent_record',return_value={'id':'002','status':'active','os':{'name':'Kali GNU/Linux'}}),\
         mock.patch.object(bridge,'wazuh_api_request',return_value={'error':0,'data':{'total_affected_items':1}}) as call:
        out=bridge.wazuh_block_agent(data)
        assert out['effect']=='wazuh_ar_dispatched' and not out['agent_execution_verified']
        payload=call.call_args.args[2]
        assert payload['command']=='!aegismesh-soar-block'
        assert payload['alert']['data']['srcip']=='8.8.4.4'
    for unsafe_ip in ['10.77.77.34','192.168.96.1','136.116.89.163','198.51.100.42']:
        try:
            bridge.wazuh_block_agent({**data,'target':{'agent_id':'002','ip':unsafe_ip}})
            raise AssertionError('Unsafe IP allowed '+unsafe_ip)
        except PermissionError: pass
    try:
        bridge.wazuh_block_agent({**data,'target':{'agent_id':'001','ip':'8.8.4.4'}})
        raise AssertionError('Unlisted agent permitted')
    except PermissionError: pass
    with mock.patch.object(bridge,'wazuh_auth_token',return_value='jwt'),\
         mock.patch.object(bridge,'wazuh_agent_record',return_value={'id':'002','status':'active','os':{'name':'Windows Server 2022'}}):
        try:
            bridge.wazuh_block_agent(data)
            raise AssertionError('Windows endpoint permitted')
        except PermissionError: pass

    # Strict nftables enforcement required for production Fail2ban action.
    banned=set()
    with mock.patch.object(bridge,'f2b_get_bans',side_effect=lambda jail:set(banned)),\
         mock.patch.object(bridge,'f2b_set',side_effect=lambda jail,op,ip: banned.add(ip) if op=='banip' else banned.discard(ip)),\
         mock.patch.object(bridge,'f2b_nft_confirmed',return_value=True),\
         mock.patch.object(bridge,'f2b_bantime_seconds',return_value=120):
        result=bridge.fail2ban_action({'target':{'ip':'8.8.4.4'}},test=False)
        assert result['nftables_verified'] and '8.8.4.4' in banned
    banned.clear()
    with mock.patch.object(bridge,'f2b_get_bans',side_effect=lambda jail:set(banned)),\
         mock.patch.object(bridge,'f2b_set',side_effect=lambda jail,op,ip: banned.add(ip) if op=='banip' else banned.discard(ip)),\
         mock.patch.object(bridge,'f2b_nft_confirmed',return_value=False),\
         mock.patch.object(bridge,'f2b_bantime_seconds',return_value=120):
        try:
            bridge.fail2ban_action({'target':{'ip':'8.8.4.4'}},test=False)
            raise AssertionError('Missing nftables block not detected')
        except RuntimeError: pass
        assert not banned
finally:
    bridge.ENV.clear();bridge.ENV.update(cfg)

# Run native agent-side AR script against a fake nftables executor, never the host nft CLI.
script=Path(__file__).resolve().parent.parent/'ops/wazuh/aegismesh-soar-block'
spec=importlib.util.spec_from_file_location('aegismesh_agent_block',script)
# file without .py is loaded explicitly through source loader
from importlib.machinery import SourceFileLoader
loader=SourceFileLoader('aegismesh_agent_block',str(script))
spec=importlib.util.spec_from_loader('aegismesh_agent_block',loader)
module=importlib.util.module_from_spec(spec);loader.exec_module(module)
with mock.patch.object(module,'management_peers',return_value={ipaddress.ip_address('8.8.8.8')}),\
     mock.patch.object(module,'ensure_table'),\
     mock.patch.object(module,'run',side_effect=['','set '+ '8.8.4.4' +' { timeout 120s }']) as r:
    obj={'command':'add','parameters':{'alert':{'data':{'srcip':'8.8.4.4','decision_id':'am-secure-case123'}}}}
    res=module.process(obj)
    assert res['success'] and res['ttl_seconds']==120
    assert r.call_args_list[0].args[0] == 'add'
    assert r.call_args_list[0].args[1] == 'element'
for bad in ('127.0.0.1','10.77.77.34','8.8.8.8'):
    with mock.patch.object(module,'management_peers',return_value={ipaddress.ip_address('8.8.8.8')}):
        try:
            module.validate_ip(bad)
            raise AssertionError('Agent blocked management/private IP')
        except PermissionError: pass
print('PASS: production Fail2ban nft verification and Wazuh Linux agent dispatch + TTL are guarded')
