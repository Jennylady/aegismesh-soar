#!/usr/bin/env python3
"""Safe adapter tests: monkeypatch in-process, no real Wazuh or Fail2ban calls."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'soar'))
import bridge

banned=set()
old_get,old_set=bridge.f2b_get_bans,bridge.f2b_set
try:
    bridge.f2b_get_bans=lambda jail: set(banned)
    def mock_set(jail, operation, ip):
        assert jail == 'aegismesh-soar-gcp'
        assert ip == '198.51.100.42'
        if operation == 'banip': banned.add(ip)
        elif operation == 'unbanip': banned.discard(ip)
        else: raise AssertionError(operation)
    bridge.f2b_set=mock_set
    result=bridge.fail2ban_action({'target':{'ip':'198.51.100.42'}},test=True)
    assert result['banned_verified'] is True and result['unban_verified'] is True
    assert not banned, 'test must clean up the temporary ban'
finally:
    bridge.f2b_get_bans,bridge.f2b_set=old_get,old_set

old_api,old_proof=bridge.wazuh_api_request,bridge.local_wazuh_proof
old_env=dict(bridge.ENV)
try:
    bridge.ENV.update({'WAZUH_USER':'dummy','WAZUH_PASSWORD':'dummy','WAZUH_TEST_AGENTS':'000'})
    calls=[]
    def mock_api(method,path,body,headers=None,raw=False):
        calls.append((method,path,body))
        if path.startswith('/security/'): return 'mock-jwt'
        assert method == 'PUT' and path == '/active-response?agents_list=000'
        assert body['command'] == '!aegismesh-soar-proof'
        return {'error':0,'data':{'total_affected_items':1}}
    bridge.wazuh_api_request=mock_api
    bridge.local_wazuh_proof=lambda ident: ident == 'valid-proof-12345'
    result=bridge.wazuh_probe({'target':{'agent_id':'000'},'decision_id':'valid-proof-12345'})
    assert result['effect']=='wazuh_ar_verified' and result['execution_verified_on_agent']
    assert len(calls)==2
finally:
    bridge.wazuh_api_request,bridge.local_wazuh_proof=old_api,old_proof
    bridge.ENV.clear();bridge.ENV.update(old_env)

print('PASS: adaptateurs Fail2ban ban+unban et Wazuh API+preuve vérifiés via doubles sans action système')
