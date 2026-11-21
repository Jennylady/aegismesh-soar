#!/usr/bin/env python3
"""Unit checks for Wazuh fleet evidence. No contact with any real endpoint."""
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('bridge_v34',ROOT/'soar/bridge.py')
bridge=importlib.util.module_from_spec(spec);spec.loader.exec_module(bridge)

def make(agent,mark):
    return json.dumps({'agent':{'id':agent},'full_log':mark,'location':'active-response\\active-responses.log'})+'\n'

with tempfile.TemporaryDirectory() as tmp:
    path=Path(tmp)/'archives.json'
    ident='am-123456789abcdef012345678'
    path.write_text(make('001','AEGISMESH-SOAR-PROOF decision_id='+ident+' status=executed')+
                    make('006','AEGISMESH-SOAR-PROOF decision_id='+ident+' status=executed')+
                    make('002','AEGISMESH-SOAR-BLOCK decision_id='+ident+' status=blocked ttl=120'))
    assert bridge.wazuh_evidence('001',ident,'proof',sources=[str(path)]) == str(path)
    assert bridge.wazuh_evidence('006',ident,'proof',sources=[str(path)]) == str(path)
    assert not bridge.wazuh_evidence('002',ident,'proof',sources=[str(path)])
    assert bridge.wazuh_evidence('002',ident,'block',sources=[str(path)]) == str(path)
    assert not bridge.wazuh_evidence('005',ident,'proof',sources=[str(path)])
    assert not bridge.wazuh_evidence('001','am-other-123456789',sources=[str(path)])

ps=(ROOT/'ops/wazuh/windows/aegismesh-soar-proof.ps1').read_text()
cmd=(ROOT/'ops/wazuh/windows/aegismesh-soar-proof.cmd').read_text()
assert '[Console]::In.ReadLine()' in ps
assert 'active-responses.log' in ps
assert 'aegismesh-soar-proof.ps1' in cmd
assert 'wazuh-proof-agents' in (ROOT/'bin/aegismesh-soar').read_text()
assert "!aegismesh-soar-proof.cmd" in (ROOT/'soar/bridge.py').read_text()
# Validate real Wazuh API command name chosen for Windows vs Linux, without calling it.
from unittest.mock import patch
requests=[]
def fake_request(method, path, body, headers):
    requests.append((method,path,body))
    return {'error':0,'data':{'total_affected_items':1}}
with patch.object(bridge,'wazuh_auth_token',return_value='fake-jwt'), \
     patch.object(bridge,'wazuh_api_request',side_effect=fake_request), \
     patch.object(bridge,'wazuh_evidence',return_value=''), \
     patch.object(bridge,'local_wazuh_proof',return_value=False), \
     patch.object(bridge,'wazuh_agent_record',side_effect=lambda agent,token: {'id':agent,'os':{'name':'Windows Server 2022' if agent=='006' else 'Kali Linux'}}):
    bridge.ENV={'WAZUH_TEST_AGENTS':'002,006'}
    for agent in ('002','006'):
        result=bridge.wazuh_probe({'decision_id':'am-123456789abcdef012345678','target':{'agent_id':agent}})
        assert result['effect']=='wazuh_ar_dispatched'
assert requests[0][2]['command']=='!aegismesh-soar-proof'
assert requests[1][2]['command']=='!aegismesh-soar-proof.cmd'
assert requests[1][2]['arguments']==['am-123456789abcdef012345678']
print('PASS: agent+decision evidence match, Linux/Windows AR commands via Wazuh API; safe endpoint installers')
