#!/usr/bin/env python3
"""AD demo contract tests. No real AD, Shuffle, Wazuh or HTTP calls."""
import datetime as dt
from pathlib import Path
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from soar import bridge

SID='S-1-5-21-1111111111-2222222222-3333333333-1105'

def decision():
    return {'decision_id':'am-'+('a'*24),'incident_id':'AD-LAB-'+('b'*24),
            'tag':'AD_LAB_DISABLE','origin':'operator_lab','approved':True,
            'confidence':0,'evidence_ids':[],
            'target':{'agent_id':'006','domain_dns':'ad.ikom.mg','user_sid':SID},
            'expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=3)).isoformat()}

def denied(data):
    try:bridge.policy(data)
    except PermissionError:return
    raise AssertionError('Unsafe AD LAB request accepted')

def run():
    saved=dict(bridge.ENV)
    try:
        bridge.ENV.clear()
        bridge.ENV.update({'ENABLE_PROD_ACTIONS':'true','ENABLE_AD_REMEDIATION':'true',
            'AD_DC_AGENT_ID':'006','AD_DOMAIN_DNS':'ad.ikom.mg',
            'WAZUH_WINDOWS_DC_AGENT_IDS':'006',
            'AD_LAB_UNTIL':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=8)).isoformat()})
        d=decision()
        assert bridge.validate_decision(d)[1]=='AD_LAB_DISABLE'
        assert bridge.policy(d)=='ad_account_disable'
        for key,val in [('approved',False),('confidence',0.99),('origin','analysis'),('evidence_ids',['fake'])]:
            bad=decision();bad[key]=val;denied(bad)
        bad=decision();bad['target']['agent_id']='001';denied(bad)
        bad=decision();bad['target']['user_sid']='S-1-5-18';denied(bad)
        bad=decision();bad['expires_at']=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=7)).isoformat();denied(bad)
        # Actual dispatch structure is the same authenticated Wazuh action for the DC,
        # not a direct PowerShell shell or a database-only no-op.
        bridge.ENV['AD_LAB_UNTIL']=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=8)).isoformat()
        from unittest.mock import patch
        calls=[]
        def fake_wazuh(method,path,body,headers):
            calls.append((method,path,body))
            return {'error':0,'data':{'total_affected_items':1}}
        with patch.object(bridge,'wazuh_auth_token',return_value='mock-api-token'), \
             patch.object(bridge,'wazuh_agent_record',return_value={'os':{'name':'Microsoft Windows Server'}}), \
             patch.object(bridge,'wazuh_api_request',side_effect=fake_wazuh), \
             patch.object(bridge,'wazuh_evidence',return_value=''):
            result=bridge.execute_tag(decision())
        assert result['effect']=='wazuh_ar_dispatched'
        assert calls[0][0]=='PUT' and calls[0][1].endswith('agents_list=006')
        remote=calls[0][2]
        assert remote['command']=='!aegismesh-soar-ad.cmd'
        assert remote['alert']['data']['action']=='lab_disable_account'
        assert remote['alert']['data']['user_sid']==SID
        assert remote['alert']['data']['confidence']==0
        bridge.ENV['AD_LAB_UNTIL']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=1)).isoformat()
        denied(decision())
        # Endpoint independently checks dedicated lab account prefix, not just the bridge.
        endpoint=(ROOT/'ops/wazuh/windows/aegismesh-soar-ad.ps1').read_text()
        assert 'lab_disable_account' in endpoint
        assert "'^aegis-lab-[a-z0-9-]{1,12}$'" in endpoint
        assert 'Assert-AegisEligibleADUser' in endpoint
        assert 'Disable-ADAccount' in endpoint and 'Get-ADUser' in endpoint
        script=(ROOT/'ops/wazuh/windows/New-AegisMeshADLabUser.ps1').read_text()
        for command in ('New-ADUser','Add-ADGroupMember','-ConfirmCreate','Get-ADUser'):
            assert command in script
    finally:
        bridge.ENV.clear();bridge.ENV.update(saved)
    print('PASS: AD lab real-only policy, expiry, no AI score invention, DC scope and endpoint test-account guard; no live action')

if __name__=='__main__':run()
