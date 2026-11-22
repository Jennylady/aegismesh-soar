#!/usr/bin/env python3
"""AD end-to-end contract tests with mocks only; NEVER mutates AD or Wazuh."""
import datetime as dt
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'soar'))
sys.path.insert(0,str(ROOT/'ops'))
import bridge
import ad_control_v38 as ad

SID='S-1-5-21-123456789-234567890-345678901-1101'
DEC='am-1234567890abcdef12345678'
AGENT='006'


def decision():
    return {'decision_id':DEC, 'tag':'AD_DISABLE_ACCOUNT', 'incident_id':'case-real-event-001',
            'target':{'agent_id':AGENT,'user_sid':SID,'domain_dns':'ad.ikom.mg'},
            'confidence':0.99,'evidence_ids':['event-001','correlation-001'],
            'approved':True,'expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=9)).isoformat()}


def run():
    previous=bridge.ENV.copy()
    previous_db=bridge.DB
    bridge.ENV.clear()
    try:
        d=decision()
        assert bridge.validate_decision(d)==(DEC,'AD_DISABLE_ACCOUNT')
        for opts in ({}, {'ENABLE_PROD_ACTIONS':'true'}, {'ENABLE_AD_REMEDIATION':'true'}):
            bridge.ENV.clear();bridge.ENV.update(opts)
            try:bridge.policy(d)
            except PermissionError:pass
            else:raise AssertionError('AD action allowed without both gates')
        bridge.ENV.update({'ENABLE_PROD_ACTIONS':'true','ENABLE_AD_REMEDIATION':'true',
                           'AD_DC_AGENT_ID':'006','AD_DOMAIN_DNS':'ad.ikom.mg','WAZUH_WINDOWS_DC_AGENT_IDS':'006'})
        assert bridge.policy(d)=='ad_account_disable'
        bads=[{'confidence':.97}, {'approved':False}, {'evidence_ids':['same','same']},
              {'target':{**d['target'],'agent_id':'001'}},
              {'target':{**d['target'],'user_sid':'Administrator'}},
              {'target':{**d['target'],'user_sid':'S-1-5-32-544'}},
              {'target':{**d['target'],'domain_dns':'other.example.com'}},
              {'target':{**d['target'],'cmd':'Disable-ADAccount'}}]
        for bad in bads:
            value={**d,**bad}
            try:bridge.policy(value)
            except (PermissionError,ValueError):pass
            else:raise AssertionError('Unsafe AD decision allowed: '+str(bad))
        response={'error':0,'data':{'total_affected_items':1}}
        with patch.object(bridge,'wazuh_auth_token',return_value='verified-token'),\
             patch.object(bridge,'wazuh_agent_record',return_value={'os':{'name':'Microsoft Windows Server'}}),\
             patch.object(bridge,'wazuh_api_request',return_value=response) as fake_api,\
             patch.object(bridge,'wazuh_evidence',return_value=''):
            result=bridge.wazuh_disable_ad_account(d)
            assert result['effect']=='wazuh_ar_dispatched'
            args=fake_api.call_args.args
            assert args[0]=='PUT' and args[1]=='/active-response?agents_list=006'
            assert args[2]['command']=='!aegismesh-soar-ad.cmd'
            assert args[2]['alert']['data']['user_sid']==SID
            assert args[2]['alert']['data']['action']=='disable_account'
            assert 'script' not in args[2]['alert']['data']
        with tempfile.TemporaryDirectory() as root:
            evidence=Path(root)/'alerts.json'
            wrong_sid='S-1-5-21-123456789-234567890-345678901-1102'
            key=('006',DEC,'adaccount')
            lines=[
                {'agent':{'id':'001'},'full_log':f'AEGISMESH-SOAR-ADACCOUNT decision_id={DEC} status=disabled sid={SID}'},
                {'agent':{'id':'006'},'full_log':f'AEGISMESH-SOAR-ADACCOUNT decision_id={DEC} status=disabled sid={wrong_sid}'},
            ]
            evidence.write_text(''.join(json.dumps(x)+'\n' for x in lines))
            assert not bridge.collected_wazuh_evidence([(*key,SID)],sources=[str(evidence)])
            lines.append({'agent':{'id':'006'},'full_log':f'AEGISMESH-SOAR-ADACCOUNT decision_id={DEC} status=disabled sid={SID}'})
            evidence.write_text(''.join(json.dumps(x)+'\n' for x in lines))
            assert key in bridge.collected_wazuh_evidence([(*key,SID)],sources=[str(evidence)])
            # A failure from the same DC must never prove a successful disable.
            failed=('006',DEC,'adfail')
            assert not bridge.collected_wazuh_evidence([(*failed,SID)],sources=[str(evidence)])
            bridge.DB=str(Path(root)/'db.sqlite3')
            bridge.init_db()
            with bridge.dbconn() as conn:
                conn.execute('INSERT INTO decisions(id,payload,tag,status,action_status,updated_at) VALUES(?,?,?,?,?,?)',
                             (DEC,json.dumps(d),'AD_DISABLE_ACCOUNT','dispatched_unverified','dispatched_unverified',bridge.utcnow()))
            with patch.object(bridge,'EVIDENCE_LOGS',(str(evidence),)):
                summary=bridge.reconcile_wazuh_decisions()
                assert summary['verified_now']==1
            with bridge.dbconn() as conn:
                row=conn.execute('SELECT action_status FROM decisions WHERE id=?',(DEC,)).fetchone()
                assert row['action_status']=='executed'
            # Endpoint failures must produce a failed/uncertain state, never executed.
            d2={**d,'decision_id':'am-876543210fedcba987654321'}
            fail_marker={'agent':{'id':'006'},'full_log':
                         'AEGISMESH-SOAR-ADFAIL decision_id='+d2['decision_id']+' status=failed sid='+SID+' phase=disable_account'}
            evidence.write_text(json.dumps(fail_marker)+'\n')
            with bridge.dbconn() as conn:
                conn.execute('INSERT INTO decisions(id,payload,tag,status,action_status,updated_at) VALUES(?,?,?,?,?,?)',
                             (d2['decision_id'],json.dumps(d2),'AD_DISABLE_ACCOUNT','dispatched_unverified','dispatched_unverified',bridge.utcnow()))
            with patch.object(bridge,'EVIDENCE_LOGS',(str(evidence),)):
                summary=bridge.reconcile_wazuh_decisions()
                assert summary['verified_now']==1
            with bridge.dbconn() as conn:
                row=conn.execute('SELECT action_status,detail FROM decisions WHERE id=?',(d2['decision_id'],)).fetchone()
                assert row['action_status']=='failed'
                detail=json.loads(row['detail'])
                assert detail['account_disabled_verified'] is False and detail['effect_uncertain'] is True
        with tempfile.TemporaryDirectory() as root:
            cfg=Path(root)/'env';rules=Path(root)/'wazuh.xml'
            cfg.write_text('ENABLE_PROD_ACTIONS=true\nWAZUH_WINDOWS_DC_AGENT_IDS=006\n')
            rules.write_text('<rule id="119874"/><rule id="119875"/><rule id="119876"/>')
            state=Path(root)/'ad-ready.json'
            ad.write_probe('006','ad.ikom.mg',DEC,state_path=state)
            checker=lambda a,ident,kind: '/var/ossec/logs/alerts/alerts.json' if a=='006' and ident==DEC and kind=='adready' else ''
            args=type('Args',(),{'confirm':True,'agent_id':'006','domain':'ad.ikom.mg'})()
            changed=[]
            ad.enable(args,config_path=cfg,rules_path=rules,env_update=changed.append,
                      agent_lookup=lambda a:{'os':{'name':'Windows Server'}},
                      probe_path=state,evidence_fn=checker)
            assert changed==[{'ENABLE_AD_REMEDIATION':'true','AD_DC_AGENT_ID':'006','AD_DOMAIN_DNS':'ad.ikom.mg'}]
            cfg.write_text('ENABLE_PROD_ACTIONS=true\nWAZUH_WINDOWS_DC_AGENT_IDS=001\n')
            try:ad.enable(args,config_path=cfg,rules_path=rules,env_update=changed.append,
                          agent_lookup=lambda a:{'os':{'name':'Windows Server'}},
                          probe_path=state,evidence_fn=checker)
            except PermissionError:pass
            else:raise AssertionError('Unregistered DC incorrectly enabled')
            # Real Wazuh read-only probe contract; no incident, no user SID.
            cfg.write_text('WAZUH_WINDOWS_DC_AGENT_IDS=006\n')
            with patch.object(ad.bridge,'wazuh_evidence',return_value=''):
                returned=[]
                def mocked_api(method,url,body,headers):
                    returned.append(body)
                    return {'error':0,'data':{'total_affected_items':1}}
                code=ad.probe(wait=0,agent='006',domain='ad.ikom.mg',
                              token_fn=lambda:'opaque-token',request_fn=mocked_api,
                              agent_lookup=lambda a,t:{'os':{'name':'Windows Server'}},
                              evidence_fn=lambda a,i,k:'',state_path=Path(root)/'failed-readiness',
                              config_path=cfg)
                assert code==3
                data=returned[0]['alert']['data']
                assert data['action']=='check_ready' and 'user_sid' not in data and 'incident_id' not in data
            # A readiness proof with wrong agent is rejected before enabling.
            assert not ad.current_probe('001','ad.ikom.mg',state_path=state,evidence_fn=checker)
        src=(ROOT/'ops/wazuh/windows/aegismesh-soar-ad.ps1').read_text()
        checks=(ROOT/'ops/wazuh/windows/aegismesh-soar-ad-lib.ps1').read_text()
        installer=(ROOT/'ops/wazuh/windows/Install-AegisMeshAD.ps1').read_text()
        assert 'Disable-ADAccount' in src and 'Get-ADUser' in src
        assert 'AEGISMESH-SOAR-ADACCOUNT' in src and 'status=disabled' in src
        for guard in ('Get-ADDomain','Get-ADGroup','Get-ADUser','adminCount','ServicePrincipalName',
                      '1.2.840.113556.1.4.1941','PrimaryGroupID','Get-CimInstance','Sid'):
            assert guard.lower() in checks.lower(),guard
        assert '-CreateScopeGroup' in installer and 'Add-ADGroupMember' not in installer
        assert 'Enable-ADAccount' not in src
        rules=(ROOT/'ops/wazuh/rules/aegismesh-soar-evidence.xml').read_text()
        assert all(x in rules for x in ('119874','119875','119876'))
        print('PASS: AD real-action contract, strict SID/DC allowlist, group safety guards, exact SID evidence, manager reconciliation; no live action')
    finally:
        bridge.DB=previous_db
        bridge.ENV.clear();bridge.ENV.update(previous)


if __name__=='__main__':run()
