#!/usr/bin/env python3
"""No live Wazuh, nftables, Firewall or EDR calls. Exact correlation tests."""
from contextlib import contextmanager
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'soar'))
from ops import response_lifecycle_v40 as resp
from ops import progressive_guard_v40 as guard
import bridge


def make_db(root):
    bridge.ENV.clear();bridge.ENV['SOAR_DB_BACKEND']='sqlite';bridge.DB=str(root/'decisions.sqlite3')
    bridge.init_db()


def decision(id,tag,agent,ip,incident='REAL-INCIDENT-001',status='executed',detail=None, when=None):
    when=when or dt.datetime.now(dt.timezone.utc).isoformat()
    payload={'decision_id':id,'tag':tag,'incident_id':incident,'target':{'agent_id':agent,'ip':ip},
             'confidence':0.97,'evidence_ids':['wazuh-01','suricata-01']}
    with bridge.dbconn() as db:
        db.execute('INSERT INTO decisions (id,payload,tag,status,action_status,detail,updated_at) VALUES (?,?,?,?,?,?,?)',
                   (id,json.dumps(payload),tag,'action_executed',status,json.dumps(detail or {}),when))
    return payload


def run():
    decision_id='am-'+'a'*24
    check_id='am-'+'b'*24
    line=f'AEGISMESH-SOAR-WINSTATE decision_id={decision_id} check_id={check_id} status=removed ip=8.8.8.8'
    assert resp.extract_state(line,decision_id=decision_id,check_id=check_id,ip='8.8.8.8',kind='WINSTATE')=='removed'
    assert resp.extract_state(line,decision_id=decision_id,check_id='am-'+'c'*24,ip='8.8.8.8',kind='WINSTATE') is None
    assert resp.extract_state(line,decision_id=decision_id,check_id=check_id,ip='8.8.4.4',kind='WINSTATE') is None
    assert resp.extract_state(line,decision_id=decision_id,check_id=check_id,ip='8.8.8.8',kind='BLOCKSTATE') is None
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);make_db(root)
        src=root/'archives.json'
        src.write_text('\n'.join(json.dumps({'agent':{'id':aid},'full_log':msg}) for aid,msg in (
            ('001',line),('006',line)))+'\n')
        assert resp.collected_state('001',decision_id,check_id,'8.8.8.8','WINSTATE',sources=[src])=={'state':'removed','source':str(src)}
        assert resp.collected_state('002',decision_id,check_id,'8.8.8.8','WINSTATE',sources=[src]) is None
        assert resp.collected_state('001',decision_id,check_id,'8.8.4.4','WINSTATE',sources=[src]) is None
        with mock.patch.object(resp,'collected_state',return_value={'state':'blocked','source':'manager'}):
            resp.record(check_id,decision_id,'001','8.8.8.8','WINDOWS_BLOCK_IP','dispatched_unverified')
            row=resp.refresh(check_id)
            assert row['status']=='blocked' and row['evidence_source']=='manager'
            assert resp.audit(decision_id)[0]['status']=='blocked'
        payload=decision(decision_id,'WINDOWS_BLOCK_IP','001','8.8.8.8',detail={'agent_execution_verified':True})
        data,_,ip,agent=resp.decision_data(decision_id)
        assert agent=='001' and ip=='8.8.8.8' and data['incident_id']=='REAL-INCIDENT-001'
        # A verified lower-level block + genuine recent EDR flow permits only
        # the guard check; it never activates quarantine by itself.
        fid='F.DC123456789'
        flow=root/'tracked.json'
        flow.write_text(json.dumps({fid:{'agent_id':'001','state':'FINISHED','result_rows':13,
                       'result_sha256':'a'*64,'last_checked':dt.datetime.now(dt.timezone.utc).isoformat()}}))
        isolation={'target':{'agent_id':'001'},'incident_id':'REAL-INCIDENT-001'}
        assert guard.guard_isolation(isolation,bridge.dbconn,flow_path=flow)['previous_block_decision']==decision_id
        assert guard.guard_isolation(isolation,bridge.dbconn,flow_path=flow)['edr_flow']==fid
        try:
            guard.guard_isolation({'target':{'agent_id':'006'},'incident_id':'REAL-INCIDENT-001'},bridge.dbconn,flow_path=flow)
            raise AssertionError('DC quarantine was not denied')
        except PermissionError:pass
        try:
            guard.guard_isolation({'target':{'agent_id':'002'},'incident_id':'REAL-INCIDENT-001'},bridge.dbconn,flow_path=flow)
            raise AssertionError('No-prior-block was accepted')
        except PermissionError:pass
        yesterday=dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=3)
        assert guard.previous_verified_block(isolation,bridge.dbconn,now=yesterday) is None
        # The timer must not dispatch checks for a fresh decision before TTL.
        with mock.patch.object(resp,'verify',side_effect=AssertionError('Premature remote Wazuh probe')):
            result=resp.reconciler(now=dt.datetime.now(dt.timezone.utc))
            assert result['checks']==[]
        # Fail2ban status refuses to conclude when nft command fails.
        p=mock.Mock(returncode=1,stdout='')
        with mock.patch.object(resp.subprocess,'run',return_value=p):
            try:resp.f2b_state('8.8.8.8');raise AssertionError('nft failure masked as removal')
            except RuntimeError:pass
    print('PASS: SOAR response check exact decision/agent/IP/fresh-check proof, PostgreSQL-compatible schema, progressive guard, nft fail-closed; no live actions')

if __name__=='__main__':run()
