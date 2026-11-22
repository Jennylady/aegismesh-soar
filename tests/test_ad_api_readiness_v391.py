#!/usr/bin/env python3
"""Wazuh API readiness/recovery contracts. No live Wazuh/AD actions."""
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock, patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ops'))
import ad_control_v38 as ad

CFG={'WAZUH_API_URL':'https://127.0.0.1:55000','WAZUH_WINDOWS_DC_AGENT_IDS':'006'}

def main():
    # Readiness wait retries only the socket and never sends an Active Response.
    clocks=iter((0, 0, 1, 1, 2))
    socket_calls=[]
    class Sock:
        def close(self):pass
    def connect(addr,timeout):
        socket_calls.append(addr)
        if len(socket_calls)<3:raise ConnectionRefusedError(111,'refused')
        return Sock()
    assert ad.wait_wazuh_api(CFG,timeout=10,connect=connect,monotonic=lambda:next(clocks),sleeper=lambda _:None)
    assert len(socket_calls)==3 and set(socket_calls)=={('127.0.0.1',55000)}
    assert not ad.wait_wazuh_api(CFG,timeout=0,connect=lambda *_: (_ for _ in ()).throw(ConnectionRefusedError()))
    # Fail closed for a remote API, never restart a remote service.
    try:ad.wazuh_port_ready({'WAZUH_API_URL':'https://10.77.77.1:55000'},connect=connect)
    except PermissionError:pass
    else:raise AssertionError('Remote Wazuh API unexpectedly permitted for recovery')
    class Result:
        def __init__(self,code=0,out=''):
            self.returncode=code
            self.stdout=out
    cmds=[]
    def runner(cmd,**kwargs):
        cmds.append(cmd)
        return Result(0)
    # Cannot run a disruptive restart without explicit confirmation.
    try:ad.wazuh_recover(confirm=False,cfg=CFG,runner=runner,connect=lambda *_: None)
    except PermissionError:pass
    else:raise AssertionError('Recovery without explicit confirmation')
    assert not cmds
    # Doctor is read-only: no restart/dispatch, shows that 006 is probe eligible
    with tempfile.TemporaryDirectory() as td:
        rules=Path(td)/'rules.xml'
        rules.write_text('<rule id="119874"/><rule id="119875"/><rule id="119876"/>')
        from io import StringIO
        from contextlib import redirect_stdout
        output=StringIO()
        with redirect_stdout(output):
            assert ad.wazuh_doctor(cfg=CFG,rules_path=rules,
                                   runner=lambda *_args,**_kwargs:Result(0,'active'),
                                   connect=lambda *_args:Sock())
        assert 'Probe candidate 006' not in output.getvalue()  # Doctor reports eligibility with clear wording below.
        assert 'Agent 006 eligible for read-only probe: True' in output.getvalue()
        assert 'AD proof rules installed: True' in output.getvalue()
        assert not cmds
    class Socket:
        def close(self):pass
    with patch.object(ad.os,'geteuid',return_value=0,create=True):
        # If API already listening, must NOT restart, but authenticate once.
        assert ad.wazuh_recover(confirm=True,cfg=CFG,runner=runner,
                                connect=lambda *_:Socket(),token_fn=lambda:'token')
        assert not cmds
        # If socket closed, run analysisd -t, restart once, then check authentication.
        closed=lambda *_: (_ for _ in ()).throw(ConnectionRefusedError())
        assert ad.wazuh_recover(confirm=True,cfg=CFG,runner=runner,connect=closed,
                                wait_fn=lambda cfg,connect:True,token_fn=lambda:'token')
        assert cmds==[['/var/ossec/bin/wazuh-analysisd','-t'],['systemctl','restart','wazuh-manager.service']]
        # Invalid config prevents restart.
        cmds.clear()
        def fail_test(cmd,**kw):
            cmds.append(cmd)
            return Result(1)
        try:ad.wazuh_recover(confirm=True,cfg=CFG,runner=fail_test,connect=closed,
                             wait_fn=lambda cfg,connect:True,token_fn=lambda:'token')
        except RuntimeError as e: assert 'rules invalid' in str(e)
        else:raise AssertionError('Failed analysisd must prevent restart')
        assert cmds==[['/var/ossec/bin/wazuh-analysisd','-t']]
    # The actual AD probe waits before auth; never dispatch if the socket remains down.
    with tempfile.TemporaryDirectory() as tmp:
        cfg_file=Path(tmp)/'soar.env'
        cfg_file.write_text('WAZUH_WINDOWS_DC_AGENT_IDS=006\nWAZUH_API_URL=https://127.0.0.1:55000\n')
        with patch.object(ad,'wait_wazuh_api',return_value=False):
            with patch.object(ad.bridge,'wazuh_auth_token',side_effect=AssertionError('No auth before port ready')):
                try:ad.probe(agent='006',domain='ad.ikom.mg',config_path=cfg_file)
                except ConnectionError as e: assert 'readiness wait' in str(e)
                else:raise AssertionError('Probe dispatched with API offline')
        # Once API is ready it is still a single authenticated dispatch and requires proof.
        with patch.object(ad,'wait_wazuh_api',return_value=True),\
             patch.object(ad.bridge,'wazuh_auth_token',return_value='valid-token'),\
             patch.object(ad.bridge,'wazuh_agent_record',return_value={'os':{'name':'Windows Server'}}),\
             patch.object(ad.bridge,'wazuh_api_request',return_value={'error':0,'data':{'total_affected_items':1}}) as sent:
            assert ad.probe(agent='006',domain='ad.ikom.mg',wait=0,config_path=cfg_file,
                            evidence_fn=lambda *_:'',state_path=Path(tmp)/'state')==3
            assert sent.call_count==1
            assert sent.call_args.args[2]['alert']['data']['action']=='check_ready'
    print('PASS: AD Wazuh API readiness wait, read-only doctor, explicit one-restart repair, no premature dispatch; no live actions')

if __name__=='__main__':main()
