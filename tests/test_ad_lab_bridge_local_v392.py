#!/usr/bin/env python3
"""V3.9.2: local-only bridge routing, authenticated AD lab submission, no live action."""
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ops'))
import ad_control_v38 as ad

SID='S-1-5-21-1802484851-3511485622-4185718730-1108'

class Response(io.BytesIO):
    def __init__(self,status,obj):
        super().__init__(json.dumps(obj).encode())
        self.status=status

class Opener:
    def __init__(self):
        self.requests=[]
    def open(self,request,timeout):
        self.requests.append((request.full_url,request.get_method(),request.headers))
        if request.full_url.endswith('/health'):
            return Response(200,{'service':'aegismesh-soar-bridge','status':'up'})
        if request.full_url.endswith('/v1/decisions'):
            data=json.loads(request.data)
            assert data['tag']=='AD_LAB_DISABLE'
            assert data['target']['user_sid']==SID
            assert data['origin']=='operator_lab'
            assert data['confidence']==0 and data['evidence_ids']==[]
            assert request.get_header('X-aegismesh-token')=='valid-private-token'
            return Response(202,{'decision_id':data['decision_id']})
        raise AssertionError('Unexpected remote URL '+request.full_url)

CFG={'ENABLE_AD_REMEDIATION':'true','ENABLE_PROD_ACTIONS':'true',
     'WAZUH_WINDOWS_DC_AGENT_IDS':'006','AD_DC_AGENT_ID':'006',
     'AD_DOMAIN_DNS':'ad.ikom.mg','SOAR_BIND_HOST':'192.168.96.1',
     'SOAR_PORT':'19081','DECISION_TOKEN':'valid-private-token'}

def main():
    # Parsed LOCAL IPv4 addresses are the only permitted non-loopback route.
    result=ad.local_bridge_endpoint(CFG,addresses_fn=lambda:{'127.0.0.1','192.168.96.1','10.77.77.1'})
    assert result=='http://192.168.96.1:19081'
    for bind,expected in [('0.0.0.0','http://127.0.0.1:19081'),
                          ('127.0.0.1','http://127.0.0.1:19081'),
                          ('localhost','http://127.0.0.1:19081'),
                          ('10.77.77.1','http://10.77.77.1:19081')]:
        assert ad.local_bridge_endpoint({**CFG,'SOAR_BIND_HOST':bind},addresses_fn=lambda:{'10.77.77.1'})==expected
    for bind in ('8.8.8.8','example.com','192.168.96.2','192.168.96.1:19081'):
        try:ad.local_bridge_endpoint({**CFG,'SOAR_BIND_HOST':bind},addresses_fn=lambda:{'192.168.96.1'})
        except PermissionError:pass
        else:raise AssertionError('Remote/ambiguous bridge accepted: '+bind)
    for port in ('0','65536','abc'):
        try:ad.local_bridge_endpoint({**CFG,'SOAR_PORT':port})
        except ValueError:pass
        else:raise AssertionError('Invalid port accepted')
    class Run:
        returncode=0
        stdout=json.dumps([{'ifname':'lo','addr_info':[{'family':'inet','local':'127.0.0.1'}]},
                           {'ifname':'br-soar','addr_info':[{'family':'inet','local':'192.168.96.1'}]},
                           {'ifname':'wg0','addr_info':[{'family':'inet','local':'10.77.77.1'}]}])
    got=ad._local_ipv4_interface_addresses(runner=lambda *args,**kwargs:Run())
    assert got=={'127.0.0.1','192.168.96.1','10.77.77.1'}
    opener=Opener()
    updates=[]
    saved=dict(ad.bridge.ENV)
    try:
        with patch.object(ad,'read_cfg',return_value=CFG), \
             patch.object(ad,'current_probe',return_value=True), \
             patch.object(ad,'_local_ipv4_interface_addresses',return_value={'192.168.96.1'}), \
             patch.object(ad,'apply_and_restart',side_effect=lambda changes,cfg:updates.append(changes)), \
             patch.object(ad.urllib.request,'build_opener',return_value=opener):
            ad.lab_disable(sid=SID,confirm=True)
        assert len(updates)==1 and 'AD_LAB_UNTIL' in updates[0]
        assert [u[0] for u in opener.requests]==[
            'http://192.168.96.1:19081/health','http://192.168.96.1:19081/v1/decisions']
        assert [u[1] for u in opener.requests]==['GET','POST']
        # Misconfigured / remote bridge stops BEFORE opening operator window.
        updates.clear()
        with patch.object(ad,'read_cfg',return_value={**CFG,'SOAR_BIND_HOST':'8.8.8.8'}), \
             patch.object(ad,'current_probe',return_value=True), \
             patch.object(ad,'_local_ipv4_interface_addresses',return_value={'192.168.96.1'}), \
             patch.object(ad,'apply_and_restart',side_effect=lambda changes,cfg:updates.append(changes)):
            try:ad.lab_disable(sid=SID,confirm=True)
            except PermissionError:pass
            else:raise AssertionError('Remote bridge submitted')
        assert not updates
        # Bridge health failure must not open the window either.
        updates.clear()
        with patch.object(ad,'read_cfg',return_value=CFG), \
             patch.object(ad,'current_probe',return_value=True), \
             patch.object(ad,'_local_ipv4_interface_addresses',return_value={'192.168.96.1'}), \
             patch.object(ad,'ensure_local_bridge_health',side_effect=ConnectionRefusedError()), \
             patch.object(ad,'apply_and_restart',side_effect=lambda changes,cfg:updates.append(changes)):
            try:ad.lab_disable(sid=SID,confirm=True)
            except ConnectionRefusedError:pass
            else:raise AssertionError('Offline bridge submitted')
        assert not updates
    finally:
        ad.bridge.ENV.clear();ad.bridge.ENV.update(saved)
    print('PASS: AD lab uses only assigned local Docker bridge + authenticated POST; preflight before policy window; no live actions')

if __name__=='__main__':main()
