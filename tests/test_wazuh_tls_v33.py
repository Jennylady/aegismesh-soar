#!/usr/bin/env python3
"""TLS unit cases; only local mocks, no real API requests."""
from pathlib import Path
from unittest import mock
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'soar'))
import bridge

class FakeContext:
    check_hostname=True
    verify_mode=2

class FakeResponse:
    def __enter__(self):return self
    def __exit__(self,*args):return None
    def read(self,limit):return b'{"error":0,"data":{"affected_items":[]}}'

class FakeOpener:
    def open(self,request,timeout):
        assert request.full_url.startswith('https://127.0.0.1:55000/')
        return FakeResponse()

saved=dict(bridge.ENV)
try:
    bridge.ENV.clear()
    bridge.ENV.update({'WAZUH_API_URL':'https://127.0.0.1:55000'})
    ctx=FakeContext()
    with mock.patch.object(bridge.os.path,'isfile',return_value=True),\
         mock.patch.object(bridge.ssl,'create_default_context',return_value=ctx) as create,\
         mock.patch.object(bridge.urllib.request,'build_opener',return_value=FakeOpener()):
        result=bridge.wazuh_api_request('GET','/agents',None)
        assert result['error']==0
        assert create.call_args.kwargs['cafile']=='/var/ossec/api/configuration/ssl/server.crt'
        assert not ctx.check_hostname and ctx.verify_mode==2
    bridge.ENV['WAZUH_TLS_INSECURE']='true'
    try:
        bridge.wazuh_api_request('GET','/agents',None)
        raise AssertionError('Insecure TLS unexpectedly accepted')
    except PermissionError:pass
finally:
    bridge.ENV.clear(); bridge.ENV.update(saved)
print('PASS: local Wazuh leaf certificate verified; permissive TLS refused')
