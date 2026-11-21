#!/usr/bin/env python3
"""Mock-Shuffle E2E test; no Fail2ban or Wazuh invocations."""
import datetime as dt
import http.server
import json
import os
from pathlib import Path
import secrets
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent.parent / 'soar'
TOKEN_A = 'A' * 60
TOKEN_B = 'B' * 60


def req(url, obj=None, token=None):
    headers = {'Content-Type':'application/json'}
    if token: headers['X-Aegismesh-Token'] = token
    body = json.dumps(obj).encode() if obj is not None else None
    request = urllib.request.Request(url, body, headers, method='POST' if body else 'GET')
    with urllib.request.urlopen(request, timeout=3) as response:
        return response.status, json.load(response)


class MockShuffle(http.server.BaseHTTPRequestHandler):
    received = []
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        data = json.loads(body)
        self.received.append(data)
        self.send_response(200)
        self.send_header('Content-Length','2')
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, *args): pass


def main():
    with tempfile.TemporaryDirectory() as d:
        mock = http.server.ThreadingHTTPServer(('127.0.0.1', 0), MockShuffle)
        threading.Thread(target=mock.serve_forever,daemon=True).start()
        # use a unique loopback port
        listener = socketserver.TCPServer(('127.0.0.1',0),http.server.BaseHTTPRequestHandler)
        port = listener.server_address[1]
        listener.server_close()
        cfg = Path(d)/'config'
        cfg.write_text(f'''DECISION_TOKEN={TOKEN_A}
SHUFFLE_ACTION_TOKEN={TOKEN_B}
SOAR_BIND_HOST=127.0.0.1
SOAR_PORT={port}
SOAR_DB={d}/decisions.sqlite3
SHUFFLE_WEBHOOK_URL=http://127.0.0.1:{mock.server_address[1]}/api/v1/webhooks/webhook_test123456
ENABLE_TEST_ACTIONS=false
ENABLE_PROD_ACTIONS=false
''')
        proc = subprocess.Popen([sys.executable,str(HERE/'bridge.py')],
                                env={**os.environ,'AEGISMESH_SOAR_ENV':str(cfg)},
                                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            base=f'http://127.0.0.1:{port}'
            for _ in range(60):
                try:
                    req(base+'/health'); break
                except Exception:time.sleep(.1)
            decision_id = 'tst-'+secrets.token_hex(8)
            payload={'decision_id':decision_id,'incident_id':'TEST-BRIDGE-001','tag':'OBSERVE',
                     'confidence':0.5,'approved':False,'evidence_ids':[], 'target':{},
                     'expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5)).isoformat()}
            assert req(base+'/v1/decisions',payload,TOKEN_A)[0]==202
            for _ in range(50):
                if MockShuffle.received: break
                time.sleep(.1)
            assert MockShuffle.received[0]['decision_id']==decision_id,'Shuffle mock did not receive decision'
            for _ in range(20):
                current=req(base+'/v1/decisions/'+decision_id,token=TOKEN_A)[1]
                if current['delivery']=='accepted_by_shuffle': break
                time.sleep(.1)
            assert current['delivery']=='accepted_by_shuffle',current
            _,action=req(base+'/v1/execute',{'decision_id':decision_id,'execution_id':'shuffle-test-0000001'},TOKEN_B)
            assert action['status']=='executed',action
            assert action['detail']['external_action'] is False,action
            _,again=req(base+'/v1/execute',{'decision_id':decision_id,'execution_id':'shuffle-test-0000001'},TOKEN_B)
            assert again['duplicate'] is True
            _,final=req(base+'/v1/decisions/'+decision_id,token=TOKEN_A)
            assert final['action_status']=='executed',final
            # Deny even a signed remote action without expected decision
            try:
                req(base+'/v1/execute',{'decision_id':'unknown000','execution_id':'shuffle-test-0000002'},TOKEN_B)
                raise AssertionError('unknown action accepted')
            except urllib.error.HTTPError as e:
                assert e.code==404
            print('PASS: authenticated decision -> webhook -> execution callback -> persisted result')
            print('PASS: duplicate execution rejected idempotently; unknown decision rejected')
            print('PASS: test environment did not invoke Wazuh, Fail2ban, or a real Shuffle workflow')
        finally:
            proc.terminate()
            proc.wait(timeout=3)
            mock.shutdown()

if __name__=='__main__':main()
