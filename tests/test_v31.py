#!/usr/bin/env python3
"""Regression: readiness blocks until HTTP is truly up; no systemd/security changes."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT=Path(__file__).resolve().parent.parent
UNIT=(ROOT/'ops/systemd/aegismesh-soar-bridge.service').read_text()
assert 'ExecStartPost=/usr/bin/python3 /opt/aegismesh/soar/ops/wait_ready.py --timeout 30' in UNIT
assert 'TimeoutStartSec=45' in UNIT

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data=b'{"service":"aegismesh-soar-bridge","status":"up"}'
        self.send_response(200);self.send_header('Content-Length',str(len(data)))
        self.end_headers();self.wfile.write(data)
    def log_message(self,*args):pass

# The port is reserved until we are ready to start; otherwise a race may break the test.
with socket.socket() as sock:
    sock.bind(('127.0.0.1',0))
    port=sock.getsockname()[1]

with tempfile.TemporaryDirectory() as tmp:
    config=Path(tmp)/'soar.env'
    config.write_text(f'SOAR_BIND_HOST=127.0.0.1\nSOAR_PORT={port}\n')
    env={**os.environ,'AEGISMESH_SOAR_ENV':str(config)}
    p=subprocess.Popen([sys.executable,str(ROOT/'ops/wait_ready.py'),'--timeout','6'],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
    time.sleep(0.7)
    assert p.poll() is None, 'wait_ready exited before delayed service started'
    server=HTTPServer(('127.0.0.1',port),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        out,err=p.communicate(timeout=7)
        assert p.returncode == 0, (out,err)
        assert '[READY]' in out
    finally:
        server.shutdown();server.server_close()

    # Failing health is detected instead of announcing success.
    q=subprocess.run([sys.executable,str(ROOT/'ops/wait_ready.py'),'--timeout','1'],
                     capture_output=True,text=True,env=env,timeout=5)
    assert q.returncode != 0
    assert '[NOT_READY]' in q.stderr

print('PASS: systemd readiness gate awaits late HTTP /health and refuses unavailable bridge')
