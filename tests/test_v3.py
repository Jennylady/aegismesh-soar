#!/usr/bin/env python3
"""V3 safety and operational smoke test; no systemd or security actions."""
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root))
from ops import health,ui

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload=b'{"service":"aegismesh-soar-bridge","status":"up"}'
        self.send_response(200)
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers();self.wfile.write(payload)
    def log_message(self,*args):pass

server=HTTPServer(('127.0.0.1',0),Handler)
th=threading.Thread(target=server.serve_forever,daemon=True);th.start()
try:
    port=str(server.server_port)
    assert health.probe('127.0.0.1',port)[0]
    assert health.wait_ready('127.0.0.1',port,seconds=2)[0]
finally:
    server.shutdown();server.server_close()

cli=root/'bin/aegismesh-soar'
# En absence de terminal interactif, l'interface doit sortir sans exception,
# quelle que soit la traduction/le texte d'aide affiche par la version CLI.
proc=subprocess.run(
    [sys.executable,str(cli),'configure'],
    input='', capture_output=True, text=True, timeout=15,
    env={**os.environ, 'NO_COLOR':'1', 'TERM':'dumb'}
)
assert proc.returncode == 0, f'configure sans TTY doit se terminer proprement: {proc.stderr[-300:]}'
assert 'Traceback' not in proc.stderr
assert 'the following arguments are required' not in proc.stderr

helptext=subprocess.check_output([sys.executable,str(cli),'--help'],text=True)
assert 'repo' in helptext and 'network' in helptext and 'configure' in helptext
h=subprocess.check_output([sys.executable,str(cli),'health','--help'],text=True)
assert '--verbose' in h
assert not ui.tty() if not sys.stdout.isatty() else True
print('PASS: santé HTTP V3, menu sans argument, aide CLI, réseau, dépôt privé')
