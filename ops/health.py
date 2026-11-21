#!/usr/bin/env python3
"""Bridge readiness, non-destructive and secret-free diagnostics."""
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

UNIT='aegismesh-soar-bridge.service'

def probe(host='127.0.0.1',port='19081',timeout=2):
    try:
        port=int(port)
        if port < 1 or port > 65535: return False, 'port invalide'
        url=f'http://{host}:{port}/health'
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url,timeout=timeout) as response:
            obj=json.loads(response.read(2048))
            if response.status == 200 and obj.get('service')=='aegismesh-soar-bridge' and obj.get('status')=='up':
                return True,'HTTP 200 / status=up'
            return False,f'HTTP {response.status} ou payload /health inattendu'
    except urllib.error.HTTPError as e: return False,f'HTTP {e.code}'
    except Exception as e: return False,type(e).__name__+': '+str(e)[:130]

def wait_ready(host,port,seconds=18):
    end=time.monotonic()+seconds
    reason='non testé'
    while time.monotonic()<end:
        ready,reason=probe(host,port)
        if ready: return True, reason
        time.sleep(0.65)
    return False,reason

def systemd():
    try:
        p=subprocess.run(['systemctl','show',UNIT,'--no-pager',
                          '-p','LoadState','-p','ActiveState','-p','SubState',
                          '-p','Result','-p','ExecMainStatus','-p','NRestarts','-p','MainPID'],
                         capture_output=True,text=True,timeout=6)
        return {k:v for k,v in (line.split('=',1) for line in p.stdout.splitlines() if '=' in line)}
    except (OSError,subprocess.TimeoutExpired): return {'error':'systemctl indisponible'}

def listening(port):
    try:
        p=subprocess.run(['ss','-lnt'],capture_output=True,text=True,timeout=5)
        return any(':'+str(port) in line.split()[3] for line in p.stdout.splitlines()[1:] if len(line.split())>3)
    except (OSError,subprocess.TimeoutExpired): return None

def print_diagnosis(cfg):
    host=cfg.get('SOAR_BIND_HOST','127.0.0.1')
    port=cfg.get('SOAR_PORT','19081')
    healthy,why=probe(host,port)
    print('Sonde HTTP locale :', 'OK' if healthy else 'ECHEC', '—',why)
    print('Bind/port configurés :',host,port)
    print('Port en écoute (ss) :',listening(port))
    for k,v in systemd().items(): print('systemd',k+':',v)
    if not healthy:
        print('Diagnostic recommandé (masquer les secrets avant partage) :')
        print('  journalctl -u '+UNIT+' --no-pager -n 60')
        print('  ss -lntp | grep :'+str(port))
        print('  systemctl status '+UNIT+' --no-pager')
    return healthy
