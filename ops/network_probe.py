#!/usr/bin/env python3
"""Lecture seule: diagnostic du transport Orborus -> bridge dans le namespace Docker.

Ne crée aucune règle de pare-feu, aucun conteneur et n'envoie aucun secret.
Le worker Shuffle peut utiliser un autre namespace; son trajet exige un test séparé.
"""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys

ENV_FILE=Path('/etc/aegismesh-soar/soar.env')

def get_config():
    cfg={'SOAR_BIND_HOST':'127.0.0.1','SOAR_PORT':'19081'}
    try:
        for line in ENV_FILE.read_text().splitlines():
            if '=' not in line or line.lstrip().startswith('#'): continue
            name,value=line.split('=',1)
            if name in cfg: cfg[name]=value
    except OSError: pass
    return cfg

def run(args, timeout=8):
    try:
        return subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        print('Impossible d’exécuter la sonde :',type(exc).__name__)
        return None

def main():
    cfg=get_config()
    host=cfg['SOAR_BIND_HOST']
    try:
        addr=ipaddress.ip_address(host)
        port=int(cfg['SOAR_PORT'])
        if not 1 <= port <= 65535: raise ValueError()
    except ValueError:
        print('[ECHEC] Configuration du bind/port non valide');return 2
    if not addr.is_private and not addr.is_loopback:
        print('[ECHEC] Le bridge ne doit pas être exposé sur une adresse publique');return 2
    print('AEGISMESH-SOAR | Portée Docker → Bridge | lecture seule')
    print('Cible:',host+':'+str(port))
    probe_code=(
        'import sys,urllib.request,urllib.error,json;'
        'u="http://"+sys.argv[1]+":"+sys.argv[2]+"/health";'
        'op=urllib.request.build_opener(urllib.request.ProxyHandler({}));'
        'r=op.open(u,timeout=4);'
        'print("HTTP",r.status,"status",json.load(r).get("status","?"))'
    )
    local=run([sys.executable,'-c',probe_code,host,str(port)])
    if local is not None and local.returncode==0:
        print('[OK] Depuis l’hôte :',local.stdout.strip())
    else:
        print('[ECHEC] Depuis l’hôte :',((local.stderr or '').strip().splitlines()[-1] if local and local.stderr else 'indisponible'))
    info=run(['docker','inspect','-f','{{.State.Pid}}','shuffle-orborus'])
    if info is None or info.returncode or not info.stdout.strip().isdigit() or int(info.stdout.strip())<2:
        print('[A_VERIFIER] Orborus inaccessible ou inactif');return 1
    pid=info.stdout.strip()
    route=run(['nsenter','-t',pid,'-n','--','ip','route','get',host])
    if route and route.returncode==0: print('[INFO] Route Orborus:',route.stdout.strip()[:240])
    probe=run(['nsenter','-t',pid,'-n','--',sys.executable,'-c',probe_code,host,str(port)],timeout=7)
    if probe is not None and probe.returncode==0:
        print('[OK] Depuis le réseau Orborus :',probe.stdout.strip())
        print('[INFO] Tester également depuis le conteneur worker/action réel dans Shuffle.')
        return 0
    err=(probe.stderr or '').strip().splitlines()[-1] if probe and probe.stderr else 'sonde impossible'
    print('[ECHEC] Depuis le réseau Orborus :',err[:280])
    print('[DIAGNOSTIC] La santé locale ne prouve pas l’accès depuis Docker.')
    print('[DIAGNOSTIC] Vérifier INPUT nftables/iptables et l’interface du réseau Shuffle,')
    print('             puis le réseau des workers. Ne pas autoriser 19081 sur 0.0.0.0.')
    print('             Aucun changement de pare-feu n’a été effectué.')
    return 1

if __name__=='__main__': sys.exit(main())
