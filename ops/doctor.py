#!/usr/bin/env python3
"""Read-only inventory of existing AEGISMESH SOAR infrastructure. No secrets."""
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET


def run(argv, timeout=8):
    try:
        p = subprocess.run(argv,capture_output=True,text=True,timeout=timeout,check=False)
        return p.returncode,p.stdout.strip(),p.stderr.strip()
    except (OSError,subprocess.TimeoutExpired):
        return 127,'','commande indisponible'


def emit(area, status, info):
    print(f'[{status}] {area}: {info}')


def active(service):
    rc, out, _ = run(['systemctl','is-active',service])
    return rc == 0 and out == 'active', out or 'inconnu'


def xmlblocks(path):
    if not path.is_file(): return None
    s=path.read_text(errors='replace')
    # Wazuh supports concatenated top-level ossec_config blocks.
    s=re.sub(r'<\?xml[^>]*\?>','',s)
    try:
        root=ET.fromstring('<aegismesh_document>'+s+'</aegismesh_document>')
    except ET.ParseError: return 'parse_error'
    return (len(root.findall('.//command')),len(root.findall('.//active-response')))


def main():
    print('AEGISMESH SOAR / inventaire en lecture seule')
    print('Aucune installation, action de sécurité, secret, restart ou webhook.')
    print('\n== Services existants ==')
    for svc in ('aegismesh-soar-bridge.service','aegismesh-shuffle-relay.service',
                'wazuh-manager.service','fail2ban.service','docker.service','aegismesh-api.service'):
        ok, state = active(svc)
        emit(svc,'OK' if ok else 'A_VERIFIER',state)
    print('\n== Wazuh ==')
    p=Path('/var/ossec/etc/ossec.conf')
    blocks=xmlblocks(p)
    emit('ossec.conf','INFO', 'commandes/liaisons='+str(blocks) if isinstance(blocks,tuple) else str(blocks))
    for binary in ('wazuh-execd','wazuh-analysisd'):
        b='/var/ossec/bin/'+binary
        if Path(b).exists():
            rc,_,_=run([b,'-t'])
            emit(binary+' -t','OK' if rc==0 else 'A_VERIFIER','code='+str(rc))
    # Agent inventory: no IPs, no user names; count only.
    rc,out,_=run(['/var/ossec/bin/agent_control','-l'])
    if rc == 0:
        connected = len(re.findall(r'^\s*ID:\s*\d+',out,re.M))
        emit('agents actifs','INFO',str(connected)+' enregistres / a confirmer')
    print('\n== Shuffle ==')
    for c in ('shuffle-backend','shuffle-frontend','shuffle-opensearch','shuffle-orborus'):
        rc,out,_=run(['docker','inspect','--format','{{.State.Status}}|{{.RestartCount}}',c])
        emit(c,'OK' if rc==0 and out.startswith('running|') else 'A_VERIFIER',out or 'introuvable')
    for url in ('http://127.0.0.1:15001/api/v1/health','http://127.0.0.1:18031/'):
        try:
            with urllib.request.urlopen(url,timeout=3) as response:
                emit(url,'OK' if response.status==200 else 'A_VERIFIER','HTTP '+str(response.status))
        except urllib.error.HTTPError as exc:
            emit(url,'A_VERIFIER','HTTP '+str(exc.code))
        except (urllib.error.URLError,TimeoutError):
            emit(url,'A_VERIFIER','pas de réponse')
    print('\n== Fail2ban ==')
    for argv in (['fail2ban-client','-t'],['fail2ban-client','ping']):
        rc,_,_=run(argv,timeout=12)
        emit(' '.join(argv),'OK' if rc==0 else 'A_VERIFIER','code='+str(rc))
    rc,out,_=run(['fail2ban-client','status'])
    m=re.search(r'Jail list:\s*(.+)',out)
    emit('jails existantes','INFO',m.group(1).strip() if m else 'inconnues')
    print('\n== Git/bridge ==')
    base=Path('/opt/aegismesh/soar')
    rc,out,_=run(['git','-C',str(base),'remote','get-url','origin'])
    # Never print a git remote URL: it may contain credentials in userinfo.
    emit('remote origin','INFO','configuré (URL masquée)' if rc==0 else 'pas encore initialisé')
    cfg=Path('/etc/aegismesh-soar/soar.env')
    emit('configuration privée','INFO','présente (non lue)' if cfg.exists() else 'non créée')
    if cfg.exists():
        port='19081'
        bind='127.0.0.1'
        for line in cfg.read_text().splitlines():
            if line.startswith('SOAR_PORT='):
                port=line.partition('=')[2]
            if line.startswith('SOAR_BIND_HOST='):
                bind=line.partition('=')[2]
        try:
            # Probe only a bound local interface, never use a proxy.
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open('http://'+bind+':'+port+'/health',timeout=3) as r:
                content=json.loads(r.read(1024))
                emit('pont SOAR','OK' if r.status==200 else 'A_VERIFIER','HTTP '+str(r.status)+' (sans action)')
        except (urllib.error.URLError,TimeoutError,ValueError):
            emit('pont SOAR','A_VERIFIER','non accessible en loopback')
    print('\nConclusion: disponibilité != preuve d’exécution Shuffle/AR/Fail2ban de bout en bout.')

if __name__=='__main__': main()
