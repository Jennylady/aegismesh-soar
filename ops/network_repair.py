#!/usr/bin/env python3
"""AEGISMESH SOAR: safe, opt-in UFW rule for Shuffle bridge -> local bridge.

Only this repository's private bridge can be reached, from the verified Shuffle
Docker network. No port publishing, global UFW restart, or default policy changes.
"""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

NETWORK = 'aegismesh-shuffle_shuffle'
MARKER = 'AEGISMESH-SOAR-SHUFFLE-19081'
ENV = Path('/etc/aegismesh-soar/soar.env')

class RepairError(Exception): pass

def run(argv, timeout=15):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepairError(f"{argv[0]}: {type(exc).__name__}") from exc

def checked(argv, timeout=15):
    p = run(argv, timeout)
    if p.returncode:
        raise RepairError(f"{argv[0]}: code {p.returncode}; {(p.stderr or p.stdout).strip()[:220]}")
    return p.stdout

def read_private_config(path=ENV):
    cfg={}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#') or '=' not in line: continue
        key,val=line.split('=',1)
        if key in ('SOAR_BIND_HOST','SOAR_PORT'): cfg[key]=val.strip()
    return cfg

def policy(network, host, port, addr_list):
    if network.get('Driver')!='bridge' or network.get('Name')!=NETWORK:
        raise RepairError('Réseau Shuffle non reconnu (driver/name)')
    cfg=(network.get('IPAM') or {}).get('Config') or []
    if len(cfg)!=1: raise RepairError('IPAM Shuffle ambigu; vérification manuelle requise')
    ipam=cfg[0]
    subnet=ipaddress.ip_network(ipam.get('Subnet',''), strict=True)
    gateway=ipaddress.ip_address(ipam.get('Gateway',''))
    binding=ipaddress.ip_address(host)
    if subnet.version != 4 or not subnet.is_private or gateway not in subnet:
        raise RepairError('Sous-réseau non IPv4 privé')
    if binding!=gateway or port!=19081:
        raise RepairError('Le bridge doit écouter strictement sur la passerelle Docker Shuffle, port 19081')
    netid=network.get('Id','')
    custom=(network.get('Options') or {}).get('com.docker.network.bridge.name','')
    interface=custom if custom else 'br-'+netid[:12]
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{2,30}',interface):
        raise RepairError('Interface non valide')
    matches=[x for x in addr_list if x.get('ifname')==interface and any(
        a.get('family')=='inet' and a.get('local')==str(gateway) for a in x.get('addr_info',[]))]
    if len(matches)!=1: raise RepairError('Passerelle ou interface Docker non vérifiée sur l’hôte')
    return interface,str(subnet),str(gateway)

def rule_args(interface, subnet, gateway, port=19081):
    # UFW INPUT: a container accessing the gateway is addressing the host, not forwarding.
    return ['allow','in','on',interface,'proto','tcp','from',subnet,'to',gateway,
            'port',str(port),'comment',MARKER]

def setup():
    if os.geteuid()!=0: raise RepairError('Exécuter en root')
    cfg=read_private_config()
    host=cfg.get('SOAR_BIND_HOST','')
    port=int(cfg.get('SOAR_PORT','0'))
    network=json.loads(checked(['docker','network','inspect',NETWORK]))
    if not isinstance(network,list) or len(network)!=1: raise RepairError('Inspect Docker incomplet')
    addr=json.loads(checked(['ip','-j','-4','addr','show']))
    iface,subnet,gateway=policy(network[0],host,port,addr)
    status=checked(['ufw','status','verbose'])
    if not re.search(r'(?im)^Status:\s+active\s*$',status):
        raise RepairError('UFW n’est pas actif; ne pas modifier le pare-feu')
    return iface,subnet,gateway,status

def check_reachability():
    p=run([sys.executable,str(Path(__file__).resolve().with_name('network_probe.py'))],timeout=20)
    print(p.stdout.rstrip())
    if p.returncode and p.stderr: print(p.stderr[-400:],file=sys.stderr)
    return p.returncode==0

def main(action='repair'):
    try:
        iface,subnet,gateway,status=setup()
        print(f'Réseau vérifié : {NETWORK} | interface={iface} | source={subnet} | destination={gateway}:19081/tcp')
        if action=='repair':
            if MARKER in status:
                print('[INFO] Autorisation SOAR déjà présente ; aucune règle ajoutée')
                return 0 if check_reachability() else 3
            if any('19081' in line and iface in line for line in status.splitlines()):
                raise RepairError('Une règle existante touche déjà cette interface/port; correction automatique refusée')
            args=rule_args(iface,subnet,gateway)
            print('[ACTION] Ajout UFW strictement limité à l’interface privée Shuffle')
            checked(['ufw','insert','1']+args,timeout=25)
            if check_reachability():
                print('[OK] Orborus atteint le bridge HTTP. Vérifier ensuite le worker HTTP réel.')
                return 0
            print('[AVERTISSEMENT] Le test échoue encore ; suppression de la règle ajoutée')
            checked(['ufw','--force','delete']+args,timeout=25)
            print('[OK] Règle temporaire retirée; aucun élargissement conservé')
            return 3
        if action=='undo':
            if MARKER not in status:
                print('[INFO] Aucune règle AEGISMESH-SOAR à retirer')
                return 0
            checked(['ufw','--force','delete']+rule_args(iface,subnet,gateway),timeout=25)
            print('[OK] Règle SOAR retirée')
            return 0
        raise RepairError('Action non reconnue')
    except (ValueError,KeyError,FileNotFoundError,json.JSONDecodeError,RepairError) as exc:
        print('[ECHEC]',str(exc))
        return 2

if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1] not in ('repair','undo') or sys.argv[2]!='--confirm':
        print('Usage: network_repair.py repair|undo --confirm')
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
