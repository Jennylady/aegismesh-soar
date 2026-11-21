#!/usr/bin/env python3
"""Non-destructive inventory to help reach bridge from Shuffle workers."""
import json
import socket
import subprocess


def run(*args):
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=6)
        return p.stdout if p.returncode==0 else None
    except (OSError,subprocess.TimeoutExpired): return None


def main():
    print('AEGISMESH-SOAR | Réseau Shuffle → Bridge (lecture seule)')
    print('Le port du bridge ne doit pas être exposé publiquement.')
    ips=run('ip','-j','-4','addr','show')
    if ips:
        for info in json.loads(ips):
            for addr in info.get('addr_info',[]):
                v=addr.get('local','')
                if v.startswith(('127.','169.254.')): continue
                print('Interface hôte :',info.get('ifname'),v)
    for name in ('shuffle-backend','shuffle-frontend','shuffle-orborus'):
        raw=run('docker','inspect','--format','{{json .NetworkSettings.Networks}}',name)
        if not raw:
            print(name,'non inspectable');continue
        try: networks=json.loads(raw)
        except ValueError: continue
        for n,info in networks.items():
            print(name, 'réseau',n,'IPv4',info.get('IPAddress','inconnue'),
                  'gateway',info.get('Gateway','inconnue'))
    print('NB : les conteneurs workers d’exécution peuvent utiliser un autre réseau.')
    print('Ne pas configurer bind sans vérifier la portée et les règles de pare-feu.')

if __name__=='__main__':main()
