#!/usr/bin/env python3
"""Install narrowly scoped Wazuh manager alert rules for SOAR evidence.

No action is taken unless --apply --confirm. Existing non-owned rule files
and settings are never modified. Wazuh manager restart is limited to an
explicitly confirmed apply; rollback is attempted on failure.
"""
import argparse
import datetime
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tempfile
import socket
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT/'ops/wazuh/rules/aegismesh-soar-evidence.xml'
DEST = Path('/var/ossec/etc/rules/aegismesh-soar-evidence.xml')
BACKUPS = Path('/var/lib/aegismesh-soar/wazuh-rule-backups')
IDS = {'119870', '119871', '119872', '119873', '119874', '119875', '119876', '119877', '119878'}


class WazuhAPIReadinessError(RuntimeError):
    """Rule deployment succeeded but the manager's HTTP API is not listening yet."""


def wait_api_socket(*, timeout=55, interval=1.5, connector=None, monotonic=None, sleeper=None):
    """Wait for Wazuh loopback port after restart; never uses insecure HTTPS options."""
    dial=connector or socket.create_connection
    clock=monotonic or time.monotonic
    sleep=sleeper or time.sleep
    deadline=clock()+timeout
    while True:
        try:
            connection=dial(('127.0.0.1',55000),1.5)
            connection.close()
            return True
        except (OSError,TimeoutError):
            if clock()>=deadline:
                return False
            sleep(min(interval,max(deadline-clock(),0)))


def check_collisions(dest=DEST, rules_dir=Path('/var/ossec/etc/rules')):
    conflicts=[]
    for path in rules_dir.glob('*.xml'):
        if path.resolve() == dest.resolve():
            continue
        try:
            rules = ET.parse(path).getroot().iter('rule')
            for rule in rules:
                if rule.attrib.get('id') in IDS:
                    conflicts.append(str(path))
        except ET.ParseError:
            # Do not alter unrelated legacy rules, Wazuh -t will validate them.
            continue
    return conflicts


def command(cmd, timeout=25):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def install(*, apply=False, confirm=False, dest=DEST, template=TEMPLATE, rules_dir=None,
            restart=True, runner=command, api_waiter=None):
    content=template.read_bytes()
    ET.fromstring(content)
    if not apply:
        return 'PREVIEW: règles 119870/119871/119872/119873/119874/119875/119876, redémarrage Wazuh uniquement avec --apply --confirm'
    if not confirm or os.geteuid()!=0:
        raise PermissionError('root et --apply --confirm requis')
    conflicts=check_collisions(dest, rules_dir or dest.parent)
    if conflicts:
        raise RuntimeError('ID de règle Wazuh déjà utilisé: '+', '.join(conflicts))
    dest.parent.mkdir(parents=True, exist_ok=True)
    previous=dest.read_bytes() if dest.exists() else None
    if previous == content:
        return 'OK: règles SOAR déjà installées, aucun redémarrage nécessaire'
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    if previous is not None:
        backup=BACKUPS/(dest.name+'.'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.bak')
        backup.write_bytes(previous)
        backup.chmod(0o600)
    fd,temp=tempfile.mkstemp(prefix='.aegismesh-evidence-', dir=str(dest.parent))
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(content)
        os.chmod(temp,0o644)
        os.replace(temp,dest)
        test=runner(['/var/ossec/bin/wazuh-analysisd','-t'],timeout=40)
        if test.returncode:
            raise RuntimeError('wazuh-analysisd -t refuse les règles, code='+str(test.returncode))
        if restart:
            result=runner(['systemctl','restart','wazuh-manager.service'],timeout=90)
            if result.returncode:
                raise RuntimeError('redémarrage Wazuh échoué, code='+str(result.returncode))
            ready=runner(['systemctl','is-active','--quiet','wazuh-manager.service'],timeout=15)
            if ready.returncode:
                raise RuntimeError('Wazuh manager inactif après redémarrage')
            waiter=api_waiter or wait_api_socket
            if not waiter():
                raise WazuhAPIReadinessError('Règles SOAR installées et Wazuh manager actif, mais API HTTPS 127.0.0.1:55000 indisponible après attente; exécuter aegismesh-soar ad doctor puis ad recover --confirm')
        return 'OK: règles SOAR installées et Wazuh manager validé'
    except WazuhAPIReadinessError:
        # Do not roll back valid alert rules or restart Wazuh again just because
        # the separately started API daemon is late/unavailable.
        raise
    except Exception:
        if previous is None:
            dest.unlink(missing_ok=True)
        else:
            dest.write_bytes(previous)
            os.chmod(dest,0o644)
        if restart:
            try: runner(['systemctl','restart','wazuh-manager.service'],timeout=90)
            except Exception: pass
        raise
    finally:
        try: os.unlink(temp)
        except FileNotFoundError: pass


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--apply',action='store_true')
    p.add_argument('--confirm',action='store_true')
    a=p.parse_args()
    try:
        print(install(apply=a.apply,confirm=a.confirm))
    except Exception as e:
        print('ECHEC:',str(e)[:200],file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':sys.exit(main())
