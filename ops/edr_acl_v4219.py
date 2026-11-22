#!/usr/bin/env python3
"""AEGISMESH LAB 001: guarded, time-limited permission window for Velociraptor.

EXECVE + NETWORK are high privilege across the Velociraptor organisation,
not just LAB 001. Never grant them silently or permanently.
A systemd timer revokes these permissions after 12 minutes, even if the
operator forgets. The original policy is backed up and restored exactly.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ops import edr_velociraptor as edr
from ops import edr_setup_v371 as setup

PRINCIPAL='AEGISMESH_SOAR_API'
WINDOW_SECONDS=720
STATE=Path('/var/lib/aegismesh-soar/edr-lab-acl-v4219.json')
TIMER='aegismesh-soar-edr-acl-expiry.timer'
SERVICE='aegismesh-soar-edr-acl-expiry.service'
OWNER='X-Aegismesh-Soar-Managed=yes'


def _run(args, timeout=30):
    try:
        return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RuntimeError('Commande locale Velociraptor inaccessible: '+type(exc).__name__) from None


def _container():
    c=edr.read_json(edr.CONF,{})
    if c.get('mode')!='docker':raise RuntimeError('Seul Velociraptor Docker est autorisé')
    c=edr.validate_config(c)
    meta=setup.probe(c['container'])
    if not meta['binary'] or not meta['server_config']:
        raise RuntimeError('Binaire ou configuration serveur Velociraptor absent')
    return c,meta


def _command(c,meta,*args):
    return ['docker','exec','--user','0',c['container'],meta['binary'],
            '--config',meta['server_config'], 'acl',*args]


def _parse_policy(raw):
    try: value=json.loads(raw.strip())
    except ValueError:raise RuntimeError('ACL Velociraptor illisible ou non JSON') from None
    if not isinstance(value,dict):raise RuntimeError('ACL Velociraptor non structurée')
    return value


def _show(c,meta,effective=False):
    args=('show','--effective',PRINCIPAL) if effective else ('show',PRINCIPAL)
    p=_run(_command(c,meta,*args),timeout=20)
    if p.returncode:raise RuntimeError('Lecture ACL impossible (code '+str(p.returncode)+')')
    return _parse_policy(p.stdout)


def _baseline(policy):
    roles=policy.get('roles')
    if not isinstance(roles,list) or set(roles)!={'api','investigator'} or len(roles)!=2:
        raise PermissionError('Rôles API existants atypiques : ACL non modifiées')
    extras={k:v for k,v in policy.items() if k!='roles' and v not in (None,False,0,'',[],{})}
    if extras:raise PermissionError('Permissions API personnalisées existantes : ACL non modifiées')


def _read():return edr.read_json(STATE,{})


def _timer_files():
    for name in (TIMER,SERVICE):
        src=ROOT/'ops'/'systemd'/name
        dst=Path('/etc/systemd/system')/name
        content=src.read_text(encoding='utf-8')
        if OWNER not in content:raise RuntimeError('Unité système non marquée comme gérée')
        if dst.exists() and (OWNER not in dst.read_text(encoding='utf-8')):
            raise PermissionError('Unité systemd non gérée : '+name)
        if dst.is_symlink():raise PermissionError('Unité systemd symbolique refusée : '+name)
        dst.write_text(content,encoding='utf-8')
        os.chmod(dst,0o644)
    for cmd in (['systemctl','daemon-reload'],['systemctl','enable','--now',TIMER]):
        p=_run(cmd,timeout=30)
        if p.returncode:raise RuntimeError('Activation timer refusée ('+cmd[1]+')')
    p=_run(['systemctl','is-active','--quiet',TIMER],timeout=10)
    if p.returncode:raise RuntimeError('Timer d expiration ACL inactif : pas d autorisation accordée')


def _grant(c,meta,policy):
    p=_run(_command(c,meta,'grant',PRINCIPAL,
                    json.dumps(policy,sort_keys=True,separators=(',',':'))),timeout=30)
    if p.returncode:raise RuntimeError('acl grant refusé (code '+str(p.returncode)+')')


def _replace(c,meta,policy):
    p=_run(_command(c,meta,'grant',PRINCIPAL,
                    json.dumps(policy,sort_keys=True,separators=(',',':'))),timeout=30)
    if p.returncode:raise RuntimeError('acl restore refusé (code '+str(p.returncode)+')')


def _restart(c):
    p=_run(['docker','restart','--time','10',c['container']],timeout=50)
    if p.returncode:raise RuntimeError('Redémarrage Velociraptor refusé (code '+str(p.returncode)+')')


def _validated(eff):
    return eff.get('execve') is True and eff.get('network') is True and eff.get('collect_client') is True


def info():
    edr.require_root()
    c,meta=_container();pol=_show(c,meta);eff=_show(c,meta,True)
    saved=_read(); expires=saved.get('expires_at')
    return {'principal':PRINCIPAL,'roles':pol.get('roles',[]),
      'collect_client':eff.get('collect_client') is True,
      'execve':eff.get('execve') is True,'network':eff.get('network') is True,
      'temporary_acl_active':bool(saved) and _validated(eff),
      'temporary_acl_expires_at':expires,
      'no_new_quarantine_started':True,
      'warning':'EXECVE/NETWORK sont des permissions org-wide, pas limitées a 001'}


def require_active_lab_acl():
    data=_read();expires=data.get('expires_at')
    if not expires:raise PermissionError('ACL Quarantine absentes : edr lab-acl grant --confirm --allow-restart')
    when=dt.datetime.fromisoformat(expires)
    if when.tzinfo is None or when<=dt.datetime.now(dt.timezone.utc):
        raise PermissionError('Fenêtre de permissions EDR expirée; aucune isolation')
    c,meta=_container();eff=_show(c,meta,True)
    if not _validated(eff):raise PermissionError('ACL Quarantine non effectives malgré état local')
    return True


def enable(*,confirm=False,allow_restart=False):
    edr.require_root()
    if not(confirm and allow_restart):
        raise PermissionError('Accepter explicitement les ACL élevées et un redémarrage: --confirm --allow-restart')
    if _read():raise PermissionError('ACL temporaires déjà suivies : vérifier status ou restore')
    # Do not grant new privileges in the presence of a running or ambiguous lab containment.
    from ops import edr_direct_v4217 as direct
    if direct._read() or edr.read_json(edr.LEASES,{}):
        raise PermissionError('Bail d isolation existant : ACL non modifiées')
    c,meta=_container();policy=_show(c,meta);eff=_show(c,meta,True)
    _baseline(policy)
    if eff.get('execve') or eff.get('network'):
        raise PermissionError('ACL déjà élevées par un tiers : refus de prendre possession')
    _timer_files()   # independent rollback is armed BEFORE any elevated permission
    now=dt.datetime.now(dt.timezone.utc)
    state={'principal':PRINCIPAL,'original_policy':policy,
      'created_at':now.isoformat(),
      'expires_at':(now+dt.timedelta(seconds=WINDOW_SECONDS)).isoformat(),
      'state':'grant_pending'}
    edr.atomic_json(STATE,state)
    try:
        # Explicitly include original roles because ACL grant replaces, not appends.
        # We do not rely on version-dependent --merge behavior.
        granted_policy=dict(policy,execve=True,network=True)
        _grant(c,meta,granted_policy)
        _restart(c)
        if not _validated(_show(c,meta,True)):
            raise RuntimeError('ACL élevées non effectives après redémarrage; le timer restaurera')
        # Readback of raw policy preserves original roles; never assume grant success.
        updated=_show(c,meta)
        if set(updated.get('roles',[])) != {'api','investigator'}:
            raise RuntimeError('Rôles API modifiés : restauration par le timer requise')
        state['state']='granted_verified';edr.atomic_json(STATE,state)
    except Exception:
        # The timer remains enabled and the private snapshot remains available.
        raise
    return {'status':'temporary_acl_verified','principal':PRINCIPAL,
      'execve':True,'network':True,'expires_at':state['expires_at'],
      'rollback_timer_enabled':True,'isolation_started':False,
      'scope_warning':'Permissions couvrent le serveur et ses clients, et ne sont pas limitables a 001 par cet ACL'}


def restore(*,confirm=False,allow_restart=False,automatic=False):
    edr.require_root()
    if not automatic and not(confirm and allow_restart):
        raise PermissionError('Restaurer avec --confirm --allow-restart')
    state=_read()
    if not state:return {'restored':False,'reason':'nothing_to_restore'}
    if state.get('principal') != PRINCIPAL or not isinstance(state.get('original_policy'),dict):
        raise PermissionError('État ACL local corrompu : refuser restauration non sûre')
    c,meta=_container();current=_show(c,meta)
    original=state['original_policy'];_baseline(original)
    if set(current.get('roles',[])) != set(original['roles']):
        raise PermissionError('ACL changées par un tiers (rôles), restauration automatique refusée')
    # Grant may have failed before changing anything. Clean up an untouched
    # snapshot without restarting or overwriting anyone's policy.
    if current==original:
        edr.atomic_json(STATE,{})
        return {'status':'original_acl_unchanged','principal':PRINCIPAL,
                'auto':automatic,'restart_required':False}
    # Restore only when the expected temporary elevation is present; never
    # overwrite another administrator's concurrent ACL changes.
    expected=dict(original,execve=True,network=True)
    def _is_default(v):return v in (None,False,0,'',[],{})
    if any(current.get(k)!=v for k,v in expected.items()):
        raise PermissionError('ACL changées par un tiers; restauration automatique refusée')
    if any(k not in expected and not _is_default(v) for k,v in current.items()):
        raise PermissionError('ACL supplémentaires inattendues; restauration refusée')
    _replace(c,meta,original)
    _restart(c)
    after=_show(c,meta,True)
    if after.get('execve') or after.get('network'):
        raise RuntimeError('Permissions élevées encore effectives; conserver l état local')
    if set(_show(c,meta).get('roles',[]))!=set(original['roles']):
        raise RuntimeError('Rôles d origine non confirmés')
    edr.atomic_json(STATE,{})
    return {'status':'original_acl_restored','principal':PRINCIPAL,
        'execve':False,'network':False,'auto':automatic}


def expire():
    edr.require_root();state=_read()
    if not state:return {'status':'no_active_acl'}
    try: deadline=dt.datetime.fromisoformat(state['expires_at'])
    except (KeyError,ValueError,TypeError):return {'status':'invalid_acl_deadline_needs_operator'}
    if deadline.tzinfo is None:return {'status':'invalid_acl_timezone_needs_operator'}
    if dt.datetime.now(dt.timezone.utc)<deadline:return {'status':'acl_not_yet_expired'}
    return restore(automatic=True)


def main(argv=None):
    p=argparse.ArgumentParser(description='Permissions Quarantine LAB temporaires / ACL Velociraptor')
    p.add_argument('action',choices=('status','grant','restore','expire'))
    p.add_argument('--confirm',action='store_true')
    p.add_argument('--allow-restart',action='store_true')
    a=p.parse_args(argv)
    try:
        if a.action=='status':result=info()
        elif a.action=='grant':result=enable(confirm=a.confirm,allow_restart=a.allow_restart)
        elif a.action=='restore':result=restore(confirm=a.confirm,allow_restart=a.allow_restart)
        else:result=expire()
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0
    except (RuntimeError,ValueError,PermissionError,OSError,FileNotFoundError) as exc:
        print('AEGISMESH LAB ACL : '+str(exc)[:300],file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
