#!/usr/bin/env python3
"""Safe Shuffle Orborus pipeline suspension for the Wazuh 1514/TCP conflict.

Only changes the already identified Compose `orborus` service environment;
never starts, stops, deletes or changes Wazuh, Docker networks, or Tenzir.
A backup is saved outside Git, and deployment is limited to one service.
"""
from __future__ import annotations
import copy
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time

from ops import audit_v42 as audit

COMPOSE=Path('/opt/aegismesh/integrations/shuffle/compose.yaml')
BACKUPS=Path('/var/lib/aegismesh-soar/compose-backups')
PROJECT='aegismesh-shuffle'
SERVICE='orborus'
ORBORUS_NAME='shuffle-orborus'
FLAG_VALUES={'SHUFFLE_SKIP_PIPELINES':'true','SHUFFLE_PIPELINE_ENABLED':'false'}
MARK='# AEGISMESH-SOAR V4.2.2: pipelines Tenzir suspendus (Wazuh conserve 1514/TCP)'


def compose_config(path=COMPOSE):
    p=audit.command(['docker','compose','-f',str(path),'-p',PROJECT,'config','--format','json'],timeout=35)
    if p.returncode:
        raise audit.AuditError('Docker Compose config invalide (code %d); détails conservés côté hôte' % p.returncode)
    try:
        obj=json.loads(p.stdout)
        if not isinstance(obj,dict) or not isinstance(obj.get('services'),dict):raise ValueError()
        return obj
    except (ValueError,TypeError) as e:
        raise audit.AuditError('Docker Compose n a pas renvoyé une configuration JSON valide') from e


def environment_map(data):
    if data is None:return {}
    if isinstance(data,dict):return {str(k):str(v) for k,v in data.items()}
    if isinstance(data,list):
        out={}
        for v in data:
            key,sep,val=str(v).partition('=')
            if not sep:raise audit.AuditError('Variables Compose non explicites; refus')
            out[key]=val
        return out
    raise audit.AuditError('Format de variables Orborus inconnu')


def service_config_check(before,after):
    b=before['services']; a=after['services']
    if set(a)!=set(b) or SERVICE not in b:raise audit.AuditError('Services Compose différents après modification')
    for k in b:
        if k!=SERVICE and b[k]!=a[k]:raise audit.AuditError('Modification indirecte du service '+k)
    orig=copy.deepcopy(b[SERVICE]); changed=copy.deepcopy(a[SERVICE])
    old_env=environment_map(orig.pop('environment',{})); new_env=environment_map(changed.pop('environment',{}))
    if orig!=changed:raise audit.AuditError('Orborus: un champ hors environnement a changé')
    for flag,value in FLAG_VALUES.items():
        if new_env.get(flag)!=value:raise audit.AuditError('Orborus: flag '+flag+' absent du Compose final')
    if {k:v for k,v in new_env.items() if k not in FLAG_VALUES}!={k:v for k,v in old_env.items() if k not in FLAG_VALUES}:
        raise audit.AuditError('Autres variables Orborus modifiées : opération refusée')
    return old_env


def add_flags(text):
    """Allow conventional 2-space YAML only; reject ambiguous layouts."""
    lines=text.splitlines(keepends=True)
    if '\t' in text:raise audit.AuditError('Tabs YAML interdits pour cette modification contrôlée')
    # Only edit an unambiguous service key at the same indentation under services:
    srv_indices=[i for i,l in enumerate(lines) if re.match(r'^  orborus:\s*(?:#.*)?$',l.rstrip('\r\n'))]
    if len(srv_indices)!=1:raise audit.AuditError('Bloc Compose services.orborus introuvable ou ambigu')
    start=srv_indices[0]
    end=next((i for i in range(start+1,len(lines)) if re.match(r'^  [A-Za-z0-9_.-]+:\s*(?:#.*)?$',lines[i].rstrip('\r\n')) or re.match(r'^[A-Za-z0-9_.-]+:\s*(?:#.*)?$',lines[i].rstrip('\r\n'))),len(lines))
    scope=lines[start:end]
    sections=[(i,l) for i,l in enumerate(scope) if re.match(r'^    environment:\s*(?:#.*)?$',l.rstrip('\r\n'))]
    if len(sections)>1:raise audit.AuditError('Orborus: plusieurs sections environment')
    newline='\r\n' if '\r\n' in text else '\n'
    if not sections:
        insert=[f'    environment:{newline}',f'      {MARK}{newline}',
                *(f'      {k}: "{v}"{newline}' for k,v in FLAG_VALUES.items())]
        return ''.join(lines[:start+1]+insert+lines[start+1:])
    idx=sections[0][0]
    section_end=next((j for j in range(idx+1,len(scope)) if re.match(r'^    [A-Za-z0-9_.-]+:\s*',scope[j])),len(scope))
    content=scope[idx+1:section_end]
    non_comment=[x for x in content if x.strip() and not x.lstrip().startswith('#')]
    kinds={'list' if re.match(r'^      -\s+',x) else 'map' if re.match(r'^      [A-Za-z0-9_]+:\s*',x) else 'unknown' for x in non_comment}
    if 'unknown' in kinds or len(kinds)>1:raise audit.AuditError('Format de environment Orborus inhabituel')
    kind=next(iter(kinds),'map')
    # Reject preexisting flags to avoid overriding a user-defined policy.
    if any(re.search(r'\b'+k+r'\b',x) for k in FLAG_VALUES for x in content):
        raise audit.AuditError('Orborus configure déjà une politique pipeline: ne pas la remplacer')
    additions=[f'      {MARK}{newline}']
    for k,v in FLAG_VALUES.items():
        additions.append(f'      - {k}={v}{newline}' if kind=='list' else f'      {k}: "{v}"{newline}')
    return ''.join(lines[:start+section_end]+additions+lines[start+section_end:])


def _wazuh_owns_tcp_1514():
    p=audit.command(['ss','-lntp'],timeout=6)
    return p.returncode==0 and any('wazuh-remoted' in line and re.search(r'(?<!\d):1514\s',line) for line in p.stdout.splitlines())


def _running_container(name):
    obj=audit.docker_object('container',name)
    return bool(obj and (obj.get('State') or {}).get('Status')=='running')


def _container_composition_ok():
    o=audit.docker_object('container',ORBORUS_NAME)
    labels=(o or {}).get('Config',{}).get('Labels') or {}
    return bool(o and labels.get('com.docker.compose.project')==PROJECT
      and labels.get('com.docker.compose.service')==SERVICE
      and labels.get('com.docker.compose.project.config_files')==str(COMPOSE))


def check_status():
    obj=audit.docker_object('container',ORBORUS_NAME)
    env=environment_map((obj or {}).get('Config',{}).get('Env',[])) if obj else {}
    flags={k:env.get(k) for k in FLAG_VALUES}
    return {'orborus_running':_running_container(ORBORUS_NAME),'compose_owner_verified':_container_composition_ok(),
            'wazuh_1514_tcp_owner': 'wazuh-remoted' if _wazuh_owns_tcp_1514() else 'not_verified',
            'pipeline_flags':flags,
            'pipelines_disabled':all(env.get(k)==v for k,v in FLAG_VALUES.items()),
            'tenzir_state':audit.tenzir_status().get('state'),
            'meaning':'Pipelines désactivés ne signifie pas Tenzir réparé'}


def disable_pipelines(*,confirm=False, wait_seconds=20):
    if not confirm:raise audit.AuditError('--confirm requis: recréation limitée du conteneur Orborus')
    if os.name!='posix' or os.geteuid()!=0:raise audit.AuditError('root Linux requis')
    if COMPOSE.is_symlink() or not COMPOSE.is_file():raise audit.AuditError('Compose Shuffle absent ou lien symbolique')
    if not _container_composition_ok():raise audit.AuditError('Orborus hors du projet Compose attendu')
    if not _wazuh_owns_tcp_1514():raise audit.AuditError('Propriétaire de 1514/TCP inattendu; opération refusée')
    if not all(_running_container(n) for n in ('shuffle-backend','shuffle-orborus')):
        raise audit.AuditError('Shuffle backend/Orborus non opérationnels avant modification')
    old_state=audit.tenzir_status()
    if old_state.get('state') not in ('broken_missing_network','created'):
        raise audit.AuditError('Panne réseau Tenzir non confirmée; pas de suspension automatique')
    current=COMPOSE.read_text(encoding='utf-8')
    before=compose_config()
    # Compose is checked against the actual running instance, before touching it.
    if SERVICE not in before['services']:raise audit.AuditError('Service orborus absent')
    existing=environment_map(before['services'][SERVICE].get('environment'))
    if all(existing.get(k)==v for k,v in FLAG_VALUES.items()):
        return {'status':'already_configured','note':'Pipelines explicitement désactivés; vérifier Orborus'}
    new=add_flags(current)
    if new==current:raise audit.AuditError('Aucune modification détectée')
    # Validate a temporary Compose copy IN THE SAME directory so relative paths work.
    # Avoid writing files containing secrets to arbitrary temp locations.
    tmp=COMPOSE.with_name('.aegismesh-soar-compose-v422.check.yaml')
    if tmp.exists():raise audit.AuditError('Fichier temporaire Compose préexistant; refus')
    try:
        fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as h:h.write(new)
        after=compose_config(tmp)
        service_config_check(before,after)
    finally:
        if tmp.exists():tmp.unlink()
    BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(BACKUPS,0o700)
    backup=BACKUPS/('compose-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(4).hex()+'.yaml')
    fd=os.open(str(backup),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as h:h.write(current.encode('utf-8'))
    origin_mode=stat.S_IMODE(COMPOSE.stat().st_mode)
    # Atomic edit; preserve permissions. Write in same directory, not source Git.
    temp=COMPOSE.with_name('.aegismesh-soar-compose-v422.pending.yaml')
    if temp.exists():raise audit.AuditError('Fichier Compose provisoire existant; refus')
    fd=os.open(str(temp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,origin_mode)
    with os.fdopen(fd,'w',encoding='utf-8') as h:h.write(new)
    os.chmod(temp,origin_mode)
    os.replace(temp,COMPOSE)
    try:
        # No --pull, no --build, no --deps. Only Orborus is recreated.
        audit.checked(['docker','compose','-f',str(COMPOSE),'-p',PROJECT,'up','-d','--no-deps','--no-build',SERVICE],timeout=90)
        if not _running_container(ORBORUS_NAME):raise audit.AuditError('Orborus non démarré après reprise')
        obj=audit.docker_object('container',ORBORUS_NAME)
        runtime=environment_map((obj.get('Config') or {}).get('Env',[]))
        if any(runtime.get(k)!=v for k,v in FLAG_VALUES.items()):
            raise audit.AuditError('Variables de suspension non appliquées au conteneur')
        if not _wazuh_owns_tcp_1514():raise audit.AuditError('Wazuh ne possède plus 1514/TCP après modification')
        time.sleep(wait_seconds)
        if not _running_container(ORBORUS_NAME):raise audit.AuditError('Orborus arrêté après validation')
        # Any new Tenzir start attempt proves the flags did not suppress it.
        p=audit.command(['docker','logs','--since',str(wait_seconds)+'s','--tail','100',ORBORUS_NAME],timeout=12)
        if p.returncode:raise audit.AuditError('Logs Orborus indisponibles pour validation')
        if re.search(r'Failed to start Tenzir Node|network tenzir-network not found',p.stdout+'\n'+p.stderr,re.I):
            raise audit.AuditError('Orborus tente toujours Tenzir: suspension inefficace')
        return {'status':'pipelines_disabled','wazuh_1514_tcp_preserved':True,
                'orborus_running':True,'tenzir_running':False,
                'backup':str(backup),'no_wazuh_change':True,
                'note':'Pipelines Shuffle/Tenzir suspendus; workers classiques à revalider via audit worker'}
    except (audit.AuditError,RuntimeError,OSError) as original:
        # If any postcondition fails, restore the file before a best-effort Orborus-only rollback.
        rollback_tmp=COMPOSE.with_name('.aegismesh-soar-compose-v422.rollback.yaml')
        try:
            fd=os.open(str(rollback_tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,origin_mode)
            with os.fdopen(fd,'w',encoding='utf-8') as h:h.write(current)
            os.chmod(rollback_tmp,origin_mode)
            os.replace(rollback_tmp,COMPOSE)
            rolled=audit.command(['docker','compose','-f',str(COMPOSE),'-p',PROJECT,'up','-d','--no-deps','--no-build',SERVICE],timeout=90)
            suffix='; rollback Compose '+('appliqué' if rolled.returncode==0 else 'non confirmé')
        except (OSError,audit.AuditError) as exc:
            suffix='; rollback échoué ('+type(exc).__name__+')'
        raise audit.AuditError(str(original)+suffix) from original
