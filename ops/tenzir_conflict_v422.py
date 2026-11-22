#!/usr/bin/env python3
"""Safe reversible Orborus pipeline suspension via a dedicated Compose override.

Preserves the original Compose YAML irrespective of indentation or anchors.
Only Orborus is recreated; Wazuh, Tenzir and Docker networks are untouched.
"""
from __future__ import annotations
import copy
import datetime as dt
import json
import os
from pathlib import Path
import re
import time

from ops import audit_v42 as audit

COMPOSE=Path('/opt/aegismesh/integrations/shuffle/compose.yaml')
BACKUPS=Path('/var/lib/aegismesh-soar/compose-backups')
PROJECT='aegismesh-shuffle'
SERVICE='orborus'
ORBORUS_NAME='shuffle-orborus'
FLAG_VALUES={'SHUFFLE_SKIP_PIPELINES':'true','SHUFFLE_PIPELINE_ENABLED':'false'}
MARK='# AEGISMESH-SOAR V4.2.4: Orborus-only pipeline override (Wazuh 1514/TCP reserved)'
OVERRIDE=COMPOSE.with_name('compose.aegismesh-soar.override.yaml')
OVERRIDE_BODY=(MARK+'\nservices:\n  orborus:\n    environment:\n'
    '      SHUFFLE_SKIP_PIPELINES: \"true\"\n'
    '      SHUFFLE_PIPELINE_ENABLED: \"false\"\n')


def compose_args(*, override=None):
    args=['docker','compose','-f',str(COMPOSE)]
    if override is not None:args+=['-f',str(override)]
    return args+['-p',PROJECT]


def compose_config(path=None):
    # The base Compose file is always first, so relative paths and .env remain
    # anchored to the same project. A second file ONLY overlays Orborus flags.
    p=audit.command(compose_args(override=path)+['config','--format','json'],timeout=35)
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
    if set(before)!=set(after):raise audit.AuditError('Champs Compose principaux modifiés')
    for key in before:
        if key!='services' and before[key]!=after[key]:
            raise audit.AuditError('Champ Compose global modifié: '+key)
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


def _wazuh_owns_tcp_1514():
    """Verify the TCP listener's *local* port and actual process owner.

    `ss` columns: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process.
    Never infer ownership from a substring elsewhere in a row (e.g. the
    remote port or a process whose name merely contains 'wazuh-remoted').
    If the PID cannot be read, fail closed rather than altering Compose.
    """
    p=audit.command(['ss','-lntp'],timeout=6)
    if p.returncode:return False
    seen=False
    for line in p.stdout.splitlines():
        fields=line.split(None,5)
        if len(fields)<6 or fields[0]!='LISTEN':continue
        address,sep,port=fields[3].rpartition(':')
        if not sep or port!='1514':continue
        seen=True
        owners=re.findall(r'\("([^"]+)",pid=\d+(?:,fd=\d+)?\)',fields[5])
        if not owners or any(owner!='wazuh-remoted' for owner in owners):
            return False
    return seen


def _running_container(name):
    obj=audit.docker_object('container',name)
    return bool(obj and (obj.get('State') or {}).get('Status')=='running')


def _compose_label_files():
    o=audit.docker_object('container',ORBORUS_NAME)
    labels=(o or {}).get('Config',{}).get('Labels') or {}
    if not o or labels.get('com.docker.compose.project')!=PROJECT or labels.get('com.docker.compose.service')!=SERVICE:
        return []
    value=labels.get('com.docker.compose.project.config_files') or ''
    return [s.strip() for s in value.split(',') if s.strip()]


def _container_composition_ok(*, expect_override=None):
    files=_compose_label_files()
    if expect_override is True:return files==[str(COMPOSE),str(OVERRIDE)]
    if expect_override is False:return files==[str(COMPOSE)]
    return files in ([str(COMPOSE)],[str(COMPOSE),str(OVERRIDE)])


def check_status():
    obj=audit.docker_object('container',ORBORUS_NAME)
    env=environment_map((obj or {}).get('Config',{}).get('Env',[])) if obj else {}
    flags={k:env.get(k) for k in FLAG_VALUES}
    return {'orborus_running':_running_container(ORBORUS_NAME),'compose_owner_verified':_container_composition_ok(),
            'wazuh_1514_tcp_owner': 'wazuh-remoted' if _wazuh_owns_tcp_1514() else 'not_verified',
            'pipeline_flags':flags,
            'compose_files':_compose_label_files(),
            'override_present':OVERRIDE.exists(),
            'pipelines_disabled':all(env.get(k)==v for k,v in FLAG_VALUES.items()),
            'tenzir_state':audit.tenzir_status().get('state'),
            'meaning':'Pipelines désactivés ne signifie pas Tenzir réparé'}


def _save_backup():
    # The base file is not changed. This copy provides an audit record of the
    # exact source configuration used to validate the override.
    BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(BACKUPS,0o700)
    filename='compose-base-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(4).hex()+'.yaml'
    backup=BACKUPS/filename
    fd=os.open(str(backup),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as h:h.write(COMPOSE.read_bytes())
    return backup


def _write_override():
    # Never overwrite somebody else's override or a symlink. An existing exact
    # managed override can be reused, for instance after an interrupted run.
    if OVERRIDE.is_symlink():raise audit.AuditError('Override Compose lien symbolique refusé')
    if OVERRIDE.exists():
        if not OVERRIDE.is_file() or OVERRIDE.read_text(encoding='utf-8')!=OVERRIDE_BODY:
            raise audit.AuditError('Override Compose préexistant et non géré; refus')
        return False
    fd=os.open(str(OVERRIDE),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as h:h.write(OVERRIDE_BODY)
    return True


def _drop_managed_override():
    if OVERRIDE.is_symlink() or not OVERRIDE.is_file() or OVERRIDE.read_text(encoding='utf-8')!=OVERRIDE_BODY:
        raise audit.AuditError('Override Compose modifié pendant le déploiement: suppression refusée')
    OVERRIDE.unlink()


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
    before=compose_config()
    if SERVICE not in before['services']:raise audit.AuditError('Service orborus absent du Compose fusionné')
    orig_env=environment_map(before['services'][SERVICE].get('environment'))
    if OVERRIDE.is_symlink():raise audit.AuditError('Override Compose symbolique: intervention refusée')
    if OVERRIDE.exists() and (not OVERRIDE.is_file() or OVERRIDE.read_text(encoding='utf-8')!=OVERRIDE_BODY):
        raise audit.AuditError('Override Compose inconnu: intervention refusée')
    live=audit.docker_object('container',ORBORUS_NAME)
    runtime=environment_map((live or {}).get('Config',{}).get('Env',[]))
    if all(runtime.get(k)==v for k,v in FLAG_VALUES.items()):
        if OVERRIDE.exists() and not _container_composition_ok(expect_override=True):
            raise audit.AuditError('Orborus actif depuis un Compose différent du fichier de surcharge')
        return {'status':'already_active','orborus_running':True,'no_wazuh_change':True}
    if OVERRIDE.exists():
        raise audit.AuditError('Override SOAR déjà présent mais non appliqué: intervention refusée')
    # A base file that already sets one of the flags is an explicit operator
    # policy and must not be silently overridden by the patch.
    if any(k in orig_env for k in FLAG_VALUES):
        raise audit.AuditError('Politique pipelines déjà définie dans Compose: intervention refusée')
    # Validate changes with a temporary file BEFORE touching Orborus. Works with
    # arbitrary valid base YAML indentation, anchors and list/map environments.
    check=COMPOSE.with_name('.aegismesh-soar-orborus.v424.check.yaml')
    if check.exists() or check.is_symlink():raise audit.AuditError('Fichier Compose de vérification déjà présent')
    try:
        fd=os.open(str(check),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as h:h.write(OVERRIDE_BODY)
        after=compose_config(check)
        service_config_check(before,after)
    finally:
        if check.exists():check.unlink()
    _save_backup()
    created=False
    try:
        created=_write_override()
        audit.checked(compose_args(override=OVERRIDE)+['up','-d','--no-deps','--no-build',SERVICE],timeout=90)
        if not _running_container(ORBORUS_NAME):raise audit.AuditError('Orborus non démarré après reprise')
        if not _container_composition_ok(expect_override=True):
            raise audit.AuditError('Orborus redémarré depuis un Compose inattendu')
        obj=audit.docker_object('container',ORBORUS_NAME)
        env=environment_map((obj or {}).get('Config',{}).get('Env',[]))
        if any(env.get(k)!=v for k,v in FLAG_VALUES.items()):
            raise audit.AuditError('Variables de suspension non appliquées à Orborus')
        if not _wazuh_owns_tcp_1514():raise audit.AuditError('Wazuh ne possède plus 1514/TCP')
        time.sleep(wait_seconds)
        if not _running_container(ORBORUS_NAME):raise audit.AuditError('Orborus arrêté après validation')
        p=audit.command(['docker','logs','--since',str(max(wait_seconds,1))+'s','--tail','100',ORBORUS_NAME],timeout=12)
        if p.returncode:raise audit.AuditError('Logs Orborus indisponibles pour validation')
        if re.search(r'Failed to start Tenzir Node|network tenzir-network not found',p.stdout+'\n'+p.stderr,re.I):
            raise audit.AuditError('Orborus tente toujours Tenzir malgré la suspension')
        return {'status':'pipelines_disabled','wazuh_1514_tcp_preserved':True,
                'orborus_running':True,'tenzir_running':False,'override':str(OVERRIDE),
                'original_compose_unchanged':True,'no_wazuh_change':True,
                'note':'Pipelines Tenzir suspendus; revalider les workers classiques'}
    except (audit.AuditError,RuntimeError,OSError) as original:
        # Roll back only the file we created. No interference with another
        # operator's file, and never delete a container or touch a Wazuh rule.
        try:
            if created:_drop_managed_override()
            rolled=audit.command(compose_args()+['up','-d','--no-deps','--no-build',SERVICE],timeout=90)
            suffix='; retour Orborus sur Compose original '+('effectué' if rolled.returncode==0 else 'non confirmé')
        except (OSError,audit.AuditError) as exc:
            suffix='; retour arrière échoué ('+type(exc).__name__+')'
        raise audit.AuditError(str(original)+suffix) from original
