#!/usr/bin/env python3
"""Bootstrap the EXISTING Velociraptor Docker server for AEGISMESH SOAR.

Introspection is read-only; issuing a new API identity and restarting a running
Velociraptor container require distinct explicit flags. API keys are never
printed, copied into Git, or stored in Docker metadata.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ops import edr_velociraptor as edr

SERVER_CONFIGS=(
 '/etc/velociraptor/server.config.yaml',
 '/etc/velociraptor.config.yaml',
 '/opt/velociraptor/server.config.yaml',
 '/velociraptor/server.config.yaml',
 '/config/server.config.yaml',
 '/etc/velociraptor/server.yaml',
)
API_CONFIGS=(
 '/etc/velociraptor/aegismesh-soar-api-client.yaml',
 '/etc/velociraptor/api_client.yaml',
 '/etc/velociraptor/api.config.yaml',
 '/data/aegismesh-soar-api-client.yaml',
 '/datastore/aegismesh-soar-api-client.yaml',
 '/var/lib/velociraptor/aegismesh-soar-api-client.yaml',
 '/opt/velociraptor/api_client.yaml',
)
BINS=('velociraptor','/usr/local/bin/velociraptor','/usr/bin/velociraptor','/velociraptor','/app/velociraptor')
API_NAME='AEGISMESH_SOAR_API'
API_FILENAME='aegismesh-soar-api-client.yaml'


def run(args, timeout=12):
    try:
        return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RuntimeError('Docker/Velociraptor indisponible: '+type(exc).__name__) from None


def check_container(name):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}', name):
        raise ValueError('Nom Docker invalide')
    if name not in edr.discovered():
        raise FileNotFoundError('Conteneur Velociraptor non actif: '+name)


def selected_container(requested=''):
    names=edr.discovered()
    if requested:
        check_container(requested)
        return requested
    if len(names)!=1:
        raise RuntimeError('Sélection automatique impossible : '+str(len(names))+
            ' conteneurs Velociraptor. Préciser --container avec un nom de edr discover.')
    return names[0]


def in_container_exists(container,path):
    if not path.startswith('/') or '..' in Path(path).parts:
        raise ValueError('Chemin conteneur invalide')
    return run(['docker','exec',container,'test','-r',path],timeout=8).returncode==0


def find_binary(container):
    p=run(['docker','exec',container,'sh','-c','command -v velociraptor'],timeout=8)
    if p.returncode==0 and p.stdout.strip() and re.fullmatch(r'/[A-Za-z0-9/._-]+',p.stdout.strip()):
        return p.stdout.strip()
    for path in BINS[1:]:
        if run(['docker','exec',container,'test','-x',path],timeout=8).returncode==0:return path
    return None


def mounts(container):
    p=run(['docker','inspect','--format','{{json .Mounts}}',container])
    if p.returncode:raise RuntimeError('docker inspect .Mounts échoué')
    try:data=json.loads(p.stdout)
    except ValueError:raise RuntimeError('Mounts Docker illisibles') from None
    if not isinstance(data,list):raise RuntimeError('Montages Docker invalides')
    return data


def persistent_destination(container):
    """Only persistent RW Docker bind/volume mounts; don't store API cert in tmpfs or image."""
    preferred=[]
    for mount in mounts(container):
        if mount.get('Type') not in ('bind','volume') or not mount.get('RW',False):continue
        dest=str(mount.get('Destination','')).rstrip('/')
        if not dest.startswith('/') or '..' in Path(dest).parts:continue
        if dest in ('/','/tmp','/run','/var/run','/proc','/sys','/dev'):continue
        # A bind-mounted file (vs directory) is not suitable for creating a credential.
        if run(['docker','exec',container,'test','-d',dest],timeout=8).returncode:continue
        # Avoid Docker secrets and special purpose mounts.
        if any(word in dest.lower() for word in ('docker.sock','secret','ssh','certs','nginx','mysql')):continue
        rank=next((i for i,p in enumerate(('/etc/velociraptor','/var/lib/velociraptor','/datastore','/data','/opt/velociraptor','/config')) if dest==p),10)
        if rank < 10:
            preferred.append((rank,dest))
    return sorted(preferred)[0][1] if preferred else None


def probe(container):
    binpath=find_binary(container)
    servers=[x for x in SERVER_CONFIGS if in_container_exists(container,x)]
    target=persistent_destination(container)
    candidates=list(API_CONFIGS)
    if target and target+'/'+API_FILENAME not in candidates:
        candidates.append(target+'/'+API_FILENAME)
    apis=[x for x in candidates if in_container_exists(container,x)]
    return {'container':container,'binary':binpath,'server_config':servers[0] if servers else None,
            'api_configs':apis,'persistent_directory':target}


def config_for(meta,path):
    return {'mode':'docker','container':meta['container'],'binary':meta['binary'],'api_config':path}


def connect_existing(meta):
    """Do not store credentials until both mTLS and read-only client inventory respond."""
    if not meta['binary']:raise RuntimeError('Binaire Velociraptor absent dans le conteneur')
    errors=[]
    for path in meta['api_configs']:
        cfg=config_for(meta,path)
        try:
            edr.api_query('SELECT * FROM info() LIMIT 1',cfg=cfg)
            edr.api_query(edr.READ_CLIENTS,cfg=cfg)
        except (RuntimeError,ValueError,PermissionError) as exc:
            errors.append((path,type(exc).__name__))
            continue
        edr.atomic_json(edr.CONF,cfg)
        return path
    if errors:
        raise RuntimeError('Certificat(s) trouvé(s), mais API refusée : '+
                           ', '.join(Path(p).name+' '+t for p,t in errors))
    raise RuntimeError('Aucun certificat API Velociraptor existant dans les chemins reconnus')


def bootstrap(meta, *, allow_restart=False):
    """Create one scoped API identity on an existing persisted Docker volume only."""
    if not allow_restart:
        raise PermissionError('L’émission d’une identité API nécessite un redémarrage Velociraptor. Ajouter --allow-restart.')
    if not meta['binary'] or not meta['server_config']:
        raise RuntimeError('Binaire ou server.config.yaml non détecté : aucune génération de certificat autorisée')
    root=meta['persistent_directory']
    if not root:raise RuntimeError('Aucun volume Docker persistant en écriture : ne pas stocker une clé dans la couche éphémère')
    dest=root+'/'+API_FILENAME
    if in_container_exists(meta['container'],dest):
        raise FileExistsError('Une clé API SOAR existe déjà. Refus de la remplacer : utiliser edr setup.')
    # Run with umask 077 in the container. No secrets or arbitrary shell input.
    command=[meta['binary'],'--config',meta['server_config'],'config','api_client',
             '--name',API_NAME,'--role','api',dest]
    p=run(['docker','exec','--user','0',meta['container'],'sh','-c','umask 077; exec "$@"', 'edr-bootstrap']+command,timeout=40)
    if p.returncode:raise RuntimeError('Création de la clé API refusée par Velociraptor, code '+str(p.returncode))
    if not in_container_exists(meta['container'],dest):raise RuntimeError('Clé API non créée dans le volume persistant')
    p=run(['docker','exec','--user','0',meta['container'],'chmod','600',dest],timeout=8)
    if p.returncode:raise RuntimeError('Clé API créée, mais permissions 0600 impossibles : arrêt')
    # The API role grants API connectivity. Investigator grants collection/labels;
    # ACL modifications via CLI require a server reload, not another user.
    p=run(['docker','exec','--user','0',meta['container'],meta['binary'],'--config',meta['server_config'],
           'acl','grant',API_NAME,'--role','api,investigator'],timeout=25)
    if p.returncode:
        raise RuntimeError('Certificat créé mais ACL non appliquée. Ne pas redémarrer; vérifier via edr doctor.')
    p=run(['docker','restart','--time','10',meta['container']],timeout=30)
    if p.returncode:raise RuntimeError('Permissions attribuées, redémarrage Velociraptor échoué')
    cfg=config_for(meta,dest)
    last='injoignable'
    for attempt in range(5):
        try:
            edr.api_query('SELECT * FROM info() LIMIT 1',cfg=cfg)
            edr.api_query(edr.READ_CLIENTS,cfg=cfg)
            edr.atomic_json(edr.CONF,cfg)
            return dest
        except (RuntimeError,ValueError) as exc:
            last=type(exc).__name__;time.sleep(2)
    raise RuntimeError('Identité générée, API non validée ('+last+'). Certificat conservé; ne pas réexécuter bootstrap.')


def main(argv=None):
    p=argparse.ArgumentParser(description='Raccordement auto du Velociraptor existant — aucune donnée secrète affichée')
    p.add_argument('action',choices=['doctor','setup','bootstrap'])
    p.add_argument('--container',default='',help='Facultatif si un seul conteneur Velociraptor')
    p.add_argument('--confirm',action='store_true')
    p.add_argument('--allow-restart',action='store_true',help='Bootstrap uniquement : redémarrer Velociraptor après création de l’identité API')
    a=p.parse_args(argv)
    try:
        edr.require_root()
        container=selected_container(a.container)
        meta=probe(container)
        print('EDR cible:',container)
        print('Binaire:',meta['binary'] or 'ABSENT')
        print('Configuration serveur:',meta['server_config'] or 'NON DÉTECTÉE')
        print('Clés API candidates:',len(meta['api_configs']))
        print('Volume persistant inscriptible:',meta['persistent_directory'] or 'ABSENT')
        if a.action=='doctor':
            print('API SOAR configurée:',edr.CONF.is_file())
            print('Actions exécutées : aucune (diagnostic lecture seule)')
            if not meta['api_configs']:
                print('Étape suivante: aegismesh-soar edr bootstrap --confirm --allow-restart')
            else:
                print('Étape suivante: aegismesh-soar edr setup --confirm')
            return 0
        if not a.confirm:raise PermissionError('Confirmer l’enregistrement API avec --confirm')
        if a.action=='setup':
            path=connect_existing(meta)
            print('API Velociraptor mTLS raccordée:',path)
            print('Aucun service redémarré. Continuer: aegismesh-soar edr clients; edr link-auto')
        else:
            # Reject attempting repeated bootstrap if the API is already ready.
            if edr.CONF.is_file():raise PermissionError('API SOAR déjà enregistrée; utiliser edr status')
            if meta['api_configs']:
                raise PermissionError('Certificat API existant détecté : tenter edr setup --confirm, pas de duplication de clé')
            path=bootstrap(meta,allow_restart=a.allow_restart)
            print('API mTLS générée, ACL activée et connexion vérifiée:',path)
            print('Conteneur Velociraptor existant redémarré UNIQUEMENT pour ses nouvelles ACL')
        return 0
    except (RuntimeError,ValueError,PermissionError,FileNotFoundError,FileExistsError) as exc:
        print('ÉCHEC EDR SETUP:',str(exc)[:300],file=sys.stderr)
        return 2

if __name__=='__main__':sys.exit(main())
