#!/usr/bin/env python3
"""PostgreSQL SOAR provisioning and lossless SQLite migration; localhost only.

One root invocation on the existing GCP host. Never touches the separate
AEGISMESH database/role and never publishes credentials or changes pg_hba.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from soar import bridge

CONFIG = Path('/etc/aegismesh-soar/soar.env')
PW_FILE = Path('/etc/aegismesh-soar/postgres.password')
STATE = Path('/var/lib/aegismesh-soar')
BACKUPS = STATE / 'backups'
SERVICE = 'aegismesh-soar-bridge.service'
ROLE = 'aegismesh_soar'
DATABASE = 'aegismesh_soar'
COLS = ('id','payload','tag','status','action_status','execution_id','detail','updated_at','attempts')


def config(path=CONFIG):
    if not path.is_file():
        raise RuntimeError('Configuration SOAR absente sur GCP')
    result = {}
    for line in path.read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            k,v = line.split('=',1)
            result[k.strip()] = v.strip().strip('"')
    return result


def run(args, *, input=None, timeout=90):
    p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError('Commande système échouée: ' + args[0] + ' (code '+str(p.returncode)+')')
    return p.stdout.strip()


def postgres_sql(sql):
    return run(['runuser','-u','postgres','--','psql','-X','-At',
                '-v','ON_ERROR_STOP=1','-d','postgres'],input=sql)


def selected_rows(connection):
    rows = connection.execute('SELECT ' + ','.join(COLS) + ' FROM decisions ORDER BY id').fetchall()
    return [tuple(row) for row in rows]


def fingerprint(rows):
    """Full content checksum, not just a row count or a sample."""
    h = hashlib.sha256()
    for row in rows:
        h.update(json.dumps(tuple(row),ensure_ascii=False,separators=(',',':')).encode('utf-8'))
        h.update(b'\n')
    return h.hexdigest()


def sqlite_backup(src, directory):
    """Create a protected, consistent copy *after* the bridge is stopped."""
    src=Path(src)
    if not src.is_file():
        raise RuntimeError('Base SQLite SOAR source introuvable; migration refusée')
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(directory,0o700)
    dest=directory / ('decisions-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.sqlite3')
    source=sqlite3.connect(src.resolve().as_uri()+'?mode=ro',uri=True,timeout=10)
    target=sqlite3.connect(str(dest))
    try:
        if source.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('Intégrité SQLite non valide')
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(dest,0o600)
    conn=sqlite3.connect(str(dest))
    try:
        records=selected_rows(conn)
    finally:
        conn.close()
    return dest,records


def initialize_pg(password):
    """Create only the fixed SOAR role/db; never alter any existing role."""
    if '\\' in password or "'" in password or not password.isalnum():
        raise ValueError('Generated PostgreSQL secret invalid')
    role_exists=postgres_sql("SELECT 1 FROM pg_roles WHERE rolname='aegismesh_soar';\n") == '1'
    if not role_exists:
        postgres_sql("CREATE ROLE aegismesh_soar LOGIN PASSWORD '"+password+"' "
                     "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;\n")
    db_owner=postgres_sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='aegismesh_soar';\n")
    if db_owner and db_owner != ROLE:
        raise PermissionError('Base du même nom appartenant à un autre rôle : refus')
    if not db_owner:
        postgres_sql('CREATE DATABASE aegismesh_soar OWNER aegismesh_soar;\n'
                     'REVOKE ALL ON DATABASE aegismesh_soar FROM PUBLIC;\n')


def configure_bridge_postgres(original,secret_path=PW_FILE):
    """Set only new keys. Keep SOAR_DB SQLite path as emergency recovery."""
    from importlib.machinery import SourceFileLoader
    managed=SourceFileLoader('aegismesh_soar_db_management',str(ROOT/'bin/aegismesh-soar')).load_module()
    managed.atomic_env({'SOAR_DB_BACKEND':'postgresql',
                        'SOAR_PG_PORT':'5432','SOAR_PG_DATABASE':DATABASE,
                        'SOAR_PG_USER':ROLE,'SOAR_PG_PASSWORD_FILE':str(secret_path)})
    return managed


def status():
    cfg=config()
    backend=cfg.get('SOAR_DB_BACKEND','sqlite')
    print('Base de données SOAR:',backend)
    print('PostgreSQL cible: 127.0.0.1:5432 / '+DATABASE+' (rôle isolé '+ROLE+')')
    if backend=='postgresql':
        bridge.ENV.clear();bridge.ENV.update(cfg)
        try:
            with bridge.dbconn() as conn:
                rows=selected_rows(conn)
            print('PostgreSQL joignable: oui')
            print('Decisions:',len(rows),'SHA-256:',fingerprint(rows))
        except Exception as exc:
            print('PostgreSQL joignable: non,',type(exc).__name__)
            raise
    else:
        path=Path(cfg.get('SOAR_DB',str(STATE/'decisions.sqlite3')))
        if path.exists():
            conn=sqlite3.connect(str(path))
            try: rows=selected_rows(conn)
            finally:conn.close()
            print('SQLite decisions:',len(rows),'SHA-256:',fingerprint(rows))
        else:
            print('SQLite source non présente')
    print('Aucune modification effectuée.')


def migrate(*, cfg_path=CONFIG):
    if os.geteuid()!=0:
        raise PermissionError('Root requis pour installer et migrer PostgreSQL')
    if ROOT!=Path('/opt/aegismesh/soar'):
        raise PermissionError('Exécuter la migration sur la vraie instance GCP')
    cfg=config(cfg_path)
    if cfg.get('SOAR_DB_BACKEND','sqlite')=='postgresql':
        print('PostgreSQL déjà actif. Migration non rejouée.')
        return status()
    if cfg.get('SOAR_DB_BACKEND','sqlite')!='sqlite':
        raise ValueError('Backend actuel non reconnu')
    path=Path(cfg.get('SOAR_DB',str(STATE/'decisions.sqlite3')))
    if not path.is_file():
        raise RuntimeError('Fichier SQLite introuvable : arrêt sans modification')
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(STATE,0o700)
    lock=STATE/'db-migration.lock'
    import fcntl  # Linux-only: offline tests must import on Windows too.
    with open(lock,'a+b') as l:
        fcntl.flock(l,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Packages are installed while the SOAR bridge remains online.
        try:
            import psycopg2  # noqa: F401
            present=True
        except ImportError:
            present=False
        if not present or not __import__('shutil').which('pg_isready'):
            run(['apt-get','install','-y','--no-upgrade','postgresql','postgresql-client','python3-psycopg2'],timeout=210)
            import psycopg2  # noqa: F401
        if subprocess.run(['pg_isready','-q','-h','127.0.0.1','-p','5432'],check=False).returncode:
            run(['systemctl','start','postgresql.service'])
        if subprocess.run(['pg_isready','-q','-h','127.0.0.1','-p','5432'],check=False).returncode:
            raise RuntimeError('PostgreSQL non joignable sur 127.0.0.1:5432')
        PW_FILE.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        os.chmod(PW_FILE.parent,0o700)
        role_exists=postgres_sql("SELECT 1 FROM pg_roles WHERE rolname='aegismesh_soar';\n")=='1'
        if role_exists and not PW_FILE.is_file():
            raise PermissionError('Rôle PG SOAR existant sans notre secret privé: refus de prise de contrôle')
        if not PW_FILE.is_file():
            secret=secrets.token_hex(32)
            fd,name=tempfile.mkstemp(dir=str(PW_FILE.parent),prefix='.pg-pass-')
            try:
                os.fchmod(fd,0o600)
                with os.fdopen(fd,'w') as out:out.write(secret+'\n')
                os.replace(name,PW_FILE)
            finally:
                if os.path.exists(name):os.unlink(name)
        if PW_FILE.stat().st_mode & 0o077:
            raise PermissionError('Secret PG trop accessible')
        password=PW_FILE.read_text().strip()
        initialize_pg(password)
        bridge.ENV.clear()
        bridge.ENV.update({'SOAR_DB_BACKEND':'postgresql','SOAR_PG_PORT':'5432',
                          'SOAR_PG_DATABASE':DATABASE,'SOAR_PG_USER':ROLE,
                          'SOAR_PG_PASSWORD_FILE':str(PW_FILE)})
        # Verify role credentials and prepare its own table before stopping bridge.
        with bridge.dbconn() as pg:
            pg.execute(bridge.DECISIONS_SCHEMA)
        print('PostgreSQL préparé (rôle, base et table dédiés).')
        was_running = subprocess.run(['systemctl','is-active','--quiet',SERVICE],check=False).returncode == 0
        if not was_running:
            raise RuntimeError('Bridge SOAR non actif avant migration : refus de bascule')
        run(['systemctl','stop',SERVICE])
        switched=False
        started=False
        try:
            backup,records=sqlite_backup(path,BACKUPS)
            expected=fingerprint(records)
            print('Sauvegarde SQLite protégée:',backup,'decisions:',len(records))
            with bridge.dbconn() as pg:
                previous=selected_rows(pg)
                if previous:
                    if len(previous)!=len(records) or fingerprint(previous)!=expected:
                        raise RuntimeError('PostgreSQL déjà rempli avec un contenu différent : arrêt')
                else:
                    query=('INSERT INTO decisions ('+','.join(COLS)+') VALUES ('+','.join(['?']*len(COLS))+')')
                    for record in records:
                        pg.execute(query,record)
            with bridge.dbconn() as pg:
                rows=selected_rows(pg)
            if len(rows)!=len(records) or fingerprint(rows)!=expected:
                raise RuntimeError('Vérification intégrale SQLite/PostgreSQL échouée')
            print('Migration vérifiée : mêmes décisions et empreinte SHA-256.')
            configure_bridge_postgres(cfg)
            switched=True
            run(['systemctl','restart',SERVICE],timeout=60)
            started=True
            if subprocess.run(['systemctl','is-active','--quiet',SERVICE],check=False).returncode:
                raise RuntimeError('Bridge SOAR inactif après migration')
            from ops import health as health_module
            ok,reason=health_module.wait_ready(cfg.get('SOAR_BIND_HOST','127.0.0.1'),
                                                cfg.get('SOAR_PORT','19081'),seconds=10)
            if not ok:raise RuntimeError('Health bridge non confirmée après bascule PostgreSQL')
            print('BASCULE RÉUSSIE — PostgreSQL actif, bridge sain. Historique SQLite préservé.')
        except BaseException:
            if switched:
                # Do not revert while a running PostgreSQL bridge may accept writes.
                run(['systemctl','stop',SERVICE],timeout=60)
                with bridge.dbconn() as pg:
                    now=selected_rows(pg)
                if len(now)!=len(records) or fingerprint(now)!=expected:
                    print('ALERTE: nouvelles écritures PostgreSQL détectées; bascule arrière interdite.',file=sys.stderr)
                    print('Bridge arrêté pour éviter toute divergence; intervention requise.',file=sys.stderr)
                    raise
                from importlib.machinery import SourceFileLoader
                manager=SourceFileLoader('aegismesh_soar_db_rollback',str(ROOT/'bin/aegismesh-soar')).load_module()
                manager.atomic_env({'SOAR_DB_BACKEND':'sqlite'})
            if was_running:
                run(['systemctl','start',SERVICE],timeout=60)
            raise


def main():
    parser=argparse.ArgumentParser(description='Gestion PostgreSQL AEGISMESH SOAR')
    sub=parser.add_subparsers(dest='action',required=True)
    sub.add_parser('status')
    m=sub.add_parser('migrate',help='Installe PostgreSQL, sauvegarde et migre SQLite, puis bascule bridge')
    m.add_argument('--apply',action='store_true');m.add_argument('--confirm',action='store_true')
    args=parser.parse_args()
    if args.action=='status':status()
    elif args.action=='migrate':
        if not (args.apply and args.confirm):
            raise PermissionError('--apply --confirm obligatoires')
        migrate()

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,PermissionError,OSError,sqlite3.Error,subprocess.TimeoutExpired) as exc:
        print('SOAR PostgreSQL ÉCHEC:',type(exc).__name__,str(exc)[:180],file=sys.stderr)
        sys.exit(2)
