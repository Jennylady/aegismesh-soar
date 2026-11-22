#!/usr/bin/env python3
"""Offline regression: SQL compatibility, backup checksum, PostgreSQL lifecycle.

No apt, service, PostgreSQL, Wazuh, Shuffle or AD actions.
"""
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from soar import bridge
from ops import database_pg_v39 as db


def run():
    previous_env=dict(bridge.ENV)
    previous_db=bridge.DB
    try:
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'db.sqlite3'
            bridge.DB=str(src)
            bridge.ENV.clear()
            bridge.init_db()
            with bridge.dbconn() as conn:
                conn.execute('INSERT INTO decisions(id,payload,tag,status,updated_at) VALUES(?,?,?,?,?)',
                             ('am-testing-0000001','{}','OBSERVE','queued','2026-11-22T00:00:00+00:00'))
            backup,records=db.sqlite_backup(src,Path(td)/'backups')
            assert backup.exists()
            if os.name != 'nt':
                assert backup.stat().st_mode & 0o777 == 0o600
            assert len(records)==1 and records[0][0]=='am-testing-0000001'
            source=sqlite3.connect(src)
            try:assert db.fingerprint(db.selected_rows(source))==db.fingerprint(records)
            finally:source.close()
            # PostgreSQL adapter must use placeholders and close cursors/connections.
            class FakeCursor:
                rowcount=1
                def __init__(self):self.closed=False;self.sql='';self.params=None
                def execute(self,sql,params):self.sql=sql;self.params=params
                def fetchall(self):return []
                def close(self):self.closed=True
            class FakeConn:
                def __init__(self):self.cursors=[];self.closed=False
                def cursor(self):
                    cur=FakeCursor();self.cursors.append(cur);return cur
                def __enter__(self):return self
                def __exit__(self,typ,exc,tb):self.committed=typ is None
                def close(self):self.closed=True
            fake=FakeConn()
            bridge.ENV['SOAR_DB_BACKEND']='postgresql'
            with patch.object(bridge,'pg_connection',return_value=fake):
                with bridge.dbconn() as conn:
                    cur=conn.execute('SELECT id FROM decisions WHERE id=?',('a',))
                    assert cur.sql=='SELECT id FROM decisions WHERE id=%s'
                    assert cur.params==('a',)
            assert fake.closed and fake.cursors[0].closed and fake.committed
            fake2=FakeConn()
            with patch.object(bridge,'pg_connection',return_value=fake2):
                try:
                    with bridge.dbconn() as conn:
                        conn.execute('SELECT id FROM decisions WHERE id=?',('a',))
                        raise ValueError('rollback')
                except ValueError:pass
            assert fake2.closed and fake2.cursors[0].closed and not fake2.committed
            assert db.fingerprint(records)!=db.fingerprint([tuple(list(records[0])[:-1]+[123])])
    finally:
        bridge.ENV.clear();bridge.ENV.update(previous_env)
        bridge.DB=previous_db
    print('PASS: SQLite backup/strong checksum, PG SQL binding, commit/rollback and close; no live action')

if __name__=='__main__':run()
