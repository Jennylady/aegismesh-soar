#!/usr/bin/env python3
"""SQLite transaction/handle lifecycle; offline, no Wazuh, Shuffle or AD action."""
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'soar'))
import bridge


def must_be_closed(conn):
    try:
        conn.execute('SELECT 1')
    except sqlite3.ProgrammingError as exc:
        assert 'closed' in str(exc).lower(), str(exc)
    else:
        raise AssertionError('SQLite connection still open outside with dbconn()')


def run():
    with tempfile.TemporaryDirectory() as folder:
        db = Path(folder) / 'db.sqlite3'
        with patch.object(bridge, 'DB', str(db)):
            bridge.init_db()
            # If __exit__ merely commits, this check fails on CPython/Windows.
            with bridge.dbconn() as conn:
                conn.execute('CREATE TABLE lifecycle (id INTEGER PRIMARY KEY, value TEXT)')
                conn.execute('INSERT INTO lifecycle(value) VALUES(?)', ('committed',))
            must_be_closed(conn)
            with bridge.dbconn() as other:
                values = [r[0] for r in other.execute('SELECT value FROM lifecycle')]
                assert values == ['committed'], values
            must_be_closed(other)

            # A failed transaction must roll back AND close its handle.
            try:
                with bridge.dbconn() as failing:
                    failing.execute('INSERT INTO lifecycle(value) VALUES(?)', ('rolled_back',))
                    raise RuntimeError('intentional test rollback')
            except RuntimeError as exc:
                assert str(exc) == 'intentional test rollback'
            else:
                raise AssertionError('Expected rollback path')
            must_be_closed(failing)
            with bridge.dbconn() as again:
                values = [r[0] for r in again.execute('SELECT value FROM lifecycle')]
                assert values == ['committed'], values
            must_be_closed(again)
        # On Windows, removal fails with WinError 32 when any SQLite handle remains open.
    print('PASS: SQLite commit, rollback, explicit connection close, Windows temp cleanup; no live actions')


if __name__ == '__main__':
    run()
