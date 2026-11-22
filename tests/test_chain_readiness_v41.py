#!/usr/bin/env python3
"""V4.1 chain status: read-only historical evidence; no network/security action."""
import datetime as dt
from io import StringIO
from pathlib import Path
import sqlite3
import sys
import tempfile
from contextlib import redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ops import chain

with tempfile.TemporaryDirectory() as td:
    dbfile = Path(td)/'decisions.sqlite3'
    with sqlite3.connect(dbfile) as db:
        db.execute('''CREATE TABLE decisions (
            id TEXT PRIMARY KEY, tag TEXT, status TEXT,
            action_status TEXT, execution_id TEXT, updated_at TEXT
        )''')
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        db.execute('''INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?)''',
                   ('am-proof-test', 'WAZUH_AR_PROOF', 'action_executed',
                    'executed', 'am-proof-test', timestamp))
    cfg = {'SOAR_DB_BACKEND': 'sqlite', 'SOAR_DB': str(dbfile),
           'WAZUH_API_URL': 'https://127.0.0.1:55000'}
    state, info = chain.last_verified_shuffle_callback(cfg)
    assert state == 'RÉCENT PROUVÉ', (state,info)
    assert 'WAZUH_AR_PROOF' in info and 'pas un test temps réel' in info

    # An accepted-by-Shuffle (but not executed) action must never count as proof.
    with sqlite3.connect(dbfile) as db:
        db.execute('DELETE FROM decisions')
        db.execute('''INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?)''',
                   ('am-not-done', 'OBSERVE', 'accepted_by_shuffle',
                    'pending', None, timestamp))
    state, info = chain.last_verified_shuffle_callback(cfg)
    assert state == 'NON PROUVÉ', (state, info)

    # Missing DB must not be interpreted as successful callback.
    state, info = chain.last_verified_shuffle_callback({**cfg, 'SOAR_DB':str(Path(td)/'absent.db')})
    assert state == 'INCONNU', (state,info)

    # Local Wazuh certificate availability is configuration, never a claimed HTTPS verification.
    with mock.patch.object(chain.Path, 'is_file', return_value=True):
        state, info = chain.wazuh_tls_configuration(cfg)
        assert state == 'CERT. LOCAL' and 'wazuh-check' in info
    state, info = chain.wazuh_tls_configuration({**cfg, 'WAZUH_TLS_INSECURE':'true'})
    assert state == 'REFUSÉ'
    with mock.patch.object(chain.Path, 'is_file', return_value=False):
        state, info = chain.wazuh_tls_configuration({**cfg, 'WAZUH_CA_FILE':'/absent.crt'})
        assert state == 'CA ABSENTE'

    with (mock.patch.object(chain, 'settings', return_value=cfg),
          mock.patch.object(chain, 'check_http_health', return_value=True),
          mock.patch.object(chain, 'service_state', return_value='active'),
          mock.patch.object(chain, 'cmd', return_value=mock.Mock(returncode=0)),
          redirect_stdout(StringIO()) as output):
        chain.report()
    text = output.getvalue()
    assert 'OPTIONNEL' in text, text
    assert 'Retour Shuffle (passé)' in text, text
    assert 'NON PROUVÉ' in text, text
    assert 'aucune action' in text.lower() or 'Aucune action' in text

print('PASS: chain status V4.1 historiques vérifiables, TLS local et webhook optionnel; aucune action réelle')
