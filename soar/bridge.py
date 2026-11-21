#!/usr/bin/env python3
"""AEGISMESH SOAR V1: authenticated tag-to-action bridge, stdlib only.

Does not touch existing relay, Wazuh config, Fail2ban config or Nginx.
Production actions disabled by default. Keep binding on loopback until network is restricted.
"""
import base64
import datetime as dt
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TAGS = {
    'OBSERVE': 'record_only',
    'ENRICH': 'record_only',
    'F2B_TEST_BAN': 'fail2ban_test',
    'F2B_BAN_SERVER': 'fail2ban_prod',
    'WAZUH_AR_PROOF': 'wazuh_probe',
    'WAZUH_BLOCK_AGENT': 'not_implemented',
    'EDR_ISOLATE': 'not_implemented',
    'AD_DISABLE_ACCOUNT': 'not_implemented',
}
RX_ID = re.compile(r'^[A-Za-z0-9_-]{8,64}$')
RX_AGENT = re.compile(r'^\d{3}$')
ENV = {}
DB = None
LOCK = threading.Lock()


def setting(name, default=''):
    return ENV.get(name, default)


def enabled(name):
    return setting(name).strip().lower() == 'true'


def log(event, **fields):
    # no full JSON request, credentials, names or IP addresses in service journal
    entry = {'ts': dt.datetime.now(dt.timezone.utc).isoformat(), 'event': event}
    entry.update(fields)
    print(json.dumps(entry, ensure_ascii=False), flush=True)


def dbconn():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=10000')
    return c


def init_db():
    Path(DB).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(Path(DB).parent, 0o700)
    with dbconn() as c:
        c.execute('CREATE TABLE IF NOT EXISTS decisions (id TEXT PRIMARY KEY, payload TEXT NOT NULL, '
                  'tag TEXT NOT NULL, status TEXT NOT NULL, action_status TEXT NOT NULL DEFAULT \'pending\', '
                  'execution_id TEXT, detail TEXT, updated_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)')
    os.chmod(DB, 0o600)


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError('expires_at absent')
    v = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if v.tzinfo is None:
        raise ValueError('expires_at sans fuseau')
    return v


def validate_decision(data):
    if not isinstance(data, dict):
        raise ValueError('JSON objet requis')
    ident = data.get('decision_id')
    if not isinstance(ident, str) or not RX_ID.fullmatch(ident):
        raise ValueError('decision_id invalide')
    tag = data.get('tag')
    if tag not in TAGS:
        raise ValueError('tag inconnu/refuse')
    if not isinstance(data.get('incident_id'), str) or not data['incident_id'].strip():
        raise ValueError('incident_id requis')
    expires = parse_time(data.get('expires_at'))
    now = dt.datetime.now(dt.timezone.utc)
    if expires <= now or expires > now + dt.timedelta(hours=2):
        raise ValueError('expiration passée ou excessive (max 2h)')
    if not isinstance(data.get('target'), dict):
        raise ValueError('target objet requis')
    confidence = data.get('confidence', 0)
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError('confidence entre 0 et 1 requis')
    evidence = data.get('evidence_ids', [])
    if not isinstance(evidence, list) or len(evidence) > 20 or not all(isinstance(x, str) and 1 <= len(x) <= 120 for x in evidence):
        raise ValueError('evidence_ids invalide')
    if 'approved' in data and not isinstance(data['approved'], bool):
        raise ValueError('approved doit être booléen')
    # no arbitrary commands, URL targets or script names in the contract
    if len(json.dumps(data, ensure_ascii=False)) > 8192:
        raise ValueError('payload trop grand')
    return ident, tag


def policy(data):
    tag = data['tag']
    if tag in ('OBSERVE', 'ENRICH'):
        return 'record_only'
    if not data.get('approved'):
        raise PermissionError('approbation explicite manquante')
    if len(data.get('evidence_ids', [])) < 2 or data.get('confidence', 0) < 0.90:
        raise PermissionError('preuves / confiance insuffisantes')
    if tag in ('EDR_ISOLATE', 'AD_DISABLE_ACCOUNT', 'WAZUH_BLOCK_AGENT'):
        raise PermissionError('tag désactivé : action endpoint critique non intégrée')
    if tag == 'F2B_TEST_BAN' and not enabled('ENABLE_TEST_ACTIONS'):
        raise PermissionError('ENABLE_TEST_ACTIONS=false')
    if tag == 'WAZUH_AR_PROOF' and not enabled('ENABLE_TEST_ACTIONS'):
        raise PermissionError('ENABLE_TEST_ACTIONS=false')
    if tag == 'F2B_BAN_SERVER' and not enabled('ENABLE_PROD_ACTIONS'):
        raise PermissionError('ENABLE_PROD_ACTIONS=false')
    return TAGS[tag]


def ipcheck(value, test=False):
    if not isinstance(value, str):
        raise ValueError('target.ip requis')
    ip = ipaddress.ip_address(value)
    if not isinstance(ip, ipaddress.IPv4Address):
        raise PermissionError('V1: IPv4 uniquement')
    # TEST-NET blocks have no legitimate Internet routing.
    if test:
        if ip != ipaddress.ip_address('198.51.100.42'):
            raise PermissionError('test IP exclusivement 198.51.100.42')
    else:
        if not ip.is_global:
            raise PermissionError('IP non globale interdite (inclut LAN/VPN/loopback)')
        protected = setting('PROTECTED_CIDRS').split(',')
        if not any(x.strip() for x in protected):
            raise PermissionError('PROTECTED_CIDRS obligatoire pour les bans réels')
        for cidr in protected:
            if cidr.strip() and ip in ipaddress.ip_network(cidr.strip(), strict=False):
                raise PermissionError('IP de gestion/protégée')
    return str(ip)


def f2b_get_bans(jail):
    p = subprocess.run(['fail2ban-client', 'status', jail], capture_output=True, text=True, timeout=8)
    if p.returncode:
        raise RuntimeError('fail2ban status a échoué')
    match = re.search(r'Banned IP list:\s*(.*)', p.stdout)
    if not match:
        raise RuntimeError('liste des IPs bannies non disponible')
    return set(match.group(1).split())


def f2b_set(jail, operation, ip):
    p = subprocess.run(['fail2ban-client', 'set', jail, operation, ip], capture_output=True, text=True, timeout=12)
    if p.returncode:
        raise RuntimeError('fail2ban-client a renvoyé un échec')


def fail2ban_action(data, test=False):
    jail = 'aegismesh-soar-gcp'  # fixed to existing project jail; never touch sshd
    ip = ipcheck(data['target'].get('ip'), test=test)
    before = f2b_get_bans(jail)
    if ip in before:
        raise PermissionError('IP déjà bannie : refus de modifier un bannissement préexistant')
    applied = False
    try:
        f2b_set(jail, 'banip', ip)
        applied = True
        if ip not in f2b_get_bans(jail):
            raise RuntimeError('commande reçue mais IP non visible dans la jail')
        if test:
            return {'effect': 'test_ban_and_unban', 'banned_verified': True,
                    'unban_verified': True, 'ip': ip, 'jail': jail}
        return {'effect': 'temporary_ban', 'banned_verified': True,
                'ip': ip, 'jail': jail, 'duration_seconds': 120}
    finally:
        if test and applied:
            f2b_set(jail, 'unbanip', ip)
            if ip in f2b_get_bans(jail):
                raise RuntimeError('test : IP encore bannie après unban')


def wazuh_api_request(method, path, body, headers=None, raw=False):
    url = setting('WAZUH_API_URL', 'https://127.0.0.1:55000').rstrip('/') + path
    context = ssl.create_default_context(cafile=setting('WAZUH_CA_FILE') or None)
    if enabled('WAZUH_TLS_INSECURE'):
        # explicit opt-in only; never the default
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    rawdata = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, rawdata, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=12, context=context) as response:
        b = response.read(32768)
        return b.decode() if raw else json.loads(b)


def wazuh_probe(data):
    agent = data['target'].get('agent_id')
    if not isinstance(agent, str) or not RX_AGENT.fullmatch(agent):
        raise ValueError('agent_id (3 chiffres) requis')
    allow = {x.strip() for x in setting('WAZUH_TEST_AGENTS', '000').split(',') if x.strip()}
    if agent not in allow:
        raise PermissionError('agent absent WAZUH_TEST_AGENTS')
    user, pwd = setting('WAZUH_USER'), setting('WAZUH_PASSWORD')
    if not user or not pwd:
        raise RuntimeError('identifiants API Wazuh non configurés')
    basic = base64.b64encode(f'{user}:{pwd}'.encode()).decode()
    jwt = wazuh_api_request('POST', '/security/user/authenticate?raw=true', None,
                            {'Authorization': f'Basic {basic}'}, raw=True).strip()
    if not jwt:
        raise RuntimeError('authentification Wazuh sans jeton')
    body = {'command': '!aegismesh-soar-proof', 'arguments': [data['decision_id']],
            'alert': {'data': {'srcip': '198.51.100.42'}}}
    result = wazuh_api_request('PUT', '/active-response?agents_list=' + agent,
                               body, {'Authorization': f'Bearer {jwt}', 'Content-Type': 'application/json'})
    block = result.get('data', {})
    if result.get('error') or block.get('total_affected_items') != 1:
        raise RuntimeError('Wazuh API n a pas confirmé la distribution de la commande')
    # Wazuh API ACK only acknowledges dispatch; verify the agent-side evidence separately.
    return {'effect': 'wazuh_ar_dispatched', 'agent_id': agent,
            'execution_verified_on_agent': False, 'expected_proof_id': data['decision_id']}


def execute_tag(data):
    action = policy(data)
    if action == 'record_only':
        return {'effect': 'record_only', 'external_action': False}
    if action == 'fail2ban_test':
        return fail2ban_action(data, test=True)
    if action == 'fail2ban_prod':
        return fail2ban_action(data)
    if action == 'wazuh_probe':
        return wazuh_probe(data)
    raise PermissionError('action non implémentée')


def get_decision(ident):
    with dbconn() as c:
        return c.execute('SELECT * FROM decisions WHERE id=?', (ident,)).fetchone()


def dispatch_one(ident):
    url = setting('SHUFFLE_WEBHOOK_URL')
    if not url:
        return
    # Exact webhook URL must be configured. No arbitrary caller-controlled URLs.
    with LOCK:
        with dbconn() as c:
            row = c.execute('SELECT * FROM decisions WHERE id=?', (ident,)).fetchone()
            if not row or row['status'] not in ('queued', 'retry'):
                return
            c.execute("UPDATE decisions SET status='sending', attempts=attempts+1, updated_at=? WHERE id=?", (utcnow(), ident))
    try:
        data = json.loads(row['payload'])
        headers = {'Content-Type': 'application/json'}
        header_name = setting('SHUFFLE_WEBHOOK_HEADER_NAME')
        header_value = setting('SHUFFLE_WEBHOOK_HEADER_VALUE')
        if header_name and header_value:
            if not re.fullmatch(r'[A-Za-z0-9-]{1,60}', header_name):
                raise ValueError('Nom de header Shuffle invalide')
            headers[header_name] = header_value
        request = urllib.request.Request(url, json.dumps(data).encode(), headers, method='POST')
        # TLS validation remains enabled for https Shuffle webhooks.
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status not in (200, 201, 202, 204):
                raise RuntimeError('HTTP inattendu')
        with dbconn() as c:
            c.execute("UPDATE decisions SET status=CASE WHEN status='action_executed' THEN status ELSE 'accepted_by_shuffle' END, updated_at=? WHERE id=?", (utcnow(), ident))
        log('shuffle_ack', decision_id=ident)
    except Exception as exc:
        with dbconn() as c:
            c.execute("UPDATE decisions SET status=CASE WHEN status='action_executed' THEN status ELSE 'retry' END, detail=?,updated_at=? WHERE id=?",
                      (type(exc).__name__, utcnow(), ident))
        log('shuffle_delivery_failed', decision_id=ident, error_type=type(exc).__name__)


def sender_loop():
    while True:
        try:
            with dbconn() as c:
                rows = c.execute("SELECT id FROM decisions WHERE status IN ('queued','retry') AND attempts<5 ORDER BY updated_at LIMIT 20").fetchall()
            for r in rows:
                dispatch_one(r['id'])
        except Exception as exc:
            log('sender_error', error_type=type(exc).__name__)
        time.sleep(10)


class HTTP(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # no tokens and no untrusted bodies in access log

    def reply(self, code, obj):
        output = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(output)))
        self.end_headers()
        self.wfile.write(output)

    def authorized(self, token_name):
        got = self.headers.get('X-Aegismesh-Token', '')
        want = setting(token_name)
        return bool(want and hmac.compare_digest(got, want))

    def body(self):
        n = int(self.headers.get('Content-Length', '0'))
        if n < 2 or n > 8192:
            raise ValueError('taille de payload refusée')
        return json.loads(self.rfile.read(n))

    def do_GET(self):
        if self.path == '/health':
            return self.reply(200, {'service': 'aegismesh-soar-bridge', 'status': 'up',
                                    'actions_enabled': enabled('ENABLE_TEST_ACTIONS') or enabled('ENABLE_PROD_ACTIONS'),
                                    'shuffle_configured': bool(setting('SHUFFLE_WEBHOOK_URL'))})
        if self.path.startswith('/v1/decisions/'):
            if not self.authorized('DECISION_TOKEN'):
                return self.reply(401, {'error': 'unauthorized'})
            ident = self.path.rsplit('/', 1)[-1]
            r = get_decision(ident)
            if not r:
                return self.reply(404, {'error': 'unknown_decision'})
            return self.reply(200, {'decision_id': ident, 'tag': r['tag'], 'delivery': r['status'],
                                    'action_status': r['action_status'], 'execution_id': r['execution_id'],
                                    'detail': r['detail'], 'attempts': r['attempts']})
        self.reply(404, {'error': 'not_found'})

    def do_POST(self):
        try:
            if self.path == '/v1/decisions':
                if not self.authorized('DECISION_TOKEN'):
                    return self.reply(401, {'error': 'unauthorized'})
                data = self.body()
                ident, tag = validate_decision(data)
                serialized = json.dumps(data, ensure_ascii=False, sort_keys=True)
                with dbconn() as c:
                    row = c.execute('SELECT payload FROM decisions WHERE id=?', (ident,)).fetchone()
                    if row:
                        if row['payload'] != serialized:
                            return self.reply(409, {'error': 'decision_id already used with different content'})
                        return self.reply(200, {'decision_id': ident, 'status': 'already_registered'})
                    c.execute("INSERT INTO decisions(id,payload,tag,status,updated_at) VALUES(?,?,?,?,?)",
                              (ident, serialized, tag, 'queued', utcnow()))
                log('decision_registered', decision_id=ident, tag=tag)
                threading.Thread(target=dispatch_one, args=(ident,), daemon=True).start()
                return self.reply(202, {'decision_id': ident, 'status': 'queued_for_shuffle'})

            if self.path == '/v1/execute':
                if not self.authorized('SHUFFLE_ACTION_TOKEN'):
                    return self.reply(401, {'error': 'unauthorized'})
                body = self.body()
                ident, execution_id = body.get('decision_id'), body.get('execution_id')
                if not isinstance(ident, str) or not RX_ID.fullmatch(ident):
                    return self.reply(400, {'error': 'invalid decision_id'})
                if not isinstance(execution_id, str) or not RX_ID.fullmatch(execution_id):
                    return self.reply(400, {'error': 'execution_id must be stable (8-64 chars)'})
                with LOCK:
                    with dbconn() as c:
                        row = c.execute('SELECT * FROM decisions WHERE id=?', (ident,)).fetchone()
                        if not row:
                            return self.reply(404, {'error': 'unknown_decision'})
                        if row['status'] not in ('sending', 'accepted_by_shuffle', 'action_executed'):
                            return self.reply(409, {'error': 'decision not acknowledged by Shuffle'})
                        if row['action_status'] != 'pending':
                            return self.reply(200, {'decision_id': ident, 'status': row['action_status'],
                                                    'detail': row['detail'], 'duplicate': True})
                        c.execute("UPDATE decisions SET action_status='executing',execution_id=?,updated_at=? WHERE id=?",
                                  (execution_id, utcnow(), ident))
                decision = json.loads(row['payload'])
                try:
                    if parse_time(decision['expires_at']) <= dt.datetime.now(dt.timezone.utc):
                        raise PermissionError('décision expirée')
                    detail = execute_tag(decision)
                    status, code = ('dispatched_unverified', 202) if detail.get('effect') == 'wazuh_ar_dispatched' else ('executed', 200)
                except Exception as exc:
                    detail = {'error': type(exc).__name__, 'reason': str(exc)[:160]}
                    status, code = ('denied', 403) if isinstance(exc, PermissionError) else ('failed', 500)
                with dbconn() as c:
                    c.execute('UPDATE decisions SET action_status=?,detail=?,status=?,updated_at=? WHERE id=?',
                              (status, json.dumps(detail), 'action_executed', utcnow(), ident))
                log('action_finished', decision_id=ident, action_status=status, tag=decision['tag'])
                return self.reply(code, {'decision_id': ident, 'status': status, 'detail': detail})
            self.reply(404, {'error': 'not_found'})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self.reply(400, {'error': type(exc).__name__, 'detail': str(exc)[:180]})
        except Exception as exc:
            log('http_error', error_type=type(exc).__name__)
            self.reply(500, {'error': type(exc).__name__})


def main():
    global ENV, DB
    envfile = Path(os.environ.get('AEGISMESH_SOAR_ENV', '/etc/aegismesh-soar/soar.env'))
    if envfile.exists():
        for line in envfile.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                name, value = line.split('=', 1)
                ENV[name.strip()] = value.strip().strip('"')
    ENV.update({k: v for k, v in os.environ.items() if k in (
        'DECISION_TOKEN', 'SHUFFLE_ACTION_TOKEN', 'SHUFFLE_WEBHOOK_URL', 'SOAR_BIND_HOST',
        'SOAR_PORT', 'SOAR_DB', 'ENABLE_TEST_ACTIONS', 'ENABLE_PROD_ACTIONS',
        'PROTECTED_CIDRS', 'WAZUH_TEST_AGENTS', 'WAZUH_API_URL', 'WAZUH_USER',
        'WAZUH_PASSWORD', 'WAZUH_CA_FILE', 'WAZUH_TLS_INSECURE',
        'SHUFFLE_WEBHOOK_HEADER_NAME', 'SHUFFLE_WEBHOOK_HEADER_VALUE')})
    for name in ('DECISION_TOKEN', 'SHUFFLE_ACTION_TOKEN'):
        if len(setting(name)) < 32:
            raise SystemExit(f'{name} needs at least 32 characters')
    DB = setting('SOAR_DB', '/var/lib/aegismesh-soar/decisions.sqlite3')
    init_db()
    threading.Thread(target=sender_loop, name='shuffle-sender', daemon=True).start()
    host, port = setting('SOAR_BIND_HOST', '127.0.0.1'), int(setting('SOAR_PORT', '19081'))
    server = ThreadingHTTPServer((host, port), HTTP)
    log('startup', host=host, port=port, production_actions=enabled('ENABLE_PROD_ACTIONS'))
    server.serve_forever()


if __name__ == '__main__':
    main()
