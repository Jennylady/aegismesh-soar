#!/usr/bin/env python3
"""AEGISMESH SOAR V1: authenticated tag-to-action bridge, stdlib only.

Does not touch existing relay, Wazuh config, Fail2ban config or Nginx.
Production actions disabled by default. Keep binding on loopback until network is restricted.
"""
import base64
from contextlib import contextmanager
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
    'WAZUH_BLOCK_AGENT': 'wazuh_block',
    'WINDOWS_BLOCK_IP': 'windows_firewall_block',
    'EDR_COLLECT': 'edr_collection',
    'EDR_ISOLATE': 'edr_quarantine',
    'AD_DISABLE_ACCOUNT': 'ad_account_disable',
    'AD_LAB_DISABLE': 'ad_account_disable',
}
RX_ID = re.compile(r'^[A-Za-z0-9_-]{8,64}$')
RX_AGENT = re.compile(r'^\d{3}$')
RX_AD_SID = re.compile(r'^S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10}$')
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


class _PostgresCursorAdapter:
    """Minimal sqlite-compatible interface for the fixed, parameterized SOAR SQL."""
    def __init__(self, connection):
        self.connection = connection
        self.open_cursors = []

    def execute(self, sql, params=()):
        # All SOAR SQL statements are defined by this repository, never by requests.
        # The only placeholders used by our fixed statements are sqlite's '?'.
        cursor = self.connection.cursor()
        self.open_cursors.append(cursor)
        cursor.execute(sql.replace('?', '%s'), params)
        return cursor

    def close(self):
        for cursor in self.open_cursors:
            try:
                cursor.close()
            except Exception:
                pass


def pg_connection():
    """Connect only to a private local PostgreSQL role, with no password in env."""
    import psycopg2
    from psycopg2.extras import DictCursor
    path = Path(setting('SOAR_PG_PASSWORD_FILE', '/etc/aegismesh-soar/postgres.password'))
    if not path.is_file():
        raise RuntimeError('Mot de passe PostgreSQL SOAR absent')
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError('Mot de passe PostgreSQL SOAR trop accessible')
    password = path.read_text().strip()
    if not password:
        raise RuntimeError('Mot de passe PostgreSQL SOAR vide')
    return psycopg2.connect(host='127.0.0.1', port=int(setting('SOAR_PG_PORT', '5432')),
                            dbname=setting('SOAR_PG_DATABASE', 'aegismesh_soar'),
                            user=setting('SOAR_PG_USER', 'aegismesh_soar'),
                            password=password, connect_timeout=5,
                            cursor_factory=DictCursor)


@contextmanager
def dbconn():
    """Close every SQLite or PostgreSQL connection after commit/rollback."""
    backend = setting('SOAR_DB_BACKEND', 'sqlite').lower()
    if backend == 'postgresql':
        conn = pg_connection()
        adapter = _PostgresCursorAdapter(conn)
        try:
            with conn:
                yield adapter
        finally:
            adapter.close()
            conn.close()
        return
    if backend != 'sqlite':
        raise ValueError('SOAR_DB_BACKEND invalide (sqlite|postgresql)')
    conn = sqlite3.connect(DB, timeout=10)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA busy_timeout=10000')
        with conn:
            yield conn
    finally:
        conn.close()


DECISIONS_SCHEMA = ('CREATE TABLE IF NOT EXISTS decisions '
                    '(id TEXT PRIMARY KEY, payload TEXT NOT NULL, tag TEXT NOT NULL, '
                    "status TEXT NOT NULL, action_status TEXT NOT NULL DEFAULT 'pending', "
                    'execution_id TEXT, detail TEXT, updated_at TEXT NOT NULL, '
                    'attempts INTEGER NOT NULL DEFAULT 0)')


def init_db():
    backend = setting('SOAR_DB_BACKEND', 'sqlite').lower()
    if backend == 'sqlite':
        Path(DB).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(Path(DB).parent, 0o700)
    with dbconn() as c:
        c.execute(DECISIONS_SCHEMA)
    if backend == 'sqlite':
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
    if tag != 'AD_LAB_DISABLE' and (len(data.get('evidence_ids', [])) < 2 or data.get('confidence', 0) < 0.90):
        raise PermissionError('preuves / confiance insuffisantes')
    if tag in ('AD_DISABLE_ACCOUNT','AD_LAB_DISABLE'):
        # A decision from the analytic engine is NOT an unrestricted AD command.
        # Only a real domain user SID, fixed DC allowlist and verified incident are accepted.
        if not (enabled('ENABLE_PROD_ACTIONS') and enabled('ENABLE_AD_REMEDIATION')):
            raise PermissionError('remédiation AD désactivée, activer séparément après installation DC')
        if tag == 'AD_DISABLE_ACCOUNT':
            if data.get('confidence', 0) < 0.98 or len(set(data.get('evidence_ids', []))) < 2:
                raise PermissionError('AD : score >=0.98 et deux preuves distinctes obligatoires')
        else:
            # Separate, time-limited operator test. NEVER treat it as an AI incident.
            until=setting('AD_LAB_UNTIL')
            try: ready=bool(until and parse_time(until)>dt.datetime.now(dt.timezone.utc))
            except (ValueError,TypeError): ready=False
            if not ready or data.get('origin')!='operator_lab' or data.get('confidence')!=0 or data.get('evidence_ids')!=[]:
                raise PermissionError('AD LAB: fenêtre opérateur expirée ou score/preuves présentés comme IA')
            if not str(data.get('incident_id','')).startswith('AD-LAB-'):
                raise PermissionError('AD LAB: identifiant de test explicite obligatoire')
            if parse_time(data['expires_at']) > dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5):
                raise PermissionError('AD LAB: expiration excessive')
        if not re.fullmatch(r'am-[0-9a-f]{24}', data['decision_id']):
            raise PermissionError('AD : identifiant de décision compatible Windows obligatoire')
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{4,120}', data.get('incident_id','')):
            raise PermissionError('AD : identifiant d incident incompatible avec exécuteur Windows')
        target = data.get('target') or {}
        if (not isinstance(target, dict) or
                target.get('agent_id') != setting('AD_DC_AGENT_ID') or
                target.get('agent_id') not in setting('WAZUH_WINDOWS_DC_AGENT_IDS').split(',')):
            raise PermissionError('AD : agent cible différent du contrôleur autorisé')
        if (not isinstance(target.get('user_sid'), str) or
                not RX_AD_SID.fullmatch(target['user_sid'])):
            raise PermissionError('AD : SID utilisateur Windows requis, nom de compte libre interdit')
        if (target.get('domain_dns') != setting('AD_DOMAIN_DNS') or
                not setting('AD_DOMAIN_DNS')):
            raise PermissionError('AD : domaine attendu non configuré ou différent')
        if set(target) != {'agent_id','user_sid','domain_dns'}:
            raise PermissionError('AD : champs target supplémentaires interdits')
    if tag == 'EDR_ISOLATE':
        if not enabled('ENABLE_EDR_ISOLATION') or not enabled('ENABLE_PROD_ACTIONS'):
            raise PermissionError('EDR isolation désactivée')
        if data.get('confidence',0) < 0.95:
            raise PermissionError('Confiance EDR isolation inférieure à 0.95')
        if enabled('ENABLE_PROGRESSIVE_GUARD'):
            import sys
            root=str(Path(__file__).resolve().parent.parent)
            if root not in sys.path:sys.path.insert(0,root)
            from ops.progressive_guard_v40 import guard_isolation
            guard_isolation(data,dbconn)
    if tag == 'EDR_COLLECT' and not enabled('ENABLE_PROD_ACTIONS'):
        raise PermissionError('EDR collection non autorisée en production')
    if tag == 'F2B_TEST_BAN' and not enabled('ENABLE_TEST_ACTIONS'):
        raise PermissionError('ENABLE_TEST_ACTIONS=false')
    if tag == 'WAZUH_AR_PROOF' and not enabled('ENABLE_TEST_ACTIONS'):
        raise PermissionError('ENABLE_TEST_ACTIONS=false')
    if tag in ('F2B_BAN_SERVER', 'WAZUH_BLOCK_AGENT', 'WINDOWS_BLOCK_IP') and not enabled('ENABLE_PROD_ACTIONS'):
        raise PermissionError('ENABLE_PROD_ACTIONS=false')
    return TAGS[tag]


def current_ssh_management_peers():
    """Identify active SSH sessions before applying any live block on this host."""
    try:
        result=subprocess.run(['ss','-H','-tn','state','established','( sport = :22 )'],
                              capture_output=True,text=True,timeout=4)
    except (OSError, subprocess.TimeoutExpired):
        raise PermissionError('Unable to check current SSH management peers') from None
    if result.returncode:
        raise PermissionError('SSH management inventory unavailable; live ban refused')
    values=set()
    for line in result.stdout.splitlines():
        parts=line.split()
        if len(parts)<5:continue
        peer=parts[4].rsplit(':',1)[0].strip('[]')
        try: values.add(ipaddress.ip_address(peer))
        except ValueError: pass
    return values


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
        if ip in current_ssh_management_peers():
            raise PermissionError('IP de session SSH actuellement connectée : protégée')
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


def f2b_bantime_seconds(jail):
    p = subprocess.run(['fail2ban-client','get',jail,'bantime'],
                       capture_output=True,text=True,timeout=8)
    if p.returncode:
        raise RuntimeError('Impossible de vérifier bantime de la jail SOAR')
    try:
        seconds=int(float(p.stdout.strip()))
    except ValueError:
        raise RuntimeError('bantime non numérique') from None
    if seconds < 30 or seconds > 300:
        raise PermissionError('Bannissement SOAR refusé : bantime doit être entre 30 et 300 secondes')
    return seconds


def _f2b_nft_ipv4_element(value):
    """Canonical IPv4 address from nft JSON. Never use fuzzy string matching."""
    if isinstance(value, dict) and 'elem' in value:
        value = value['elem']
        if isinstance(value, dict):
            value = value.get('val')
    try:
        if not isinstance(value, str):
            return None
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        return None


def f2b_nft_confirmed(ip):
    """Verify exact SOAR nftables topology AND IPv4 membership.

    Expected live topology (GCP, 22 Nov 2026):
      table inet aegismesh_soar_gcp
      set aegismesh_block_v4 (ipv4_addr)
      chain aegismesh_input (input hook)
      rule tcp dport 443 ip saddr @aegismesh_block_v4 drop

    A missing/unreadable/unexpected ruleset raises: absence of a table is not
    evidence that a temporary ban was successfully removed. The caller must
    fail closed. Returns False *only* with a verified rule and no IP element.
    """
    ip = str(ipaddress.IPv4Address(ip))
    try:
        proc = subprocess.run(['nft', '-j', 'list', 'table', 'inet', 'aegismesh_soar_gcp'],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError('nftables inaccessible, état du confinement inconnu') from exc
    if proc.returncode:
        # Ne jamais exposer stderr brut (chemins, informations système) dans
        # les callbacks SOAR. Donner un diagnostic classifié pour l'exploitant.
        stderr = (proc.stderr if isinstance(proc.stderr, str) else '').lower()
        if 'address family not supported' in stderr or 'protocol not supported' in stderr:
            hint = 'AF_NETLINK probablement interdit par systemd'
        elif 'operation not permitted' in stderr or 'permission denied' in stderr:
            hint = 'accès Netlink refusé (restrictions systemd ou CAP_NET_ADMIN)'
        elif 'no such file or directory' in stderr or 'does not exist' in stderr:
            hint = 'table nftables absente ou non accessible'
        else:
            hint = 'consulter journalctl -u aegismesh-soar-bridge.service'
        raise RuntimeError(f'Table nftables SOAR inaccessible (nft rc={proc.returncode}; {hint})')
    try:
        entries = json.loads(proc.stdout)['nftables']
    except (TypeError, ValueError, KeyError) as exc:
        raise RuntimeError('Réponse JSON nftables SOAR invalide') from exc
    if not isinstance(entries, list):
        raise RuntimeError('Réponse nftables non structurée')
    table = False
    target_set = None
    target_chain = False
    valid_drop_rule = False
    expected = ('inet', 'aegismesh_soar_gcp')
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        obj = entry.get('table')
        if isinstance(obj, dict) and (obj.get('family'), obj.get('name')) == expected:
            table = True
        obj = entry.get('set')
        if isinstance(obj, dict) and (obj.get('family'), obj.get('table'), obj.get('name')) == (
                'inet', 'aegismesh_soar_gcp', 'aegismesh_block_v4'):
            if obj.get('type') != 'ipv4_addr' or target_set is not None:
                raise RuntimeError('Ensemble nftables SOAR absent ou ambigu')
            target_set = obj
        obj = entry.get('chain')
        if isinstance(obj, dict) and (obj.get('family'),obj.get('table'),obj.get('name')) == (
                'inet','aegismesh_soar_gcp','aegismesh_input'):
            if obj.get('type') == 'filter' and obj.get('hook') == 'input':
                target_chain = True
        obj = entry.get('rule')
        if not isinstance(obj, dict) or (obj.get('family'),obj.get('table'),obj.get('chain')) != (
                'inet','aegismesh_soar_gcp','aegismesh_input'):
            continue
        expr = obj.get('expr')
        if not isinstance(expr, list):
            continue
        port = source_set = verdict = False
        for part in expr:
            if not isinstance(part, dict):
                continue
            match = part.get('match')
            if isinstance(match, dict) and match.get('op') == '==':
                left, right = match.get('left'), match.get('right')
                payload = left.get('payload') if isinstance(left, dict) else None
                if payload == {'protocol': 'tcp', 'field': 'dport'} and right == 443:
                    port = True
                if payload == {'protocol': 'ip', 'field': 'saddr'} and right == '@aegismesh_block_v4':
                    source_set = True
            if 'drop' in part:
                verdict = True
        # Reject unrelated extra matches that might alter packet-matching scope.
        if port and source_set and verdict and len(expr) == 3:
            valid_drop_rule = True
    if not (table and target_set is not None and target_chain and valid_drop_rule):
        raise RuntimeError('Chaîne nftables SOAR inattendue : impossible de prouver le filtrage')
    elements = target_set.get('elem', [])
    if not isinstance(elements, list):
        raise RuntimeError('Éléments nftables SOAR illisibles')
    return ip in {_f2b_nft_ipv4_element(item) for item in elements}


def fail2ban_action(data, test=False):
    jail = 'aegismesh-soar-gcp'  # Never touch SSH jail.
    ip = ipcheck(data['target'].get('ip'), test=test)
    bantime = f2b_bantime_seconds(jail) if not test else 120
    if ip in f2b_get_bans(jail):
        raise PermissionError('IP déjà bannie : refus de modifier un bannissement préexistant')
    if test and f2b_nft_confirmed(ip):
        raise PermissionError('IP de test déjà présente dans nftables : refus de modifier un élément préexistant')
    applied = False
    try:
        f2b_set(jail, 'banip', ip)
        applied = True
        if ip not in f2b_get_bans(jail):
            raise RuntimeError('commande reçue mais IP non visible dans la jail')
        if not f2b_nft_confirmed(ip):
            raise RuntimeError('Bannissement non présent dans le set nftables SOAR')
        if not test:
            return {'effect': 'temporary_ban', 'banned_verified': True,
                    'nftables_verified': True, 'ip': ip, 'jail': jail,
                    'port': 443, 'duration_seconds': bantime}
    except Exception:
        if applied and not test:
            # Always roll back a newly created ban if nft verification is false,
            # malformed or unavailable. Never delete bans that preceded us.
            f2b_set(jail, 'unbanip', ip)
        raise
    finally:
        if test and applied:
            f2b_set(jail, 'unbanip', ip)
            if ip in f2b_get_bans(jail):
                raise RuntimeError('test : IP encore bannie dans Fail2ban après unban')
            if f2b_nft_confirmed(ip):
                raise RuntimeError('test : IP encore présente dans nftables après unban')
    return {'effect': 'test_ban_and_unban', 'banned_verified': True,
            'nftables_verified_during_ban': True, 'unban_verified': True,
            'nftables_removed_verified': True, 'ip': ip, 'jail': jail, 'port': 443}


def wazuh_api_request(method, path, body, headers=None, raw=False):
    """Wazuh 4.14 local HTTPS: verify TLS, using the locally installed server cert.

    Wazuh's initial installation commonly uses a self-signed leaf certificate
    without an IP SAN. For an *exact loopback* API endpoint only, trust this
    particular installed certificate and disable hostname checking while keeping
    certificate-chain verification on. Remote API endpoints MUST have normal TLS
    hostname verification and an explicitly configured trusted CA.
    """
    base = setting('WAZUH_API_URL', 'https://127.0.0.1:55000').rstrip('/')
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != 'https' or parsed.username or parsed.password:
        raise ValueError('API Wazuh : URL HTTPS sans identifiants requise')
    local = parsed.hostname in ('127.0.0.1', 'localhost', '::1') and (parsed.port or 443) == 55000
    ca = setting('WAZUH_CA_FILE')
    auto_pinned_local = False
    if not ca and local:
        default_cert = '/var/ossec/api/configuration/ssl/server.crt'
        if os.path.isfile(default_cert):
            ca = default_cert
            auto_pinned_local = True
    if enabled('WAZUH_TLS_INSECURE'):
        raise PermissionError('WAZUH_TLS_INSECURE=true interdit pour les actions SOAR')
    context = ssl.create_default_context(cafile=ca or None)
    if auto_pinned_local:
        # Only a locally installed server leaf cert is trusted, never a global
        # blanket `verify=False`. No network-accessible hostname uses this mode.
        context.check_hostname = False
    request_data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, request_data,
                                 headers=headers or {}, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                          urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(req, timeout=12) as response:
            b = response.read(32768)
            return b.decode() if raw else json.loads(b)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'Wazuh HTTP {exc.code} sur {path.split("?")[0]} (droits/API)') from None
    except urllib.error.URLError as exc:
        reason = getattr(exc, 'reason', None)
        # Never print URL userinfo/passwords, tokens or sensitive server bodies.
        desc = str(reason)[:130] if reason is not None else type(exc).__name__
        raise ConnectionError(f'Wazuh {parsed.hostname}:{parsed.port}: {desc}') from None
    except ssl.SSLError as exc:
        raise ConnectionError('Wazuh TLS: '+str(exc)[:130]) from None


def wazuh_auth_token():
    user, pwd = setting('WAZUH_USER'), setting('WAZUH_PASSWORD')
    if not user or not pwd:
        raise RuntimeError('Identifiants Wazuh absents: aegismesh-soar configure wazuh')
    basic = base64.b64encode(f'{user}:{pwd}'.encode()).decode()
    token = wazuh_api_request('POST', '/security/user/authenticate?raw=true', None,
                              {'Authorization': 'Basic '+basic}, raw=True).strip()
    if not token:
        raise RuntimeError('API Wazuh: authentification sans jeton')
    return token


def wazuh_agent_record(agent, token):
    response = wazuh_api_request('GET', '/agents?agents_list='+agent+'&limit=1', None,
                                 {'Authorization': 'Bearer '+token})
    entries = response.get('data', {}).get('affected_items', [])
    for item in entries:
        if str(item.get('id')) == agent:
            if str(item.get('status', '')).lower() != 'active':
                raise RuntimeError('Agent Wazuh '+agent+' inactif')
            return item
    raise RuntimeError('Agent Wazuh '+agent+' introuvable ou accès interdit')


def local_wazuh_proof(proof_id, *, path='/var/ossec/logs/aegismesh-soar-proof.jsonl', wait_seconds=9):
    """Check agent-side evidence, not just Wazuh API dispatch acknowledgement.

    Only manager-local (agent 000) evidence is readable on this host. Other
    agents require an explicit remote evidence check in a later stage.
    """
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            with open(path, 'rb') as source:
                source.seek(0, os.SEEK_END)
                source.seek(max(0, source.tell() - 65536))
                for raw in source:
                    try:
                        event = json.loads(raw)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if (event.get('proof_id') == proof_id and
                            event.get('event') == 'wazuh-active-response-executed' and
                            event.get('command') == 'add'):
                        return True
        except (FileNotFoundError, PermissionError, OSError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(.4)



EVIDENCE_MARKER = re.compile(r'AEGISMESH-SOAR-(PROOF|BLOCK|WINBLOCK|WINUNBLOCK|ADACCOUNT|ADFAIL|ADREADY) decision_id=([A-Za-z0-9_-]{8,64}) status=(executed|blocked|removed|disabled|failed|ready)')
AD_SID_MARKER = re.compile(r'\bsid=(S-1-5-21-(?:[0-9]{1,10}-){3}[0-9]{1,10})(?=\s|$)')
EVIDENCE_LOGS = ('/var/ossec/logs/alerts/alerts.json', '/var/ossec/logs/archives/archives.json')


def collected_wazuh_evidence(pending, *, sources=None, tail_bytes=24_000_000):
    """One bounded scan, strictly matching manager agent.id, decision and action.

    The Wazuh server must have collected these lines from the endpoint into
    alerts.json (through our dedicated rule) or archives.json. Files on agents
    alone never imply manager-side verification.
    """
    # Entries are (agent, decision_id, kind[, expected_user_sid]).
    # When checking AD evidence, SID matching is compulsory to prevent a
    # different account's log line from proving an unrelated remediation.
    wanted = {}
    for item in pending:
        if len(item) not in (3, 4):
            continue
        agent, decision_id, kind = item[:3]
        sid = item[3] if len(item) == 4 else None
        agent = str(agent).zfill(3)
        if (not RX_AGENT.fullmatch(agent) or not RX_ID.fullmatch(str(decision_id)) or
                kind not in ('proof','block','winblock','winunblock','adaccount','adfail','adready')):
            continue
        if kind in ('adaccount','adfail') and (not isinstance(sid, str) or not RX_AD_SID.fullmatch(sid)):
            continue
        wanted[(agent, decision_id, kind)] = sid
    found = {}
    if not wanted:
        return found
    for path in sources if sources is not None else EVIDENCE_LOGS:
        try:
            with open(path, 'rb') as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - tail_bytes))
                # Discard a partial line when reading only the tail.
                if stream.tell() != 0:
                    stream.readline()
                for raw in stream:
                    if b'AEGISMESH-SOAR-' not in raw:
                        continue
                    try:
                        event = json.loads(raw)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    agent = str((event.get('agent') or {}).get('id', '')).zfill(3)
                    message = event.get('full_log', '')
                    if not isinstance(message, str):
                        continue
                    for match in EVIDENCE_MARKER.finditer(message):
                        kind = {'PROOF':'proof', 'BLOCK':'block', 'WINBLOCK':'winblock', 'WINUNBLOCK':'winunblock','ADACCOUNT':'adaccount','ADFAIL':'adfail','ADREADY':'adready'}[match.group(1)]
                        expected_status = ('executed' if kind == 'proof' else 'removed' if kind == 'winunblock'
                                           else 'disabled' if kind == 'adaccount' else 'failed' if kind == 'adfail' else 'ready' if kind == 'adready' else 'blocked')
                        key = (agent, match.group(2), kind)
                        if match.group(3) == expected_status and key in wanted:
                            if kind in ('adaccount','adfail'):
                                sid_match = AD_SID_MARKER.search(message[match.end():])
                                if not sid_match or sid_match.group(1) != wanted[key]:
                                    continue
                            found[key] = path
                    if len(found) == len(wanted):
                        return found
        except (OSError, PermissionError):
            continue
    return found


def wazuh_evidence(agent, decision_id, kind='proof', *, sources=None, user_sid=None):
    item = (agent, decision_id, kind, user_sid) if kind in ('adaccount','adfail') else (agent, decision_id, kind)
    return collected_wazuh_evidence([item], sources=sources).get(
        (str(agent).zfill(3), decision_id, kind), '')


def reconcile_wazuh_decisions():
    """Promote only actions proven by Wazuh-collected endpoint events."""
    with dbconn() as conn:
        rows = conn.execute("SELECT id,payload,detail FROM decisions WHERE action_status='dispatched_unverified' LIMIT 250").fetchall()
    pending = []
    for row in rows:
        try:
            data = json.loads(row['payload'])
            tag = data.get('tag')
            if tag not in ('WAZUH_AR_PROOF', 'WAZUH_BLOCK_AGENT', 'WINDOWS_BLOCK_IP', 'AD_DISABLE_ACCOUNT', 'AD_LAB_DISABLE'):
                continue
            agent = str(data.get('target', {}).get('agent_id', ''))
            kind = ('proof' if tag == 'WAZUH_AR_PROOF' else 'winblock' if tag == 'WINDOWS_BLOCK_IP'
                    else 'adaccount' if tag in ('AD_DISABLE_ACCOUNT','AD_LAB_DISABLE') else 'block')
            sid = data.get('target', {}).get('user_sid') if kind == 'adaccount' else None
            pending.append((agent, row['id'], kind, sid, row))
        except (ValueError, TypeError, KeyError):
            continue
    requests = [(a,d,k,sid) if k == 'adaccount' else (a,d,k)
                for a,d,k,sid,_ in pending]
    requests += [(a,d,'adfail',sid) for a,d,k,sid,_ in pending if k == 'adaccount']
    found = collected_wazuh_evidence(requests)
    matched = 0
    for agent, decision_id, kind, sid, row in pending:
        location = found.get((agent, decision_id, kind))
        failed = found.get((agent, decision_id, 'adfail')) if kind == 'adaccount' else None
        if not location and not failed:
            continue
        try:
            details = json.loads(row['detail'] or '{}')
            if not isinstance(details, dict):
                details = {}
        except (TypeError, ValueError):
            details = {}
        state = 'needs_manual_review' if location and failed else 'failed' if failed else 'executed'
        details.update({'agent_execution_verified': bool(location),
                        'account_disabled_verified': bool(location) and not bool(failed) if kind=='adaccount' else details.get('account_disabled_verified'),
                        'execution_verified_on_agent': bool(location),
                        'evidence_via_wazuh': 'agent_logcollector',
                        'evidence_source': location or failed,
                        'endpoint_failure_reported': bool(failed),
                        'effect_uncertain': bool(failed)})
        with dbconn() as conn:
            result = conn.execute("UPDATE decisions SET action_status=?,status='action_executed',detail=?,updated_at=? WHERE id=? AND action_status='dispatched_unverified'",
                                  (state, json.dumps(details), utcnow(), decision_id))
            if result.rowcount:
                matched += 1
                log('wazuh_agent_evidence_verified' if state=='executed' else 'wazuh_agent_action_not_verified',
                    decision_id=decision_id, agent_id=agent, action_status=state)
    return {'pending': len(pending), 'verified_now': matched, 'still_unverified': len(pending)-matched}


def wazuh_verify_loop():
    """Continuous background reconciliation; never dispatches an action."""
    while True:
        try:
            reconcile_wazuh_decisions()
        except Exception as exc:
            log('wazuh_evidence_error', error_type=type(exc).__name__)
        time.sleep(7)

def wazuh_probe(data):
    agent = data['target'].get('agent_id')
    if not isinstance(agent, str) or not RX_AGENT.fullmatch(agent):
        raise ValueError('agent_id (3 chiffres) requis')
    allow = {x.strip() for x in setting('WAZUH_TEST_AGENTS', '000').split(',') if x.strip()}
    if agent not in allow:
        raise PermissionError('agent absent WAZUH_TEST_AGENTS')
    jwt = wazuh_auth_token()
    item = wazuh_agent_record(agent, jwt)
    osdata = item.get('os') or {}
    oslabel = ' '.join(str(osdata.get(k,'')) for k in ('name','platform','version')).lower()
    if agent == '000' or any(v in oslabel for v in ('ubuntu','debian','linux','kali','fedora','centos','rocky','rhel','suse','alma')):
        script = '!aegismesh-soar-proof'
    elif 'windows' in oslabel:
        script = '!aegismesh-soar-proof.cmd'
    else:
        raise PermissionError('OS Wazuh inconnu : exécuteur de preuve non défini')
    body = {'command': script, 'arguments': [data['decision_id']],
            'alert': {'data': {'srcip': '198.51.100.42'}}}
    result = wazuh_api_request('PUT', '/active-response?agents_list=' + agent,
                               body, {'Authorization': f'Bearer {jwt}', 'Content-Type': 'application/json'})
    block = result.get('data', {})
    if result.get('error') or block.get('total_affected_items') != 1:
        raise RuntimeError('Wazuh API n a pas confirmé la distribution de la commande')
    # API ACK merely confirms dispatch. Only 000's proof is locally readable.
    verified_local = agent == '000' and local_wazuh_proof(data['decision_id'])
    evidence = '' if verified_local else wazuh_evidence(agent,data['decision_id'])
    verified = verified_local or bool(evidence)
    return {'effect': 'wazuh_ar_verified' if verified else 'wazuh_ar_dispatched',
            'agent_id': agent, 'execution_verified_on_agent': bool(verified),
            'expected_proof_id': data['decision_id'],
            'evidence_source': evidence or ('local_manager_proof' if verified_local else None)}


def wazuh_block_agent(data):
    """Dispatch a real, short-lived firewall ban on an explicitly provisioned Linux agent.

    The agent script uses an nftables set with a native 120-second timeout.
    The manager can verify delivery, but not remote nftables execution: return
    `dispatched_unverified` until separate endpoint evidence is available.
    """
    if enabled('WAZUH_TLS_INSECURE'):
        raise PermissionError('TLS non vérifié interdit pour une Active Response de production')
    target = data['target']
    agent = target.get('agent_id')
    if not isinstance(agent, str) or not RX_AGENT.fullmatch(agent) or agent == '000':
        raise PermissionError('Agent Linux distant (ID 001-999) requis')
    allow = {x.strip() for x in setting('WAZUH_PROD_AGENT_IDS').split(',') if x.strip()}
    if agent not in allow:
        raise PermissionError('Agent non autorisé dans WAZUH_PROD_AGENT_IDS')
    ip = ipcheck(target.get('ip'), test=False)
    jwt = wazuh_auth_token()
    item = wazuh_agent_record(agent, jwt)
    osdata = item.get('os') or {}
    oslabel = ' '.join(str(osdata.get(k, '')) for k in ('name', 'platform', 'version')).lower()
    if not any(x in oslabel for x in ('linux', 'ubuntu', 'debian', 'kali', 'centos',
                                      'redhat', 'rhel', 'fedora', 'rocky', 'alma', 'suse')):
        raise PermissionError('Agent non confirmé Linux; Windows/AD exclus de cette action')
    # Fixed command. No free-form executable, shell, payload or URL from a decision.
    payload = {'command': '!aegismesh-soar-block', 'arguments': [],
               'alert': {'data': {'srcip': ip, 'decision_id': data['decision_id']}}}
    result = wazuh_api_request('PUT', '/active-response?agents_list='+agent, payload,
                               {'Authorization': 'Bearer '+jwt, 'Content-Type': 'application/json'})
    block = result.get('data', {})
    if result.get('error') or int(block.get('total_affected_items', 0)) != 1:
        raise RuntimeError('Wazuh API refuse la distribution de l’action sur l’agent')
    evidence = wazuh_evidence(agent,data['decision_id'],'block')
    return {'effect': 'wazuh_ar_verified' if evidence else 'wazuh_ar_dispatched',
            'agent_id': agent, 'script': 'aegismesh-soar-block', 'ip': ip,
            'ttl_seconds': 120, 'agent_execution_verified': bool(evidence),
            'evidence_source': evidence or None,
            'agent_evidence_path': '/var/ossec/logs/aegismesh-soar-ar.jsonl'}


def wazuh_block_windows(data):
    """Bounded Windows Firewall containment; never full-machine isolation.

    DCs must be explicitly allowlisted separately. Execution is only considered
    successful after the manager collects a matching endpoint confirmation.
    """
    if enabled('WAZUH_TLS_INSECURE'):
        raise PermissionError('Wazuh TLS verification obligatoire')
    target = data['target']
    agent = target.get('agent_id')
    if not isinstance(agent, str) or not RX_AGENT.fullmatch(agent) or agent == '000':
        raise PermissionError('ID agent Windows distant invalide')
    standard = {x.strip() for x in setting('WAZUH_WINDOWS_AGENT_IDS').split(',') if x.strip()}
    domain_controllers = {x.strip() for x in setting('WAZUH_WINDOWS_DC_AGENT_IDS').split(',') if x.strip()}
    if standard & domain_controllers:
        raise PermissionError('Agent declare Windows LAB et DC simultanement : refus')
    if agent not in standard and agent not in domain_controllers:
        raise PermissionError('Agent Windows non autorise dans la politique SOAR')
    ip = ipcheck(target.get('ip'), test=False)
    token = wazuh_auth_token()
    record = wazuh_agent_record(agent, token)
    info = record.get('os') or {}
    label = ' '.join(str(info.get(k, '')) for k in ('name', 'platform', 'version')).lower()
    if 'windows' not in label:
        raise PermissionError('La machine cible ne declare pas Windows dans Wazuh')
    # Force an on-endpoint role check as well; DC permission cannot be inferred
    # from an arbitrary target field sent by incident analysis.
    body = {'command': '!aegismesh-soar-firewall.cmd', 'arguments': [],
            'alert': {'data': {'srcip': ip, 'decision_id': data['decision_id'],
                               'dc_approved': agent in domain_controllers}}}
    result = wazuh_api_request('PUT', '/active-response?agents_list='+agent, body,
                               {'Authorization':'Bearer '+token, 'Content-Type':'application/json'})
    info = result.get('data') or {}
    if result.get('error') or int(info.get('total_affected_items', 0)) != 1:
        raise RuntimeError('Wazuh API : distribution Windows non confirmee')
    source = wazuh_evidence(agent, data['decision_id'], 'winblock')
    return {'effect': 'wazuh_ar_verified' if source else 'wazuh_ar_dispatched',
            'agent_id': agent, 'executor':'aegismesh-soar-firewall.cmd',
            'duration_seconds':120, 'agent_execution_verified':bool(source),
            'evidence_source':source or None, 'containment':'remote_ipv4_only',
            'domain_controller_policy': agent in domain_controllers}



def wazuh_disable_ad_account(data):
    """Dispatch fixed AD executor to explicitly provisioned DC only.

    The endpoint resolves SID and independently checks group membership,
    privilege exclusions, the domain, and AD readback before emitting evidence.
    API dispatch is NOT success proof.
    """
    target = data['target']
    agent = target['agent_id']
    sid = target['user_sid']
    if enabled('WAZUH_TLS_INSECURE'):
        raise PermissionError('AD : Wazuh API TLS non vérifié interdit')
    token = wazuh_auth_token()
    record = wazuh_agent_record(agent, token)
    oslabel = str((record.get('os') or {}).get('name', '')).lower()
    if 'windows' not in oslabel:
        raise PermissionError('AD : le contrôleur cible doit être Windows')
    body = {
        'command': '!aegismesh-soar-ad.cmd',
        'arguments': [],
        'alert': {'data': {
            'decision_id': data['decision_id'],
            'incident_id': data['incident_id'],
            'user_sid': sid,
            'domain_dns': target['domain_dns'],
            'expires_at': data['expires_at'],
            'confidence': data['confidence'],
            'evidence_ids': data['evidence_ids'],
            'approved': True,
            'action': 'lab_disable_account' if data['tag']=='AD_LAB_DISABLE' else 'disable_account',
        }}
    }
    response = wazuh_api_request('PUT','/active-response?agents_list='+agent,body,
                                 {'Authorization':'Bearer '+token, 'Content-Type':'application/json'})
    result = response.get('data') or {}
    if response.get('error') or int(result.get('total_affected_items',0)) != 1:
        raise RuntimeError('AD : Wazuh n a pas accusé réception de la commande sur le contrôleur')
    evidence = wazuh_evidence(agent, data['decision_id'], 'adaccount', user_sid=sid)
    error = wazuh_evidence(agent, data['decision_id'], 'adfail', user_sid=sid)
    if error: raise RuntimeError('AD endpoint signaled failure: manual verification required')
    return {'effect':'wazuh_ar_verified' if evidence else 'wazuh_ar_dispatched',
            'agent_id':agent, 'action':data['tag'],
            'user_sid':sid,'domain_dns':target['domain_dns'],
            'agent_execution_verified':bool(evidence),'evidence_source':evidence or None,
            'account_disabled_verified':bool(evidence)}

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
    if action == 'wazuh_block':
        return wazuh_block_agent(data)
    if action == 'windows_firewall_block':
        return wazuh_block_windows(data)
    if action == 'ad_account_disable':
        return wazuh_disable_ad_account(data)
    if action in ('edr_collection','edr_quarantine'):
        import sys
        sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
        from ops import edr_velociraptor as edr
        agent=(data.get('target') or {}).get('agent_id')
        if not isinstance(agent,str) or not RX_AGENT.fullmatch(agent) or agent=='000':
            raise PermissionError('Agent EDR invalide')
        cid=edr.linked(agent)
        edr.valid_client(cid)
        if action=='edr_collection':
            rows=edr.api_query(edr.COLLECT,{'ClientId':cid})
            if not rows:raise RuntimeError('Collecte Velociraptor non confirmée')
            return {'effect':'edr_collection_queued','agent_id':agent,'client_id':cid,
                    'collection_completed':False,'request':str(rows[0])[:160]}
        return edr.request_quarantine(agent,data['decision_id'])
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
                        if row['status'] not in ('sending', 'accepted_by_shuffle', 'action_executed', 'dispatched_unverified'):
                            return self.reply(409, {'error': 'decision not acknowledged by Shuffle'})
                        if row['action_status'] != 'pending':
                            if row['execution_id'] != execution_id:
                                return self.reply(409, {'error': 'execution_id_conflict'})
                            return self.reply(200, {'decision_id': ident, 'status': row['action_status'],
                                                    'detail': row['detail'], 'duplicate': True})
                        c.execute("UPDATE decisions SET action_status='executing',execution_id=?,updated_at=? WHERE id=?",
                                  (execution_id, utcnow(), ident))
                decision = json.loads(row['payload'])
                try:
                    if parse_time(decision['expires_at']) <= dt.datetime.now(dt.timezone.utc):
                        raise PermissionError('décision expirée')
                    detail = execute_tag(decision)
                    status, code = ('dispatched_unverified', 202) if detail.get('effect') in ('wazuh_ar_dispatched','edr_collection_queued','edr_quarantine_requested') else ('executed', 200)
                except Exception as exc:
                    detail = {'error': type(exc).__name__, 'reason': str(exc)[:160]}
                    status, code = ('denied', 403) if isinstance(exc, PermissionError) else ('failed', 500)
                with dbconn() as c:
                    c.execute('UPDATE decisions SET action_status=?,detail=?,status=?,updated_at=? WHERE id=?',
                              (status, json.dumps(detail), 'dispatched_unverified' if status == 'dispatched_unverified' else 'action_executed', utcnow(), ident))
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
        'SOAR_PORT', 'SOAR_DB', 'SOAR_DB_BACKEND', 'SOAR_PG_PORT',
        'SOAR_PG_DATABASE', 'SOAR_PG_USER', 'SOAR_PG_PASSWORD_FILE', 'ENABLE_TEST_ACTIONS', 'ENABLE_PROD_ACTIONS',
        'PROTECTED_CIDRS', 'WAZUH_TEST_AGENTS', 'WAZUH_API_URL', 'WAZUH_USER',
        'WAZUH_PASSWORD', 'WAZUH_CA_FILE', 'WAZUH_TLS_INSECURE', 'WAZUH_PROD_AGENT_IDS',
        'WAZUH_WINDOWS_AGENT_IDS', 'WAZUH_WINDOWS_DC_AGENT_IDS',
        'SHUFFLE_WEBHOOK_HEADER_NAME', 'SHUFFLE_WEBHOOK_HEADER_VALUE',
        'ENABLE_EDR_ISOLATION','EDR_ISOLATION_AGENT_IDS',
        'ENABLE_PROGRESSIVE_GUARD','ENABLE_AD_REMEDIATION','AD_DC_AGENT_ID','AD_DOMAIN_DNS','AD_LAB_UNTIL')})
    for name in ('DECISION_TOKEN', 'SHUFFLE_ACTION_TOKEN'):
        if len(setting(name)) < 32:
            raise SystemExit(f'{name} needs at least 32 characters')
    DB = setting('SOAR_DB', '/var/lib/aegismesh-soar/decisions.sqlite3')
    init_db()
    threading.Thread(target=sender_loop, name='shuffle-sender', daemon=True).start()
    threading.Thread(target=wazuh_verify_loop, name='wazuh-evidence-reconciler', daemon=True).start()
    host, port = setting('SOAR_BIND_HOST', '127.0.0.1'), int(setting('SOAR_PORT', '19081'))
    server = ThreadingHTTPServer((host, port), HTTP)
    log('startup', host=host, port=port, production_actions=enabled('ENABLE_PROD_ACTIONS'))
    server.serve_forever()


if __name__ == '__main__':
    main()
