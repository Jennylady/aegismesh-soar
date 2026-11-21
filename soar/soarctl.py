#!/usr/bin/env python3
"""CLI for SOAR bridge. No magic passwords, no implicit approvals."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import sys
import time
import urllib.error
import urllib.request


def config(path='/etc/aegismesh-soar/soar.env'):
    d = {}
    for row in Path(path).read_text().splitlines():
        if '=' in row and not row.lstrip().startswith('#'):
            key, value = row.split('=', 1)
            d[key.strip()] = value.strip()
    return d


def main():
    ap = argparse.ArgumentParser(description='AEGISMESH decision client for localhost bridge')
    sub = ap.add_subparsers(dest='command', required=True)
    submit = sub.add_parser('submit')
    submit.add_argument('--tag', required=True, choices=['OBSERVE','ENRICH','F2B_TEST_BAN','F2B_BAN_SERVER',
                                                         'WAZUH_AR_PROOF','WAZUH_BLOCK_AGENT','EDR_ISOLATE','AD_DISABLE_ACCOUNT'])
    submit.add_argument('--incident-id', default='manual-soar-validation')
    submit.add_argument('--ip', default='')
    submit.add_argument('--agent-id', default='')
    submit.add_argument('--evidence', action='append', default=[])
    submit.add_argument('--confidence', type=float, default=0.0)
    submit.add_argument('--approved', action='store_true')
    submit.add_argument('--wait', type=int, default=10)
    check = sub.add_parser('status')
    check.add_argument('decision_id')
    args = ap.parse_args()
    cfg = config()
    base = 'http://127.0.0.1:' + cfg.get('SOAR_PORT','19081')
    headers = {'X-Aegismesh-Token': cfg['DECISION_TOKEN'], 'Content-Type': 'application/json'}
    if args.command == 'status':
        path, payload = '/v1/decisions/' + args.decision_id, None
    else:
        ident = 'am-' + secrets.token_hex(12)
        data = {
            'decision_id': ident, 'incident_id': args.incident_id, 'tag': args.tag,
            'approved': args.approved, 'confidence': args.confidence, 'evidence_ids': args.evidence,
            'expires_at': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
            'target': {k: v for k, v in {'ip':args.ip, 'agent_id':args.agent_id}.items() if v},
        }
        path, payload = '/v1/decisions', json.dumps(data).encode()
    request = urllib.request.Request(base+path, payload, headers=headers, method='POST' if payload else 'GET')
    try:
        with urllib.request.urlopen(request, timeout=6) as r:
            print(json.dumps(json.load(r), ensure_ascii=False, indent=2))
    except urllib.error.HTTPError as e:
        print('HTTP', e.code, e.read(500).decode(), file=sys.stderr)
        raise SystemExit(1)
    if args.command == 'submit':
        for _ in range(max(0,min(args.wait,40))):
            time.sleep(1)
            request = urllib.request.Request(base+'/v1/decisions/'+ident, headers=headers)
            with urllib.request.urlopen(request, timeout=5) as r:
                status = json.load(r)
            if status['action_status'] != 'pending' or status['delivery'] not in ('queued','sending','retry'):
                print(json.dumps(status, ensure_ascii=False, indent=2))
                break
        else:
            print('No action confirmation within wait interval. Inspect workflow and /v1/decisions/<id>.')

if __name__ == '__main__':
    main()
