#!/usr/bin/env python3
import datetime as dt
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "soar"))
from bridge import validate_decision, policy, ipcheck, ENV

EX={'decision_id':'abcdefghi','incident_id':'CASE-01','tag':'OBSERVE','target':{},'confidence':0.5,
    'evidence_ids':[], 'approved':False,
    'expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=10)).isoformat()}
assert validate_decision(EX)==('abcdefghi','OBSERVE')
assert policy(EX)=='record_only'
for tag in ('EDR_ISOLATE','AD_DISABLE_ACCOUNT','WAZUH_BLOCK_AGENT'):
    x={**EX,'tag':tag,'approved':True,'confidence':1,'evidence_ids':['a','b']}
    try:policy(x); raise AssertionError('critical tag allowed')
    except PermissionError:pass
for ip in ('127.0.0.1','10.77.77.34','192.168.0.10','198.51.100.42'):
    try:ipcheck(ip);raise AssertionError('unsafe destination allowed')
    except PermissionError:pass
assert ipcheck('198.51.100.42',test=True)=='198.51.100.42'
print('PASS: unknown/high-impact tags blocked; private, VPN, and reserved IPs protected')
