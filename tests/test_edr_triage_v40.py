#!/usr/bin/env python3
"""OS-bound EDR triage and quarantine monitor checks; mocked mTLS only."""
import sys
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from ops import edr_velociraptor as edr


@mock.patch.object(edr, 'require_root')
def run(root_guard):
    # These are offline tests on Windows and Linux: no root, no real API.
    # Production CLI still enforces require_root() on the GCP Linux host.
    cid='C.'+'a'*16
    win={'client_id':cid,'hostname':'win-lab-01','os':'windows'}
    wz={'id':'001','name':'win-lab-01','status':'active','os':{'name':'Microsoft Windows'}}
    requests=[]
    def fake_api(query, env=None, **_):
        requests.append((query,env))
        if query==edr.COLLECT_WIN_TRIAGE:
            return [{'collection':{'flow_id':'F.ABCD12345678'}}]
        raise AssertionError('Unexpected VQL')
    with mock.patch.object(edr,'linked',return_value=cid), \
         mock.patch.object(edr,'valid_client',return_value=win), \
         mock.patch.object(edr,'wazuh_agents',return_value=[wz]), \
         mock.patch.object(edr,'flow_list',return_value=[]), \
         mock.patch.object(edr,'api_query',side_effect=fake_api), \
         mock.patch.object(edr,'track_flow') as tracked:
        r=edr.request_triage('001',confirm=True)
        assert r['flow_id']=='F.ABCD12345678' and r['endpoint_data_verified'] is False
        assert edr.COLLECT_WIN_TRIAGE in [x[0] for x in requests]
        tracked.assert_called_once()
    with mock.patch.object(edr,'linked',return_value=cid), \
         mock.patch.object(edr,'valid_client',return_value=win), \
         mock.patch.object(edr,'wazuh_agents',return_value=[wz]), \
         mock.patch.object(edr,'flow_list',return_value=[{'state':'RUNNING'}]):
        try:edr.request_triage('001',confirm=True);raise AssertionError('Duplicated active EDR collection')
        except RuntimeError:pass
    assert 'Linux.Sys.Pslist' in edr.COLLECT_LINUX_TRIAGE
    assert 'Linux.Network.Netstat' in edr.COLLECT_LINUX_TRIAGE
    # Named Kali Wazuh agent maps to Velociraptor hostname 'offensive'. A
    # manually approved mapping needs its own short-lived attestation.
    linux={'client_id':cid,'hostname':'offensive','os':'linux'}
    kali={'id':'002','name':'kali-ikom','status':'active','os':{'name':'Linux'}}
    from datetime import datetime, timezone, timedelta
    until=(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat()
    with mock.patch.object(edr,'read_json',return_value={'002':{'client_id':cid,
         'wazuh_name':'kali-ikom','edr_hostname':'offensive','expires_at':until}}):
        assert edr.identity_corresponds('002',linux,kali) is True
    with mock.patch.object(edr,'read_json',return_value={}):
        assert edr.identity_corresponds('002',linux,kali) is False
    with mock.patch.object(edr,'linked',return_value=cid), \
         mock.patch.object(edr,'valid_client',return_value=linux), \
         mock.patch.object(edr,'wazuh_agents',return_value=[kali]), \
         mock.patch.object(edr,'atomic_json') as save:
        result=edr.attest_link('002',confirm=True)
        assert result['edr_hostname']=='offensive' and result['mapping_explicitly_attested']
        save.assert_called_once()
    assert root_guard.call_count == 3, 'Sensitive EDR entrypoints must still require root in production'
    print('PASS: OS-specific EDR triage, root guard mocked only in unit tests, duplicate flow guard; no live collections')

if __name__=='__main__':run()
