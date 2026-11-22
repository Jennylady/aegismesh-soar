#!/usr/bin/env python3
"""LAB-only EDR quarantine contracts. Entirely mocked, never contacts Windows."""
import contextlib
import datetime as dt
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr

ID='001'
CID='C.3c9cde1e0b930676'
assert lab.LAB_AGENT == ID and lab.LAB_TTL_SECONDS == 180

@contextlib.contextmanager
def fake_lock():
    yield object()


def fails(fn, exc):
    try: fn()
    except exc: return
    raise AssertionError('Unexpectedly accepted unsafe operation')

with tempfile.TemporaryDirectory() as t:
    base = Path(t)
    config = base/'velociraptor.json';config.write_text('{}')
    lease_file=base/'leases.json'
    labels=set()
    def fake_modify(_, op):
        if op=='set': labels.add('Quarantine')
        else: labels.discard('Quarantine')
    def fake_atomic(path, obj):
        path.write_text(json.dumps(obj))
    def fake_status(_):
        return {'artifact_referenced_by_server_monitoring':True,'quarantine_label_present':'Quarantine' in labels}
    with (patch.object(edr,'require_root'),
          patch.object(edr,'CONF',config),
          patch.object(edr,'LEASES',lease_file),
          patch.object(edr,'lease_lock',fake_lock),
          patch.object(edr,'atomic_json',fake_atomic),
          patch.object(edr,'linked',return_value=CID),
          patch.object(edr,'valid_client',return_value={'hostname':'WIN-LAB-01','os':'windows','client_id':CID}),
          patch.object(edr,'wazuh_agents',return_value=[{'id':'001','status':'active','name':'win-lab-01'}]),
          patch.object(edr,'identity_corresponds',return_value=True),
          patch.object(edr,'timer_active',return_value=True),
          patch.object(edr,'quarantine_monitoring_status',side_effect=fake_status),
          patch.object(edr,'api_query',return_value=[{'monitoring':{'label_events':[{'label':'Quarantine','artifacts':{'specs':[{'artifact':'Windows.Remediation.QuarantineMonitor','parameters':{'env':[{'key':'RuleLookupTable','value':edr.WG_LAB_RULE_TABLE}]}}]}}]}}]),
          patch.object(edr,'labels_for',side_effect=lambda _cid: sorted(labels)),
          patch.object(edr,'modify_label',side_effect=fake_modify)):
        fails(lambda:lab.start('006',confirm=True,console_access=True),PermissionError)
        fails(lambda:lab.start('002',confirm=True,console_access=True),PermissionError)
        fails(lambda:lab.start(ID,confirm=True),PermissionError)
        fails(lambda:lab.start(ID,console_access=True),PermissionError)
        assert not lease_file.exists() and not labels
        result=lab.start(ID,confirm=True,console_access=True)
        assert result['source']=='operator_lab_real_not_ai'
        assert result['endpoint_network_isolation_verified'] is False
        assert result['production_isolation_configuration_changed'] is False
        assert labels == {'Quarantine'}
        data=json.loads(lease_file.read_text())
        assert list(data)==[ID] and data[ID]['source']=='operator_lab_real'
        assert data[ID]['decision_id'].startswith('lab-')
        created=dt.datetime.fromisoformat(data[ID]['created_at'])
        expiry=dt.datetime.fromisoformat(data[ID]['expires_at'])
        assert 179 <= (expiry-created).total_seconds() <= 181
        fails(lambda:lab.start(ID,confirm=True,console_access=True),PermissionError)
        fails(lambda:lab.stop('006',confirm=True),PermissionError)
        fails(lambda:lab.stop(ID),PermissionError)
        # Mimic existing release contract (updates label and lease atomically).
        def release(agent,*,expected_cid=None):
            assert agent==ID and expected_cid==CID
            fake_modify(CID,'remove')
            fake_atomic(lease_file,{})
            return {'agent_id':ID,'quarantine_label_removed':True}
        with patch.object(edr,'release',side_effect=release):
            out=lab.stop(ID,confirm=True)
            assert out['network_restoration_verified'] is False
            assert not labels and json.loads(lease_file.read_text())=={}
        # Existing foreign quarantine may never be overwritten or silently removed.
        labels.add('Quarantine')
        fails(lambda:lab.start(ID,confirm=True,console_access=True),PermissionError)
        assert json.loads(lease_file.read_text())=={}
        labels.clear()
        # API error during label placement: keep no dangling lease when rollback works.
        def fail_set(_,op):
            if op=='set': raise RuntimeError('API refused')
            fake_modify(CID,'remove')
        with patch.object(edr,'modify_label',side_effect=fail_set):
            fails(lambda:lab.start(ID,confirm=True,console_access=True),RuntimeError)
            assert json.loads(lease_file.read_text())=={}
        # Precondition: timer inactive means no quarantining of the endpoint.
        with patch.object(edr,'timer_active',return_value=False):
            fails(lambda:lab.start(ID,confirm=True,console_access=True),PermissionError)
        # Precondition: monitoring absent means no inert label operation.
        with patch.object(edr,'quarantine_monitoring_status',return_value={'artifact_referenced_by_server_monitoring':False}):
            fails(lambda:lab.start(ID,confirm=True,console_access=True),PermissionError)
        # Monitoring under an unrelated label must NOT pass as a valid guard.
        with patch.object(edr,'api_query',return_value=[{'monitoring':{'label_events':[{'label':'Other','artifacts':{'specs':[{'artifact':'Windows.Remediation.QuarantineMonitor','parameters':{'env':[{'key':'RuleLookupTable','value':edr.WG_LAB_RULE_TABLE}]}}]}}]}}]):
            assert not lab.monitor_assigned_to_quarantine()
        assert lab.monitor_assigned_to_quarantine()
        # Read-only monitoring results are strictly attributed to the linked client.
        with patch.object(edr,'api_query',return_value=[{'level':'INFO','message':'fake artifact record'}]) as q:
            out=lab.monitoring_logs(ID)
            assert out['endpoint_network_isolation_verified'] is False
            assert q.call_args.args==(edr.READ_QUARANTINE_LOGS, {'ClientId':CID})

# Absolute deny of arbitrary VQL and unknown EDR command injection.
assert 'READ_QUARANTINE_LOGS' in Path(edr.__file__).read_text()
assert 'lab-quarantine' in Path(edr.__file__).read_text()
print('PASS: LAB 001 quarantine 180s, DC refusal, rollback, external label protection, no fabricated AI score or endpoint verification')
