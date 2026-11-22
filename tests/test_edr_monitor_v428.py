#!/usr/bin/env python3
"""AEGISMESH 4.2.8: safe, mocked client monitoring assignment tests."""
from pathlib import Path
import sys
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr

CID=lab.LAB_CLIENT
MON='Windows.Remediation.QuarantineMonitor'

def monitor(*, label='Other', globally=False, style='specs'):
    assignment = {'specs':[{'artifact':MON}]} if style=='specs' else {'artifacts':[MON]}
    return {'monitoring': {
        'artifacts': assignment if globally else {'specs': []},
        'label_events': [] if globally else [{'label':label,'artifacts':assignment}],
    }}

def assert_denied(fn, cls=PermissionError):
    try: fn()
    except cls: return
    raise AssertionError('Failed closed precondition: unexpected success')

with patch.object(edr,'api_query',return_value=[monitor(label='Other')]):
    assert not lab.monitor_assigned_to_quarantine()
    assert lab._read_monitoring_assignments()['labels']==['Other']
with patch.object(edr,'api_query',return_value=[monitor(label='Quarantine')]):
    assert lab.monitor_assigned_to_quarantine()
with patch.object(edr,'api_query',return_value=[monitor(label='Quarantine',style='artifacts')]):
    assert lab.monitor_assigned_to_quarantine()
with patch.object(edr,'api_query',return_value=[monitor(globally=True)]):
    assert lab.monitor_assigned_to_quarantine()
with patch.object(edr,'api_query',return_value=[{'monitoring':{'label_events':[{'label':'Other','artifacts':{'specs':[{'artifact':MON}]}}]}}]):
    assert not lab.monitor_assigned_to_quarantine()
with patch.object(edr,'api_query',return_value=[{'monitoring':{'artifacts':{'specs':[{'artifact':'Other'}]}, 'label_events':[]}}]):
    assert not lab.monitor_assigned_to_quarantine()
with patch.object(edr,'api_query',return_value=[{'monitoring':'invalid json'}]):
    assert_denied(lab.monitor_assigned_to_quarantine,RuntimeError)
with patch.object(edr,'api_query',return_value=[]):
    assert_denied(lab.monitor_assigned_to_quarantine,RuntimeError)

base_patches = [
    patch.object(edr,'require_root'),
    patch.object(lab,'_validate_target',return_value=CID),
    patch.object(edr,'labels_for',return_value=[]),
    patch.object(edr,'read_json',return_value={}),
    patch.object(edr,'api_clients',return_value=[{'client_id':CID, 'labels':[]}]),
]
from contextlib import ExitStack
with ExitStack() as stack:
    for p in base_patches: stack.enter_context(p)
    state = {'monitoring':monitor(label='Other')}
    queries=[]
    def fake_api(query):
        queries.append(query)
        if query==edr.READ_MONITORING:
            return [state['monitoring']]
        if query==edr.ADD_QUARANTINE_MONITOR:
            state['monitoring']=monitor(label='Quarantine')
            return [{'result':True}]
        raise AssertionError('Unexpected VQL')
    with patch.object(edr,'api_query',side_effect=fake_api):
        assert_denied(lambda:lab.ensure_monitor('001'))
        assert not queries
        before=lab.monitor_status('001')
        assert not before['ready_for_lab_quarantine']
        after=lab.ensure_monitor('001',confirm=True)
        assert after['status']=='monitor_configured' and after['changed']
        assert edr.ADD_QUARANTINE_MONITOR in queries
        assert lab.monitor_status('001')['ready_for_lab_quarantine']
        previous_count=queries.count(edr.ADD_QUARANTINE_MONITOR)
        again=lab.ensure_monitor('001',confirm=True)
        assert again['status']=='already_configured' and not again['changed']
        assert queries.count(edr.ADD_QUARANTINE_MONITOR)==previous_count

with ExitStack() as stack:
    for p in base_patches: stack.enter_context(p)
    with patch.object(edr,'api_query',return_value=[monitor(label='Other')]) as api:
        with patch.object(edr,'api_clients',return_value=[{'client_id':'C.abcdef1234567890','labels':['Quarantine']}]):
            assert_denied(lambda:lab.ensure_monitor('001',confirm=True))
        with patch.object(edr,'read_json',return_value={'001':{'client_id':CID}}):
            assert_denied(lambda:lab.ensure_monitor('001',confirm=True))
        with patch.object(edr,'labels_for',return_value=['Quarantine']):
            assert_denied(lambda:lab.ensure_monitor('001',confirm=True))
        assert api.call_count >= 3

with ExitStack() as stack:
    for p in base_patches: stack.enter_context(p)
    def fails_to_update(query):
        if query==edr.READ_MONITORING:return [monitor(label='Unrelated')]
        if query==edr.ADD_QUARANTINE_MONITOR:return [{'result':False}]
    with patch.object(edr,'api_query',side_effect=fails_to_update):
        assert_denied(lambda:lab.ensure_monitor('001',confirm=True),RuntimeError)

assert 'COLLECT_CLIENT' in Path(__file__).resolve().parents[1].joinpath('docs/EDR-MONITOR-V4.2.8.md').read_text()
print('PASS: V4.2.8 targeted Quarantine monitoring, idempotent setup, least privilege, no actual EDR action')
