#!/usr/bin/env python3
"""Read-only and attribution tests; all API responses are mocked."""
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops import edr_lab_v427 as lab
from ops import edr_velociraptor as edr

assert "FROM monitoring(client_id=ClientId" in edr.READ_QUARANTINE_RESULTS
assert 'Windows.Remediation.QuarantineMonitor' in edr.READ_QUARANTINE_RESULTS
assert edr.READ_QUARANTINE_RESULTS != edr.READ_QUARANTINE_LOGS
assert 'READ_QUARANTINE_RESULTS' in Path(edr.__file__).read_text()

def denied(fn):
    try: fn()
    except PermissionError: return
    raise AssertionError('Expected fail-closed')

with patch.object(edr,'require_root'), patch.object(edr,'linked',return_value=lab.LAB_CLIENT):
    with patch.object(edr,'api_query',return_value=[{'Result':'VelociraptorQuarantine IPsec policy created.'},{'Result':'VelociraptorQuarantine failed connection test. Removing IPsec policy.'}]) as api:
        result=lab.monitor_results('001')
        assert result['artifact_reports_failed_frontend_test']
        assert not result['endpoint_network_isolation_verified']
        assert 'frontend' in result['note']
        assert api.call_args.args==(edr.READ_QUARANTINE_RESULTS, {'ClientId':lab.LAB_CLIENT})
        denied(lambda:lab.monitor_results('006'))
    with patch.object(edr,'api_query',return_value=[{'Result':'VelociraptorQuarantine IPsec policy applied.'}]):
        result=lab.monitor_results('001')
        assert result['artifact_reports_policy_applied']
        assert not result['endpoint_network_isolation_verified']
    with patch.object(edr,'api_query',return_value=[]):
        result=lab.monitor_results('001')
        assert not result['artifact_reports_policy_applied']
        assert not result['endpoint_network_isolation_verified']
    with patch.object(edr,'linked',return_value='C.1111111111111111'), patch.object(edr,'api_query') as api:
        denied(lambda:lab.monitor_results('001'))
        api.assert_not_called()

print('PASS: V4.2.9 read-only Velociraptor quarantine artifact results, strict LAB target and no false proof')
