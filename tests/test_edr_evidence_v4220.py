#!/usr/bin/env python3
"""Read-only 4.2.20 evidence, strict attribution, never launch net actions."""
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ops import edr_direct_v4217 as direct, edr_velociraptor as edr

FID='F.DC1KC83C11SSI'
CID=direct.CID
artifact='Windows.Remediation.Quarantine'
flow={'client_id':CID,'flow_id':FID,'state':'FINISHED','request':{'artifacts':[artifact]},
      'total_collected_rows':16,'creator':'AEGISMESH_SOAR_API'}
rows=[{'Time':'2026-11-22T19:44:40Z','Result':'VelociraptorQuarantine IPsec policy applied.'},
      {'Time':'2026-11-22T19:44:50Z','Result':'VelociraptorQuarantine failed connection test. Removing IPsec policy.'}]
assert 'flow_results(' in edr.READ_DIRECT_QUARANTINE_RESULTS
assert "artifact='Windows.Remediation.Quarantine'" in edr.READ_DIRECT_QUARANTINE_RESULTS
assert 'LIMIT 100' in edr.READ_DIRECT_QUARANTINE_RESULTS
assert edr.DIRECT_QUARANTINE_COLLECT not in edr.READ_DIRECT_QUARANTINE_RESULTS
assert edr.DIRECT_QUARANTINE_REMOVE not in edr.READ_DIRECT_QUARANTINE_RESULTS

with patch.object(edr,'require_root'),patch.object(direct,'_identity',return_value=CID),\
     patch.object(edr,'matching_flow',return_value=flow),\
     patch.object(edr,'api_query',return_value=rows) as query:
    result=direct.evidence('001',FID)
    assert result['result_rows_read']==2
    assert result['policy_applied_reported'] is True
    assert result['frontend_check_failed_reported'] is True
    assert result['frontend_check_success_reported'] is False
    assert result['endpoint_network_isolation_verified'] is False
    assert result['network_restoration_verified'] is False
    assert len(result['results_sha256'])==64
    query.assert_called_once_with(edr.READ_DIRECT_QUARANTINE_RESULTS,{'ClientId':CID,'FlowId':FID})

with patch.object(edr,'require_root'),patch.object(direct,'_identity',return_value=CID),\
     patch.object(edr,'matching_flow',return_value={**flow,'request':{'artifacts':['Generic.Client.Info']}}),\
     patch.object(edr,'api_query') as query:
    try:direct.evidence('001',FID)
    except PermissionError:pass
    else:raise AssertionError('Non-quarantine evidence accepted')
    query.assert_not_called()

with patch.object(edr,'require_root'),patch.object(direct,'_identity',return_value=CID),\
     patch.object(edr,'matching_flow',return_value={**flow,'state':'RUNNING'}),\
     patch.object(edr,'api_query') as query:
    result=direct.evidence('001',FID)
    assert result['results_read'] is False
    query.assert_not_called()

with patch.object(edr,'require_root'),patch.object(direct,'_identity',return_value=CID),\
     patch.object(edr,'matching_flow',return_value=flow),\
     patch.object(edr,'api_query',return_value=[]) as query:
    result=direct.evidence('001',FID)
    assert result['result_rows_read']==0
    assert result['policy_applied_reported'] is False

with patch.object(edr,'require_root'),patch.object(direct,'_identity',return_value=CID),\
     patch.object(edr,'matching_flow',return_value=flow),\
     patch.object(edr,'api_query',return_value=[{'Time':'x','Result':'x'}]*101):
    try:direct.evidence('001',FID)
    except RuntimeError:pass
    else:raise AssertionError('Unbounded output accepted')

with patch.object(edr,'get_agent_flow_rows',return_value=(CID,[flow])),\
     patch.object(edr,'matching_flow',return_value=flow),\
     patch.object(edr,'api_query',return_value=rows) as query:
    outcome=edr.flow_status('001',FID,persist=False)
    assert outcome['collection_finished'] is True
    assert outcome['result_rows_sampled']==2
    assert outcome['results_present'] is True
    assert len(outcome['sample_sha256'])==64
    assert outcome['sampled_artifacts']=={artifact:2}
    query.assert_called_once_with(edr.READ_DIRECT_QUARANTINE_RESULTS,{'ClientId':CID,'FlowId':FID})

# No arbitrary identifiers; maintain hard DC refusal and strict flow matching.
with patch.object(edr,'require_root'):
    try:direct.evidence('006',FID)
    except PermissionError:pass
    else:raise AssertionError('DC evidence accepted')

print('PASS V4.2.20: immutable flow evidence, read-only results, strict client/artifact, truthful outcome')
