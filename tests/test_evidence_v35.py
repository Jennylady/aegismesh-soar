#!/usr/bin/env python3
"""Real agent proof record parser tests; no Wazuh or firewall actions."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'soar'))
import bridge

def run():
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp)/'alerts.json'
        decisions=[('002','am-f13a42cd31f500eebd3234f7','proof'),
                   ('001','am-185a777d64673edeffd70f9d','proof'),
                   ('006','am-967f2a052bc4526773179aff','proof')]
        lines=[
            {'agent':{'id':'002'},'full_log':'AEGISMESH-SOAR-PROOF decision_id=am-f13a42cd31f500eebd3234f7 status=executed'},
            {'agent':{'id':'006'},'full_log':'AEGISMESH-SOAR-PROOF decision_id=am-967f2a052bc4526773179aff status=executed'},
            # wrong agent and an unrelated decision MUST NOT verify 001
            {'agent':{'id':'006'},'full_log':'AEGISMESH-SOAR-PROOF decision_id=am-185a777d64673edeffd70f9d status=executed'},
            {'agent':{'id':'002'},'full_log':'AEGISMESH-SOAR-BLOCK decision_id=am-aaaaaaaabbbbbbbb status=blocked'},
        ]
        p.write_text(''.join(json.dumps(x)+'\n' for x in lines))
        found=bridge.collected_wazuh_evidence(decisions,sources=[str(p)])
        assert ('002',decisions[0][1],'proof') in found
        assert ('006',decisions[2][1],'proof') in found
        assert ('001',decisions[1][1],'proof') not in found
        # ensure wrong status is not accepted
        assert not bridge.collected_wazuh_evidence([('002','am-aaaaaaaabbbbbbbb','proof')],sources=[str(p)])
    # Installer performs no changes in preview mode.
    sys.path.insert(0,str(ROOT/'ops/wazuh'))
    import install_manager_evidence as manager
    assert 'PREVIEW' in manager.install()
    assert manager.IDS=={'119870','119871','119872','119873','119874','119875','119876'}
    assert 'aegismesh-soar-evidence.log' in (ROOT/'ops/wazuh/install_agent_proof.sh').read_text()
    assert 'aegismesh-soar-evidence.log' in (ROOT/'ops/wazuh/windows/Install-AegisMeshProof.ps1').read_text()
    assert 'wazuh_verify_loop' in (ROOT/'soar/bridge.py').read_text()
    import xml.etree.ElementTree as ET
    rules=ET.parse(ROOT/'ops/wazuh/rules/aegismesh-soar-evidence.xml').getroot()
    assert {r.get('id') for r in rules.findall('rule')} == manager.IDS
    proc=subprocess.run([sys.executable,str(ROOT/'bin/aegismesh-soar'),'fleet','evidence','install'],capture_output=True,text=True,timeout=8)
    assert proc.returncode==0,proc.stderr
    assert 'PREVIEW' in proc.stdout
    print('PASS: manager evidence uses strict agent+decision matching; Linux/Windows collector recipes present')

if __name__ == '__main__':run()
