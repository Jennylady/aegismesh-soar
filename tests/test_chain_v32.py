#!/usr/bin/env python3
"""V3.2 checks require no real Shuffle/Wazuh/Fail2ban services."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root/'soar'))
from bridge import local_wazuh_proof

with tempfile.TemporaryDirectory() as td:
    log=Path(td)/'proof.jsonl'
    log.write_text(json.dumps({'proof_id':'am-proof-00001234','event':'wazuh-active-response-executed','command':'add'})+'\n')
    assert local_wazuh_proof('am-proof-00001234',path=str(log),wait_seconds=0)
    assert not local_wazuh_proof('am-unknown-000012',path=str(log),wait_seconds=0)

p=subprocess.run([sys.executable,str(root/'ops/chain.py'),'guide'],capture_output=True,text=True,timeout=5)
assert p.returncode==0 and '$exec.decision_id' in p.stdout
p=subprocess.run([sys.executable,str(root/'ops/chain.py'),'f2b-test'],capture_output=True,text=True,timeout=5)
assert p.returncode != 0 and '--confirm' in p.stderr
p=subprocess.run([sys.executable,str(root/'bin/aegismesh-soar'),'chain','--help'],capture_output=True,text=True,timeout=5)
assert p.returncode == 0
print('PASS: modes chain, preuve locale Wazuh, gardes des tests actifs validés sans action réelle')
