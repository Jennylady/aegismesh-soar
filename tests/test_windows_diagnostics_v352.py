#!/usr/bin/env python3
"""Read-only diagnostics and safer Windows error messages, without agent action."""
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ops'))
import fleet
win=ROOT/'ops/wazuh/windows'
ps=(win/'aegismesh-soar-proof.ps1').read_text()
cmd=(win/'aegismesh-soar-proof.cmd').read_text()
diag=(win/'Diagnose-AegisMeshProof.ps1').read_text()
assert 'reason = $_.Exception.GetType().Name' in ps
assert 'launcher_failed exit_code' in cmd
assert 'aegismesh-soar-evidence.log' in diag
assert 'Get-Service -Name WazuhSvc' in diag
assert 'Preuve locale pour decision' in diag
assert 'WriteAllText' not in diag and 'AppendAllText' not in diag
assert 'Restart-Service' not in diag and 'Set-ExecutionPolicy' not in diag
assert 'Invoke-WebRequest' not in diag
assert 'evidence_diagnose' in (ROOT/'ops/fleet.py').read_text()
with patch.object(fleet.bridge,'dbconn',side_effect=RuntimeError('mock DB reached')):
    try:
        fleet.evidence_diagnose('001','bad')
    except ValueError:
        pass
    else:
        raise AssertionError('Invalid decision ID should be rejected before DB access')
proc=subprocess.run([sys.executable,str(ROOT/'ops/fleet.py'),'evidence','diagnose','--help'],capture_output=True,text=True,timeout=5)
assert proc.returncode==0,proc.stderr
assert '--decision-id' in proc.stdout
print('PASS: Windows diagnostic read-only; launcher errors classified; manager evidence trace exposed')
