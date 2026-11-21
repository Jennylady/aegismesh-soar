#!/usr/bin/env python3
"""Validate offline command-line help and static paths, without sudo or mutation."""
import ast
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parent.parent
cli = root/'bin/aegismesh-soar'
assert cli.exists()
assert 'aegismesh-soar/soar.env' in cli.read_text()
assert '/opt/aegismesh/soar' in cli.read_text()
assert 'git' in cli.read_text()
assert 'merge' in cli.read_text()
assert 'X-Aegismesh-Soar-Managed=yes' in (root/'ops/systemd/aegismesh-soar-bridge.service').read_text()
for f in (cli,root/'soar/bridge.py',root/'soar/soarctl.py',root/'ops/doctor.py'):
    ast.parse(f.read_text(),filename=str(f))
proc = subprocess.run([sys.executable,str(cli),'--help'],capture_output=True,text=True)
assert proc.returncode==0,proc.stderr
assert 'update' in proc.stdout and 'doctor' in proc.stdout
proc = subprocess.run([sys.executable,str(cli),'submit','--help'],capture_output=True,text=True)
assert proc.returncode==0,proc.stderr
assert '--tag' in proc.stdout
print('PASS: CLI standalone, systemd marker and production path validated')
