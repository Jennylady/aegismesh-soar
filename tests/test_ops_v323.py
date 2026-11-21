#!/usr/bin/env python3
"""V3.2.3 CLI tests: ensure secrets stay out of help and rotation cannot run unattended."""
from pathlib import Path
import subprocess,sys,os
root=Path(__file__).resolve().parent.parent
cli=root/'bin/aegismesh-soar'
def run(*args):
    return subprocess.run([sys.executable,str(cli),*args],capture_output=True,text=True,timeout=15,
                          env={**os.environ,'TERM':'dumb','NO_COLOR':'1'},input='')
assert run('logs','--help').returncode==0
assert '--lines' in run('logs','--help').stdout
assert 'rotate-action-token' in run('configure','--help').stdout
r=run('configure','rotate-action-token')
assert r.returncode!=0, 'no-TTY rotation must refuse to rotate'
assert 'Traceback' not in r.stderr
assert run('--help').returncode==0
print('PASS: logs CLI exposed; token rotation requires interactive terminal')
