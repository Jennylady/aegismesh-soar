#!/usr/bin/env python3
"""Offline integration test for update --check and fast-forward without touching systemd."""
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = root/'bin/aegismesh-soar'
loader = SourceFileLoader('aegismesh_soar_cli_test', str(source))
spec = spec_from_loader(loader.name, loader)
mod = module_from_spec(spec)
loader.exec_module(mod)


def git(*args, cwd=None):
    return subprocess.check_output(['git',*args],cwd=cwd,text=True,stderr=subprocess.DEVNULL).strip()

with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    bare = base/'origin.git'
    git('init','--bare',str(bare))
    local = base/'source'
    other = base/'publisher'
    git('clone',str(bare),str(local))
    git('-C',str(local),'checkout','-b','main')
    git('-C',str(local),'config','user.name','AEGISMESH Test')
    git('-C',str(local),'config','user.email','test@example.invalid')
    (local/'VERSION').write_text('1\n')
    git('-C',str(local),'add','VERSION')
    git('-C',str(local),'commit','-m','initial')
    git('-C',str(local),'push','-u','origin','main')
    original=git('-C',str(local),'rev-parse','HEAD')
    git('clone','--branch','main',str(bare),str(other))
    git('-C',str(other),'config','user.name','AEGISMESH Test')
    git('-C',str(other),'config','user.email','test@example.invalid')
    (other/'VERSION').write_text('2\n')
    git('-C',str(other),'add','VERSION')
    git('-C',str(other),'commit','-m','second')
    git('-C',str(other),'push','origin','main')
    newest=git('-C',str(other),'rev-parse','HEAD')
    # Redirect all paths to a temp repo, and disable real service management.
    mod.ROOT = local
    mod.EXPECTED_ROOT = local
    mod.REMOTE_URL = str(bare)
    mod.UNIT_DEST = base/'nonexistent-service.unit'
    mod.root_required = lambda: None
    mod.tests = lambda: None
    mod.update(check_only=True)
    assert git('-C',str(local),'rev-parse','HEAD')==original
    mod.update(check_only=False)
    assert git('-C',str(local),'rev-parse','HEAD')==newest
    assert (local/'VERSION').read_text() == '2\n'
print('PASS: update --check leaves code unchanged; actual update is fast-forward only')
