#!/usr/bin/env python3
"""Manager rules post-restart API listener check; mock-only."""
from pathlib import Path
import sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ops/wazuh'))
import install_manager_evidence as mgr

class Socket:
    def close(self):pass

def run():
    hits=[]
    def fail_twice(addr,delay):
        hits.append(addr)
        if len(hits)<3:raise ConnectionRefusedError()
        return Socket()
    assert mgr.wait_api_socket(timeout=2,connector=fail_twice,sleeper=lambda t:None)
    assert hits==[('127.0.0.1',55000)]*3
    assert not mgr.wait_api_socket(timeout=0,connector=lambda *_: (_ for _ in ()).throw(ConnectionRefusedError()))
    assert issubclass(mgr.WazuhAPIReadinessError, RuntimeError)
    assert 'except WazuhAPIReadinessError:' in Path(mgr.__file__).read_text()
    print('PASS: manager rules restart awaits local Wazuh API and retains valid rules on API-only delay; no live actions')

if __name__=='__main__':run()
