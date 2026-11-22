#!/usr/bin/env python3
"""Real root guard refuses unsupported platforms; no EDR action."""
import os
import sys
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ops import edr_velociraptor as edr


def run():
    # An environment without get(e)uid (such as native Windows) must fail
    # with a controlled PermissionError, not AttributeError.
    with mock.patch.object(os,'geteuid',None,create=True):
        try:
            edr.require_root()
        except PermissionError:
            pass
        else:
            raise AssertionError('EDR root guard accepted a platform without geteuid')
    # A POSIX non-root user is always refused.
    if os.name == 'posix':
        with mock.patch.object(os,'geteuid',return_value=1000):
            try:
                edr.require_root()
            except PermissionError:
                pass
            else:
                raise AssertionError('EDR root guard accepted a non-root user')
    print('PASS: EDR root guard fails closed without POSIX geteuid; no live actions')

if __name__=='__main__':run()
