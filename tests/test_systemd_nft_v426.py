#!/usr/bin/env python3
"""Regression: AF_NETLINK required for nft read access inside SOAR systemd service.

Purely static and mocked tests. No actual systemd, nft or Fail2ban actions.
"""
from pathlib import Path
from unittest import mock
import subprocess, sys

root = Path(__file__).resolve().parent.parent
unit = (root/'ops/systemd/aegismesh-soar-bridge.service').read_text()
lines = [line.partition('=')[2].split() for line in unit.splitlines()
         if line.startswith('RestrictAddressFamilies=')]
assert len(lines) == 1, 'a single explicit address-family allowlist is required'
assert set(lines[0]) == {'AF_INET', 'AF_INET6', 'AF_UNIX', 'AF_NETLINK'}, lines[0]
for protected in ('User=root', 'Group=root', 'NoNewPrivileges=true',
                  'PrivateTmp=true', 'ProtectHome=true', 'ProtectSystem=full',
                  'ProtectKernelTunables=true', 'ProtectControlGroups=true'):
    assert protected in unit, protected
assert 'AF_PACKET' not in unit

sys.path.insert(0,str(root/'soar'))
import bridge
ip = '198.51.100.42'
for stderr, expected in [
    ('Error: netlink: Address family not supported by protocol', 'AF_NETLINK'),
    ('Error: netlink: Operation not permitted', 'CAP_NET_ADMIN'),
    ('Error: No such file or directory', 'table nftables absente'),
    ('Error: an unknown failure SECRET_CANARY', 'consulter journalctl'),
]:
    proc = subprocess.CompletedProcess([], 1, stdout='', stderr=stderr)
    with mock.patch.object(bridge.subprocess, 'run', return_value=proc) as run:
        try:
            bridge.f2b_nft_confirmed(ip)
        except RuntimeError as exc:
            message = str(exc)
            assert expected in message, message
            assert 'SECRET_CANARY' not in message
            assert 'rc=1' in message
        else:
            raise AssertionError('inaccessible nftables was accepted')
        run.assert_called_once_with(['nft','-j','list','table','inet','aegismesh_soar_gcp'],
                                    capture_output=True,text=True,timeout=10)
print('PASS: V4.2.6 AF_NETLINK only addition; service hardening preserved; nft failure diagnostics redacted')
