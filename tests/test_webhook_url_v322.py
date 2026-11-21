#!/usr/bin/env python3
"""Regression tests: Shuffle /hooks and /webhooks. No network or privileged writes."""
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from pathlib import Path
import sys

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
loader = SourceFileLoader('aegismesh_soar_cli_webhook_test', str(root/'bin/aegismesh-soar'))
spec = spec_from_loader(loader.name, loader)
cli = module_from_spec(spec)
loader.exec_module(cli)
validate = cli.validate_shuffle_webhook_url
id_ = 'webhook_f10e9aed-b06a-423d-bc98-c38b0f6587bb'
for url in (
    'http://127.0.0.1:15001/api/v1/hooks/' + id_,
    'http://127.0.0.1:18031/api/v1/hooks/' + id_,
    'http://127.0.0.1:15001/api/v1/webhooks/' + id_,
    'https://shuffle.example.org/api/v1/hooks/' + id_,
):
    assert validate(url) == url, url
for url in (
    'http://127.0.0.1:15001/hooks/' + id_,
    'http://127.0.0.1:15001/api/v1/hooks/webhook_',
    'http://127.0.0.1:15001/api/v1/hooks/' + id_ + '?token=leak',
    'http://attacker.example/api/v1/hooks/' + id_,
    'http://127.0.0.1:bad/api/v1/hooks/' + id_,
    'http\\://127.0.0.1:15001/api/v1/hooks/' + id_,
    'http://user:pass@127.0.0.1:15001/api/v1/hooks/' + id_,
    'file:///api/v1/hooks/' + id_,
):
    try:
        validate(url)
    except ValueError:
        pass
    else:
        raise AssertionError('URL dangereuse ou incorrecte acceptée: ' + url)
print('PASS: Shuffle /api/v1/hooks et /api/v1/webhooks acceptés ; URL incorrectes refusées')
