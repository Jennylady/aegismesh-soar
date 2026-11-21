#!/usr/bin/env python3
"""Wait until THIS bridge really answers /health before systemd finishes restart.

The old V2 updater tests health immediately after `systemctl restart`. By using
ExecStartPost, systemd restart only completes once the local bridge is ready.
Never restarts/changes other services and never prints secrets.
"""
import argparse
import os
from pathlib import Path
import sys

# This script is launched by systemd, under the same effective user as the bridge.
from health import wait_ready


def settings():
    values = {'SOAR_BIND_HOST': '127.0.0.1', 'SOAR_PORT': '19081'}
    path = Path(os.environ.get('AEGISMESH_SOAR_ENV', '/etc/aegismesh-soar/soar.env'))
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                key, value = line.split('=', 1)
                if key.strip() in values:
                    values[key.strip()] = value.strip().strip('"')
    for key in tuple(values):
        if key in os.environ:
            values[key] = os.environ[key]
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description='Readiness gate for aegismesh-soar-bridge.service')
    parser.add_argument('--timeout', type=float, default=30)
    args = parser.parse_args(argv)
    cfg = settings()
    if not 0 < args.timeout <= 90:
        parser.error('--timeout doit être compris entre 0 et 90 secondes')
    ready, reason = wait_ready(cfg['SOAR_BIND_HOST'], cfg['SOAR_PORT'], seconds=args.timeout)
    if ready:
        print('[READY] Pont SOAR répond sur /health', flush=True)
        return 0
    print('[NOT_READY] Pont SOAR non disponible après attente : ' + reason, file=sys.stderr, flush=True)
    print('Vérifier: journalctl -u aegismesh-soar-bridge.service -n 70 --no-pager', file=sys.stderr, flush=True)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
