#!/usr/bin/env bash
# Install only the Wazuh AR proof executable on a Linux agent. Does not restart or reconfigure Wazuh.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo "Exécuter en root" >&2; exit 2; }
[[ -d /var/ossec/active-response/bin ]] || { echo "Agent Wazuh absent" >&2; exit 2; }
getent group wazuh >/dev/null || { echo "Groupe Wazuh introuvable" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
install -o root -g wazuh -m 0750 "$HERE/aegismesh-soar-proof" /var/ossec/active-response/bin/aegismesh-soar-proof
python3 -m py_compile /var/ossec/active-response/bin/aegismesh-soar-proof
printf 'AEGISMESH: preuve Active Response installée sur %s (aucune réponse déclenchée).\n' "$(hostname)"
