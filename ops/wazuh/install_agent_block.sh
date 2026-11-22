#!/usr/bin/env bash
# One-time Linux agent-side deployment. Does not modify ossec.conf or Wazuh manager.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Exécuter en root'; exit 2; }
[[ -x /usr/sbin/nft || -x /usr/bin/nft ]] || { echo 'nft manquant : installer nftables sur cet agent'; exit 2; }
[[ -d /var/ossec/active-response/bin ]] || { echo 'Wazuh agent non installé sur cet endpoint'; exit 2; }
SRC="$(cd "$(dirname "$0")" && pwd)/aegismesh-soar-block"
[[ -f "$SRC" ]] || { echo 'Script source introuvable'; exit 2; }
getent group wazuh >/dev/null || { echo 'Groupe wazuh manquant'; exit 2; }
install -o root -g wazuh -m 0750 "$SRC" /var/ossec/active-response/bin/aegismesh-soar-block
install -o root -g wazuh -m 0750 "$(dirname "$SRC")/aegismesh-soar-block-status" /var/ossec/active-response/bin/aegismesh-soar-block-status
python3 -m py_compile /var/ossec/active-response/bin/aegismesh-soar-block
python3 -m py_compile /var/ossec/active-response/bin/aegismesh-soar-block-status
printf 'Action Linux installée dans /var/ossec/active-response/bin/aegismesh-soar-block\n'
printf 'Blocage IPv4 public via nftables (TTL 120 s). Aucun blocage déclenché.\n'
