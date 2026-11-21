#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
[[ "${EUID}" -eq 0 ]] || { echo 'Exécuter en root'; exit 1; }
[[ -d /var/ossec/active-response/bin ]] || { echo 'Wazuh Active Response absent'; exit 1; }
[[ -f "${HERE}/aegismesh-soar-proof" ]] || { echo 'Script de preuve absent'; exit 1; }
DEST=/var/ossec/active-response/bin/aegismesh-soar-proof
if [[ -e "$DEST" ]]; then
  cmp -s "$DEST" "$HERE/aegismesh-soar-proof" || { echo 'Un exécutable portant le même nom existe déjà : pas d’écrasement'; exit 2; }
  echo 'Exécutable de preuve déjà installé (contenu identique).'; exit 0
fi
getent group wazuh >/dev/null || { echo 'Groupe wazuh absent; installation abandonnée'; exit 2; }
install -m 750 -o root -g wazuh "${HERE}/aegismesh-soar-proof" "$DEST"
echo 'Exécutable de preuve installé sans modifier ossec.conf ni redémarrer Wazuh.'
