#!/usr/bin/env bash
# Endpoint-only installation: no credentials or Git runtime on the Wazuh agent.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Root requis' >&2; exit 2; }
[[ -d /var/ossec/active-response/bin ]] || { echo 'Wazuh agent introuvable' >&2; exit 2; }
getent group wazuh >/dev/null || { echo 'Groupe wazuh absent' >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
install -o root -g wazuh -m 0750 "$HERE/aegismesh-soar-proof" /var/ossec/active-response/bin/aegismesh-soar-proof
if [[ -f /var/ossec/active-response/bin/aegismesh-soar-block ]]; then
  install -o root -g wazuh -m 0750 "$HERE/aegismesh-soar-block" /var/ossec/active-response/bin/aegismesh-soar-block
fi
python3 -m py_compile /var/ossec/active-response/bin/aegismesh-soar-proof
LOG=/var/ossec/logs/aegismesh-soar-evidence.log
if [[ ! -f "$LOG" ]]; then
  touch "$LOG"
  chown root:wazuh "$LOG"
  chmod 0640 "$LOG"
fi
if [[ "${1:-}" == '--enable-collection' ]]; then
  CFG=/var/ossec/etc/ossec.conf
  [[ -f "$CFG" ]] || { echo 'ossec.conf absent' >&2; exit 2; }
  if ! grep -Fq '<location>/var/ossec/logs/aegismesh-soar-evidence.log</location>' "$CFG"; then
    BACKUP="$CFG.aegismesh-soar.$(date -u +%Y%m%dT%H%M%SZ).bak"
    cp -a "$CFG" "$BACKUP"
    cat >> "$CFG" <<'EOF'

<!-- AEGISMESH SOAR - dedicated agent evidence collection -->
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/aegismesh-soar-evidence.log</location>
  </localfile>
</ossec_config>
EOF
    if [[ -x /var/ossec/bin/wazuh-agentd ]] && ! /var/ossec/bin/wazuh-agentd -t >/dev/null 2>&1; then
      cp -a "$BACKUP" "$CFG"
      echo 'Configuration Wazuh agent invalide: restauration effectuée' >&2
      exit 2
    fi
    echo 'Collecte dédiée ajoutée; redémarrage du service Wazuh agent uniquement.'
    if ! systemctl restart wazuh-agent.service; then
      cp -a "$BACKUP" "$CFG"
      systemctl restart wazuh-agent.service || true
      echo 'Redémarrage agent refusé; sauvegarde restaurée' >&2
      exit 2
    fi
  else
    echo 'Collecte SOAR déjà configurée; aucun redémarrage nécessaire.'
  fi
fi
printf 'AEGISMESH: exécuteur + journal installé sur %s. Aucune réponse déclenchée.
' "$(hostname)"
