#!/usr/bin/env bash
# First-time initialization of the *new* independent Git repository.
set -euo pipefail
EXPECTED=/opt/aegismesh/soar
[[ "$EUID" -eq 0 ]] || { echo 'Exécuter en root/sudo'; exit 2; }
[[ "$(pwd -P)" == "$EXPECTED" ]] || { echo "Placez les fichiers et entrez dans $EXPECTED"; exit 2; }
[[ -f "$EXPECTED/bin/aegismesh-soar" ]] || { echo 'Fichiers du paquet absents'; exit 2; }
if [[ ! -d .git ]]; then
    git init -b main
    git remote add origin https://github.com/Jennylady/aegismesh-soar.git
    echo 'Dépôt local initialisé. Aucun push effectué : authentification GitHub nécessaire.'
else
    echo 'Dépôt Git existant conservé ; aucun init/reset.'
fi
python3 bin/aegismesh-soar test
python3 bin/aegismesh-soar install
printf '\nPublier une seule fois le code dans le dépôt GitHub vide :\n'
printf '  git add -A && git commit -m "Initialisation AEGISMESH SOAR" && git push -u origin main\n'
printf 'Ensuite : aegismesh-soar update\n'
