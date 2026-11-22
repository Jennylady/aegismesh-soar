# AEGISMESH-SOAR V4.2.5 — Preuves Fail2ban/nftables sur GCP

## État découvert (22 novembre 2026)

Le serveur utilise la jail `aegismesh-soar-gcp` et l'action `nftables` avec :
- `table inet aegismesh_soar_gcp` ;
- `set aegismesh_block_v4` (IPv4) ;
- `chain aegismesh_input` (hook `input`) ;
- règle `tcp dport 443 ip saddr @aegismesh_block_v4 drop`.

La jail n'avait aucun ban actif à la fin du test V4.2.4, ce qui explique pourquoi le set nftables était vide. La présence de la règle ne prouve **pas** un paquet rejeté sans test réseau.

## Nouveaux contrôles

`aegismesh-soar chain f2b-test --confirm` déclenche via Shuffle une décision `F2B_TEST_BAN` ciblant uniquement `198.51.100.42`. Pendant le ban, le bridge vérifie le statut Fail2ban **et** l'appartenance au set nftables avec une règle de rejet valide. Après unban, il vérifie la disparition de l'IP dans les deux états. Ce test ne touche ni à `sshd`, ni à une IP réelle, ni aux règles statiques. Le port effectivement couvert est 443/TCP.

La vérification `F2B_BAN_SERVER` emploie la même preuve et retire le nouveau ban si nftables ne confirme pas sa mise en place. La commande `aegismesh-soar response verify-block` doit traiter une structure nftables illisible comme une erreur, jamais comme une preuve de retrait.

### Validation après `aegismesh-soar update`

```bash
aegismesh-soar chain f2b-test --confirm
fail2ban-client status aegismesh-soar-gcp
nft -a list table inet aegismesh_soar_gcp
```

Résultat attendu sur la décision de test :

```text
"banned_verified": true
"nftables_verified_during_ban": true
"unban_verified": true
"nftables_removed_verified": true
```

Ces résultats prouvent le changement d'état firewall dans la chaîne de test. Ils ne prouvent pas encore qu'une connexion TCP extérieure vers 443 a été effectivement rejetée. Le test réseau supplémentaire doit se faire exclusivement depuis un client de laboratoire approuvé et avec canal d'administration séparé.

### Si un test échoue

Ne pas désactiver les garde-fous. Vérifier seulement `fail2ban-client status aegismesh-soar-gcp`, `nft -j list table inet aegismesh_soar_gcp` et les logs du bridge. Ne pas nettoyer manuellement les règles sans avoir vérifié l'absence d'autres bans légitimes.
