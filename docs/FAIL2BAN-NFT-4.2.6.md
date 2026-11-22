# AEGISMESH-SOAR 4.2.6 — Accès Netlink du bridge

## Symptôme sur GCP

Après le déploiement de V4.2.5 : `F2B_TEST_BAN` est envoyé à Shuffle, mais le bridge renvoie `Table nftables SOAR inaccessible` ; pourtant `nft -a list table inet aegismesh_soar_gcp` fonctionne depuis un shell root. Aucune IP n'est laissée bannie.

## Cause probable, à confirmer sur le service réel

La version de l'unité systemd incluse dans le dépôt applique `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, qui exclut `AF_NETLINK`. Le binaire `nft` nécessite un socket Netlink, même en lecture seule. Un terminal root n'a pas nécessairement les restrictions du service systemd.

## Correction

L'unité `ops/systemd/aegismesh-soar-bridge.service` ajoute **uniquement `AF_NETLINK`** à la liste existante. L'installation/mise à jour du dépôt remplace son unité gérée, appelle `systemctl daemon-reload`, redémarre le bridge et vérifie `/health` ; les autres services restent inchangés. Le pont continue de refuser les opérations en cas d'absence de preuve nftables.

## Vérifications après déploiement

```bash
systemctl show aegismesh-soar-bridge.service -p RestrictAddressFamilies -p User -p MainPID
systemctl is-active aegismesh-soar-bridge.service
# Vérification de la restriction appliquée à l'unité systemd
systemctl cat aegismesh-soar-bridge.service | grep 'RestrictAddressFamilies='
```

Lancer ensuite `aegismesh-soar chain f2b-test --confirm` et inspecter `nftables_verified_during_ban`, `nftables_removed_verified` avec `banned_verified`, `unban_verified`.

En cas d'échec, conserver les garde-fous, relever le callback et le journal du bridge, puis les valeurs de restriction systemd. Le test utilise uniquement l'IP de documentation `198.51.100.42` et ne prouve pas le rejet d'un paquet externe. Ne pas contourner le test en désactivant la validation nftables.
