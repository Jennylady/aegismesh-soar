# AD Lab bridge local V3.9.2

## Cause du refus

`ad lab-disable` refusait le paramètre `SOAR_BIND_HOST` lorsqu'il désignait la passerelle Docker locale du serveur GCP et non `127.0.0.1`. Or cette adresse est nécessaire à la communication Shuffle conteneur → bridge hôte. Le test échouait avant `POST /v1/decisions` sans désactiver de compte.

## Correction

- Résout l'URL HTTP du bridge sur le **serveur courant seulement** : loopback, bind wildcard accessible par loopback, ou IPv4 réellement affectée à l'hôte (`ip -j address show`).
- Refuse les noms DNS arbitraires et toute IPv4 absente de la machine.
- Précontrôle `/health` avant l'ouverture de `AD_LAB_UNTIL`, puis `POST /v1/decisions` au même endpoint avec le `DECISION_TOKEN` déjà configuré.
- Les garanties de l'agent Windows `006`, du groupe AD d'éligibilité et de la fenêtre opérateur restent inchangées. Aucun utilisateur n'est ajouté au groupe et aucune action AD n'est lancée par les tests.

## Validation après déploiement

```bash
aegismesh-soar update
aegismesh-soar ad status
# Uniquement si la preuve readiness de 40 min a expiré :
aegismesh-soar ad probe --confirm
# Le seul compte d'essai créé et éligible :
aegismesh-soar ad lab-disable --sid 'S-1-5-21-1802484851-3511485622-4185718730-1108' --confirm
```

Ne pas répéter `ad lab-disable` en cas de réponse réseau incertaine : vérifier `aegismesh-soar orchestrate recent` et l'état réel du compte dans AD. Une acceptation HTTP/Shuffle n'est pas une preuve de désactivation.
