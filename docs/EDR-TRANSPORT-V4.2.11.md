# AEGISMESH SOAR V4.2.11 — Correction transport EDR pour Windows LAB 001

## Constat réel

GCP a correctement déployé V4.2.10 (`a32c97a62005`), mais `transport-status` et `transport-ensure` ont affiché « Moniteur Quarantine absent ou dupliqué ». Cela ne prouve pas la disparition du moniteur : Velociraptor peut stocker le nom d'un artefact sans paramètres personnalisés dans `label_events[].artifacts.artifacts` sans ajouter de ligne `specs`. La V4.2.10 exigeait, à tort, une ligne `specs`.

Une nouvelle quarantaine de labo a été démarrée (`lab-247df20e198e85033b5fb4b3`, expiration `2026-11-22T18:38:55Z`) **sans exception UDP confirmée** ; aucune preuve d'isolement réseau n'est acquise. Attendre la libération ou utiliser la commande de retrait si le bail est encore actif.

## Correctif

`transport-status` lit maintenant correctement les deux représentations et distingue un artefact existant avec paramètres par défaut d'un artefact absent. Les doublons restent refusés. `start` exige l'exception WireGuard confirmée avant tout nouveau test.

## Procédure GCP

```sh
aegismesh-soar update
aegismesh-soar edr lab-quarantine status --agent-id 001
aegismesh-soar edr lab-quarantine transport-inspect --agent-id 001
aegismesh-soar edr lab-quarantine transport-status --agent-id 001
# Uniquement après disparition du label et du bail et si aucune autre machine n'est marquée Quarantine :
aegismesh-soar edr lab-quarantine transport-ensure --agent-id 001 --confirm
aegismesh-soar edr lab-quarantine transport-status --agent-id 001
```

Le test d'isolation ne doit être tenté à nouveau que si `wg_exception_configured: true`, avec console locale de secours non réseau sur Windows LAB et mesure réseau réelle. En cas de refus API ou de valeur différente après configuration, conserver la cible non isolée et examiner la table client monitoring. Il reste possible qu'une négociation TLS frontend interrompe l'isolement même lorsque UDP 51820 est autorisé.

**Ne jamais** modifier les certificats ou le contrôleur AD, désactiver les tests de connexion Velociraptor, ni inventer une preuve `endpoint_network_isolation_verified`.
