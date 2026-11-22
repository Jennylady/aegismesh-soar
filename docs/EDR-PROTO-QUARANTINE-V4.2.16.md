# AEGISMESH-SOAR V4.2.16 — Inspection et réparation sûre des métadonnées Quarantine

## Pourquoi V4.2.15 refuse `Artefacts Quarantine non standard`
Le serveur Velociraptor peut sérialiser des champs protobuf supplémentaires dans `label_events[].artifacts` au-delà de `artifacts` et `specs`. V4.2.15 refusait **tout** champ supplémentaire, même nul. V4.2.16 refuse uniquement les valeurs non vides/non standard, car leur suppression pourrait écraser des paramètres de ressources personnalisés.

## Depuis Windows (PowerShell) et Git
Extraire le ZIP dans `F:\SOUTENANCE\Lady\aegismesh-soar`, `git diff --check`, puis commit/push. Depuis GCP : `aegismesh-soar update`.

## GCP : lecture seule d'abord
`aegismesh-soar edr lab-quarantine status --agent-id 001`
`aegismesh-soar edr lab-quarantine transport-inspect --agent-id 001`

Contrôler `proto_metadata.safe_default_only`. Les seuls champs affichés sont les **noms** et **types**, pas les valeurs. Si vrai et si le label/bail est absent :

`aegismesh-soar edr lab-quarantine transport-repair --agent-id 001 --confirm`
`aegismesh-soar edr lab-quarantine transport-status --agent-id 001`

**Ne pas lancer `lab-quarantine start` si `wg_exception_configured` est faux.** Ne jamais isoler le contrôleur AD 006. Conserver un accès console de secours. Même lorsque l'exception UDP est persistée, vérifier séparément l'accès TLS Velociraptor, l'IPsec et le trafic LDAP lors d'un test ultérieur.

Si `nondefault_extra_keys` est non vide, ne pas supprimer le moniteur existant; relever seulement les noms de champs pour une correction ciblée qui préserve ces paramètres.
