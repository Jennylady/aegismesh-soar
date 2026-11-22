# AEGISMESH-SOAR V4.2.14 — Patch VQL typé pour moniteur Quarantine

## Raison de la correction
Sur GCP en V4.2.13, `transport-diagnose --agent-id 001` a révélé `patch_preview_valid: false` et `Liste des spécifications du monitoring invalide`. La première variante VQL génère un objet que le client ne peut valider comme liste `specs`.

## Séquence ciblée, sans quarantaine
```bash
aegismesh-soar update
aegismesh-soar edr lab-quarantine transport-diagnose --agent-id 001
# Seulement si patch_preview_valid == true :
aegismesh-soar edr lab-quarantine transport-ensure --agent-id 001 --confirm
aegismesh-soar edr lab-quarantine transport-status --agent-id 001
```

## Garanties
Le patch JSON RFC 6902 est construit entièrement en code. Une variante non validée en prévisualisation est refusée sans écriture. Seule la valeur `RuleLookupTable` du moniteur du label `Quarantine` doit changer; les autres groupes sont contrôlés en lecture avant et après écriture. Cible: Windows LAB `001`. Aucune isolation du domaine AD `006`, aucune élévation de droits, modification de certificats ou de frontend, aucun score IA fictif. `wg_exception_configured: true` prouve seulement la configuration Velociraptor, pas le filtrage Windows ou la disponibilité HTTPS.
