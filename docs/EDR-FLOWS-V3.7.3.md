# Correctif V3.7.3 — Suivi Velociraptor

L'adaptateur V3.7.2 écartait les collections VQL lorsque leur identifiant utilisait `FlowId` au lieu de `flow_id`. Le correctif normalise les propriétés `FlowId`, `ClientId`, `Request`, `Creator`, `State` et leurs équivalents snake_case, tout en conservant les contrôles exacts d'attribution.

Sur GCP après `aegismesh-soar update` :

```bash
aegismesh-soar edr flows --agent-id 001
aegismesh-soar edr flows --agent-id 002
aegismesh-soar edr flow-status --agent-id 001 --flow-id F.DC1APVLV8NO1Q
aegismesh-soar edr flow-status --agent-id 002 --flow-id F.DC1B583LF7L32
aegismesh-soar edr investigations
```

Toutes ces commandes sont strictement en lecture seule du serveur EDR. Une erreur de schéma désormais signalée explicitement indique un besoin de vérification, pas une absence de données. Pour un flow `FINISHED`, un résultat `result_rows_sampled=0` ne prouve pas qu'un artefact a retourné des résultats.
