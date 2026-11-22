# Suivi EDR V3.7.2

Toutes les commandes ci-dessous sont à exécuter sur le GCP Orchestrator. Aucune des commandes de suivi ne déclenche de collecte.

```bash
aegismesh-soar edr flows
aegismesh-soar edr flow-status --agent-id 001 --flow-id F.DC1APVLV8NO1Q
aegismesh-soar edr flow-status --agent-id 002 --flow-id F.DC1B583LF7L32
aegismesh-soar edr investigations
```

`flows` lit les 50 flows les plus récents disponibles par agent lié; `investigations` filtre les flows créés par l'identité `AEGISMESH_SOAR_API` ou enregistrés localement. `flow-status` vérifie que le flow appartient au client associé à l'agent. Les statuts sont ceux de l'API Velociraptor (RUNNING, FINISHED, ERROR, etc.) et non des succès inventés.

Pour un flow FINISHED de l'artefact Generic.Client.Info, l'adaptateur lit au maximum 20 lignes de résultat en mémoire et ne conserve qu'une empreinte SHA256 et le nombre de lignes. `result_rows_sampled=0` signifie qu'aucune ligne n'a été retournée par la requête bornée; la preuve de collecte ne doit pas être confondue avec une preuve de remédiation.

Les flows historiques, lancés avant V3.7.2, restent visibles via l'API. Les erreurs API sont signalées explicitement; l'outil n'envoie aucune commande d'isolement et ne modifie pas les services.
