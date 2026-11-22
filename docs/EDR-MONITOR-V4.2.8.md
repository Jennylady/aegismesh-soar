# AEGISMESH-SOAR V4.2.8 — Attribution EDR Velociraptor automatisée

La V4.2.7 refuse à juste titre le déclenchement lorsque `Windows.Remediation.QuarantineMonitor` figure dans la configuration de surveillance, mais ne s'applique pas au groupe `Quarantine` ou global. Cette version ajoute un diagnostic d'affectation exact et la possibilité d'ajouter le moniteur au groupe concerné avec l'API Velociraptor authentifiée mTLS.

Préconditions : `WIN-LAB-01`, agent Wazuh `001`, client EDR `C.3c9cde1e0b930676`; Wazuh actif et identité vérifiée; timer de retrait EDR actif; aucune quarantaine/bail existant; rôle de l'API Velociraptor possédant `COLLECT_CLIENT`. Ne jamais accorder silencieusement des permissions supplémentaires, et ne jamais toucher au contrôleur de domaine `006`.

```bash
# Après mise à jour par GitHub -> aegismesh-soar update :
aegismesh-soar edr lab-quarantine monitor-status --agent-id 001
# Si non configuré : affectation ciblée (n'isole personne) :
aegismesh-soar edr lab-quarantine monitor-ensure --agent-id 001 --confirm
# Puis vérification de l'attribution au groupe Quarantine :
aegismesh-soar edr lab-quarantine monitor-status --agent-id 001
# Une console indépendante du réseau est indispensable pour la suite :
aegismesh-soar edr lab-quarantine start --agent-id 001 --confirm --console-access
# Lire le label/bail et les journaux des événements :
aegismesh-soar edr lab-quarantine status --agent-id 001
aegismesh-soar edr lab-quarantine logs --agent-id 001
# Libération de secours, en cas de bail créé par la commande :
aegismesh-soar edr lab-quarantine release --agent-id 001 --confirm
```

Sur WIN-LAB-01, confirmer le filtrage réel pendant la quarantaine : LDAP sur `10.77.77.34:389` auparavant disponible devient injoignable, puis redevient joignable après libération ; la présence d'une politique IPsec et les journaux de l'artefact sont nécessaires pour en attribuer la cause. Le simple label ne prouve rien. Le bail de laboratoire demeure de 180 secondes, avec désisolement prévu par le timer SOAR. Le client EDR peut être hors ligne et la restauration effective retardée : conserver un accès console indépendant du réseau.

La commande `monitor-ensure` n'effectue que l'affectation globale **du groupe de label `Quarantine`** par `add_client_monitoring`. Elle ne pose pas le label sur un client ; elle n'active pas `ENABLE_EDR_ISOLATION`, ne modifie ni les autres règles d'événements ni les services Windows. Si l'API refuse `COLLECT_CLIENT`, la commande échoue proprement sans action réseau et sans élévation automatique des permissions.
