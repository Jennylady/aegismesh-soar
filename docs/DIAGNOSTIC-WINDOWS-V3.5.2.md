# Diagnostic Windows 001 (V3.5.2)

1. Sur Kali, appliquer le ZIP à la racine du dépôt, exécuter `python3 bin/aegismesh-soar test`, puis commit/push. Ne pas extraire le ZIP sur GCP.
2. Sur GCP, `aegismesh-soar update`, puis `aegismesh-soar fleet evidence diagnose --agent-id 001 --decision-id am-7cb8f4e2c76e13cda871c0fa`.
3. Sur Windows LAB 001, récupérer les fichiers `ops/wazuh/windows` du **même commit**, installer ou mettre à jour via `Install-AegisMeshProof.ps1 -EnableCollection` si nécessaire, puis lancer `Diagnose-AegisMeshProof.ps1 -DecisionId am-7cb8f4e2c76e13cda871c0fa`.
4. La preuve locale manque et le journal d’erreurs en contient : problème d’exécution. Examiner la catégorie d’erreur et le journal ossec.log.
5. La preuve locale existe mais GCP ne la voit pas : vérifier la configuration `localfile`, le statut `WazuhSvc`, puis les archives/alertes du manager.
6. Sans preuve locale, ne jamais marquer une action comme exécutée. Ne pas déclencher de nouvelles réponses sur le contrôleur de domaine uniquement pour le diagnostic.

Le script Diagnose est en lecture seule. Ne pas transmettre les jetons privés ni les mots de passe.
