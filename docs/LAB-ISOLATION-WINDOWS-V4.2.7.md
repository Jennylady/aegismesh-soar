# AEGISMESH-SOAR 4.2.7 — Test d'isolation réelle Windows LAB par script

Ce mode est **réel**, distinct des décisions autonomes : il ne crée ni incident, ni preuve, ni score IA inventés. Il modifie temporairement l'état de quarantaine du poste `WIN-LAB-01` (`001`, `C.3c9cde1e0b930676`) via l'API mTLS Velociraptor existante.

**Portée stricte :** jamais `006` (contrôleur AD), `002`, manager, autre client ; jamais d'activation permanente d'`ENABLE_EDR_ISOLATION`. Les autres machines restent inchangées. Un accès console de secours indépendant du réseau est indispensable car l'isolation peut interrompre LDAP/RDP/WireGuard.

Le moniteur Velociraptor doit déjà être présent. Le script crée un bail SOAR **avant** de poser le label. `aegismesh-soar-edr-expiry.timer`, déjà actif, retire ce label après **180 secondes**, à son prochain passage ; un agent hors ligne peut retarder l'application du désisolement au poste. Une vraie restauration réseau doit donc être vérifiée sur l'endpoint.

## Sur le serveur GCP (après publication Git et `aegismesh-soar update`)

```bash
aegismesh-soar edr lab-quarantine start --agent-id 001 --confirm --console-access
# Attendre que le label soit visible et constater l'effet réseau depuis le Windows LAB
aegismesh-soar edr lab-quarantine status --agent-id 001
# Examiner les journaux client Velociraptor du moniteur, lecture seule
aegismesh-soar edr lab-quarantine logs --agent-id 001
# Retrait immédiat de secours (uniquement d'un bail créé par cette commande)
aegismesh-soar edr lab-quarantine release --agent-id 001 --confirm
```

## Sur Windows LAB — script PowerShell administrateur pendant le test

```powershell
$DC='10.77.77.34'
1..70 | ForEach-Object {
    $connected=Test-NetConnection -ComputerName $DC -Port 389 -InformationLevel Quiet -WarningAction SilentlyContinue
    $ipsec=((netsh ipsec static show policy all) -join "`n") -match 'VelociraptorQuarantine'
    [pscustomobject]@{ Horodatage=(Get-Date).ToString('o'); LDAP=$connected; IPsecPolicyDetectee=$ipsec } |
      ConvertTo-Json -Compress
    Start-Sleep 3
}
```

Avant : `LDAP=true`. Pendant : `LDAP=false` **si la quarantaine réseau est réellement effective** ; le moniteur IPsec doit également montrer une politique. Après : `LDAP=true`. Les deux changements ne sont **pas garantis** par la simple présence du label.

## Sécurité et limites

- Refuse si le label `Quarantine` est préexistant, si un bail SOAR est actif, si le timer est inactif ou si l'identité Wazuh/Velociraptor diverge.
- Conserve le mécanisme original de retrait à échéance, sans ajouter de suppression manuelle de politiques Windows ni ouvrir le canal réseau.
- Si `Quarantine` est présent mais LDAP reste accessible, vérifier la stratégie IPsec du domaine et les événements `Windows.Remediation.QuarantineMonitor`. Ne pas annoncer une isolation réussie.
- Les journaux de monitoring peuvent être vides tant que les événements ne sont pas arrivés ; cet état n'est pas un succès prouvé.

Un script PowerShell en lecture seule est fourni :
`ops/wazuh/windows/Watch-AegisMeshIsolation.ps1`. Il est réservé à `WIN-LAB-01`,
collecte au format CSV les variations de LDAP et la présence d'une politique IPsec,
et refuse de tourner sur le contrôleur AD. Le script ne remplace pas la preuve
indépendante du client Velociraptor.
