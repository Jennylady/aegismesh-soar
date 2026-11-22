# V3.7.1 — Raccordement Velociraptor Docker (sans chemins à deviner)

La sortie GCP du 22 novembre montre un conteneur nommé `aegismesh-velociraptor`, mais aucune configuration API mTLS SOAR. Les erreurs « mode doit être host ou docker », « agent sans correspondance Velociraptor » sont consécutives à ce prérequis absent. La mise à jour de code ne remplace pas l'émission d'une identité API par le serveur EDR.

## Procédure sur GCP

```bash
aegismesh-soar update
aegismesh-soar edr doctor
```

Cette sonde ne change rien. Elle affiche le binaire trouvé, le chemin du serveur Velociraptor, le nombre de configurations API candidates et un volume inscriptible persistant. Elle ne lit pas les données privées du YAML.

Si l'instance possède déjà une clé API utilisable :

```bash
aegismesh-soar edr setup --confirm
```

Les commandes d'information et d'inventaire sont **réellement** exécutées avant d'enregistrer `/etc/aegismesh-soar/velociraptor.json` (mode 0600).

S'il n'y a pas encore de clé API et **uniquement après avoir vérifié l'impact du redémarrage EDR** :

```bash
aegismesh-soar edr bootstrap --confirm --allow-restart
```

Le bootstrap :

1. Exige un unique conteneur Velociraptor actif, son binaire et son fichier de configuration serveur préexistant.
2. Refuse d'émettre une clé dans une couche Docker éphémère ; exige un volume bind/volume en lecture-écriture et évite d'écraser une clé existante.
3. Exécute `velociraptor --config <serveur> config api_client --name AEGISMESH_SOAR_API --role api <volume>/aegismesh-soar-api-client.yaml` sous `umask 077`.
4. Ajoute les rôles `api,investigator` via `acl grant` pour permettre les collectes ; l'API dispose de droits élevés et doit être protégée. Aucun rôle `administrator` n'est émis.
5. Redémarre **seulement** le conteneur Velociraptor existant, car les ACL modifiées par la CLI nécessitent le rechargement du service. Ceci peut momentanément interrompre les investigations EDR; ne l'utiliser que lorsque cette interruption est acceptable.
6. Vérifie l'API mTLS et les droits de lecture du parc avant de sauvegarder le raccordement. Ne révèle jamais le certificat ni la clé privée dans les logs.

Cette opération n'installe ni Velociraptor, ni agents et ne modifie pas Wazuh, Shuffle ou Fail2ban. Si la configuration n'est pas reconnue, ou que Docker n'a pas de volume en lecture-écriture, le bootstrap s'arrête sans générer de nouveaux certificats.

Après une liaison réussie :

```bash
aegismesh-soar edr clients
aegismesh-soar edr link-auto
aegismesh-soar edr status
aegismesh-soar orchestrate status
```

`link-auto` n'associe que des noms d'hôtes uniques. Kali peut être nommé `offensive` dans l'OS alors que Wazuh l'appelle `kali-ikom` ; il faut alors vérifier le couple via `edr clients`, sans inventer le client ID.

## Politique de sécurité

- Ne pas exposer la configuration mTLS, ni la copier dans GitHub, un ZIP ou une capture d'écran.
- Le rôle `investigator` est puissant (collecte d'artefacts) : protéger les fichiers du volume Docker et maintenir Velociraptor à une version corrigée selon les avis de sécurité.
- Les actions d'isolement `EDR_ISOLATE` restent désactivées par défaut; le DC `006` est exclu de la quarantaine générale.
- La correspondance agent ↔ EDR, la mise en place du timer de retrait et les autorisations d'isolement sont des étapes séparées. Un label `Quarantine` n'est pas une preuve de confinement réseau.
- Si le certificat est créé mais que la validation échoue, ne pas répéter `bootstrap` : diagnostiquer la configuration et les ACL existantes, puis exécuter `edr setup --confirm`.
