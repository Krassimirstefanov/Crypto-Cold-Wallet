# Protection des données privées

Le coffre protège les données au repos sans chiffrer arbitrairement le code de l'application.

- `wallets/wallets.enc` contient les portefeuilles et les métadonnées chiffrés avec la masterkey.
- `beneficiaries.enc` contient les bénéficiaires chiffrés avec la masterkey.
- `historique/transactions.log.enc` contient l'historique chiffré avec la masterkey.
- En mode Medium, les opérations sensibles demandent aussi le mot de passe secondaire.
- En mode Advanced, les secrets de chaque portefeuille sont compartimentés par une passphrase de 25 mots.
- Les fichiers temporaires en clair sont supprimés après migration; les secrets ne sont déchiffrés qu'en mémoire pour l'opération demandée.

La masterkey, le mot de passe secondaire et les passphrases ne sont jamais enregistrés en clair. La protection contre un vol de dossier suppose également que les mots de passe ne soient pas stockés avec ce dossier et que l'ordinateur soit correctement protégé.
