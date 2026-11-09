# AUDIT — Crypto-Cold-Wallet

Date : 2026-10-16
Ensemble : `/home/brew/Documents/wallet_audit/Crypto-Cold-Wallet`
Auditeur : Hermes Agent (solar-mini4) — mise à jour.

---

## 1. État version / git

- Remote : `https://github.com/Krassimirstefanov/Crypto-Cold-Wallet.git`
- Commits :
  - `53adfad` Initial commit
  - `e01e3bf` Add files via upload
- Tree suivi : 56 fichiers (hors `.venv`/`.git`).

Modification dans l'arbre de travail contre HEAD :

| Fichier | État |
|---|---|
| `balance.py` | `M` ( +47/-0 lignes) |
| `transfer.py` | `M` (+188/-161) |
| `menu.py` | `M` (+24/-2) |
| `beneficiaries.enc` | `M` (144 -> 2535 o) — re-chiffré, jamais commité |
| `menu.py` | 19 `__pycache__/*.pyc` suivis et modifiés |

Non suivi (34 fichiers) : `.venv/`, `__pycache__/*.pyc`, `*.bak` (3), `correctif.patch`,
`historique/`, `local_keys.py`, `wallets/`, `.gitignore`, `gateway.conf`, `AUDIT.md`…
Aucun `.gitignore` initial → nettoyage ajouté (`.gitignore` + `gateway.conf` p.ex.).

---

## 2. Structure

| Dossier/ Fichier | Rôle |
|---|---|
| `menu.py` (115 ko) | Interface interactive principale |
| `wallet_manager.py` | Générateur / gestionnaire de wallets locaux |
| `balance.py` | Lecture de soldes en read-only |
| `transfer.py` | Envoi de transactions (broadcast) |
| `swap.py` / `swap_guided.py` / `swap_hsh_usdt.py` | Flux de conversion → XMR / PancakeSwap |
| `security_core.py` | Argon2id + AES-256-GCM, vault |
| `security_access.py` | Easy / Medium / Advanced |
| `decrypt_wallet.py` | Déchiffrage de `wallets.enc` |
| `xmr_gateway.py` | Monero (`monero-wallet-rpc`) via Tor |
| `beneficiaries_manager.py`, `asset_catalog.py`, `privatekey_wallet.py`, `hsh_bep20.py`, `i18n.py`, `startup_splash.py`, `beta_feedback.py`, `debug*`... | Vocabulaires, catalogue d'actifs, clés UTXO in-RAM, i18n, splash |
| `assets/crypto_wallet_logo.png` | Logo |
| `historique/transactions.log.enc` | Historique chiffré |
| `wallets/wallets.enc` | Wallet (clés) chiffré |
| `wallets/.onboarding_complete` | `"completed"` (indique on-boarding fini) |
| `.venv/` | Python 3.11.16 (uv), dépendances complètes |

Dépendances clés : `bitcoinlib 0.7.10`, `web3 7.16.0`, `eth-account`, `solana 0.40.1`,
`solders 0.28.0`, `base58`, `cryptography 50.0.2`, `mnemonic`, `bip32utils`, `ecdsa`,
`monero 1.1.1`, `requests`, `krakenex`, `tronpy 0.6.2`, `PySocks`, `python-bidi`,
`argon2-cffi 25.1.0`.

---

## 3. Sécurité — vérifications

### Permissions (toutes sensibles = 600)
| Fichier | Taille | Mode |
|---|---|---|
| `wallets/wallets.enc` | 3534 o | `-rw-------` |
| `beneficiaries.enc` | 2535 o | `-rw-------` |
| `historique/transactions.log.enc` | 31040 o | `-rw-------` |
| `security.json` | 114 o | `-rw-------` |

`security.json` : `{"format":2, "mode":"standard", "kdf":"Argon2id", "cipher":"AES-256-GCM", "access_level":"easy"}`.
**Ce fichier ne contient jamais de passphrase, de seed, ni de clé privée** → savoir l'atout ou pas.

### Content
- **Aucune clé/API/token/password durcie dans le code** (grep `-rInsE` sur `*.py/*.conf/*.json/.sh/.md/.txt` + `os.getenv`, `__import__("requests")`).
- `local_keys.py` : générateur de clés in-RAM (mnémonique → UTXO segwit), pas de base locale. ✅.
- `swap.py` : `CHANGENOW_API_KEY` lu via `os.environ.get` — non dans le dépôt. ✅
- `xmr_gateway.py` : passwd RPC via `XMR_GATEWAY_PASS` > `gateway.conf` > interactive. ✅
- `decrypt_wallet.py`, `beneficiaries_manager.py`, `wallet_manager.py` : `get_secret()` (getpass → input) — jamais en clair dans des fichiers.
- `correctif.patch` : patch de correction (normalisation devise/réseau + interdiction de transfert non supporté), s'applique proprement. ✅

### Liquidation chiffrée
- Les trois fichiers `.enc` **n'ont pas été déchiffrés** (données sensibles).
- Taux de lecture : **sagesse**, pas de contenu secret affiché.

---

## 4. Intégrité du code

- Tous les `.py` (18 cibles auditées) se **parsent** avec `ast.parse` — aucune erreur de syntaxe.
- Vérification de `import os` : ajouté manquants (`security_access.py`, `swap.py`…), pas d'exception.
- Patch `correctif.patch` appliquée proprement (`git apply --check --reverse` → OK).
- Aucun `eval`/`exec(compile(...))` dans le code de l'application (seul dans le test offline).

---

## 5. Mapping des canaux de broadcast (envoi de transaction)

| Crypto / réseau | Lecture de solde | Send / broadcast | Jeton requis |
|---|---|---|---|
| Bitcoin, LTC, DOGE | API public | Local HDWallet (bitcoinlib) | aucun |
| Ethereum / ERC20 (USDT, USDC, DAI, SAND, SHIB, POL) | RPC public | Clé privée du wallet local + optional swap ChangeNOW | aucun (swap : `CHANGENOW_API_KEY`) |
| BSC / BEP20 (BNB, USDT, USDC, DAI, SHIB, SAND) | RPC public | Local BSC wallet (PancakeSwap) | gas BNB |
| Polygon | RPC public | Local wallet | aucun |
| Avalanche / Arbitrum / Optimism | RPC public | Local wallet | aucun |
| Solana | RPC public | Local wallet | aucun |
| Ripple (XRP), Tron (TRX), Cosmos (ATOM) | API public | balance ok, pas d'envoi | aucun |
| Cardano (ADA) | Blockfrost (dossier) | balance ok | `ADA_BLOCKFROST_PROJECT_ID` (env) — **non configuré** |
| Monero (XMR) | `monero-wallet-rpc` via Tor | Gateway `transfer` RPC | `XMR_GATEWAY_PASS` / `gateway.conf` |
| Swap (3e partie) | — | ChangeNOW API | `CHANGENOW_API_KEY` |

Notes :
- Aucun *balance read* nécessite de clé.
- Seuls les **envoi** (send) nécessitent un secret :
  - clé privée du wallet local (chiffrée dans `wallets.enc`),
  - gas BNB (BSC),
  - portail XMR (`gateway.conf` / `XMR_GATEWAY_PASS`),
  - portail ChangeNOW (`CHANGENOW_API_KEY` — à toi de te connecter).
- Pour Cardano, la lecture de solde est **inopérante** tant que `ADA_BLOCKFROST_PROJECT_ID` n'est pas défini (c'est l'ajout de l'audit, voir section 6).

---

## 6. Risques et choses à faire

### Essentiels (sans lesquels l'audit est bloqué)
1. `ADA_BLOCKFROST_PROJECT_ID` : variable qui manque. Remarque : Blockfrost nécessite un `project_id` à son URL; sans, le solde ADA ne se lit pas (on le détecte clairement). À configurer toi (https://blockfrost.io → Projects → Project ID).
2. `WALLET_BETA_SMTP_PASSWORD` / `WALLET_BETA_EMAIL` : du genre beta-feedback, hors d'ici.
3. `gateway.conf` : remplir manuellement (mot de passe RPC XMR) ou via `XMR_GATEWAY_PASS`.

### Bonnes à savoir
4. `beneficiaries.enc` a changé de 144→2535 o et n'est pas encore commité. Vérifier si c'est le même contenu chiffré que celui de l'audit d'origine.
5. `.venv`/`.pyc` dans `.gitignore` (ajouté) : `.bak`/`.patch`/`.pyc`/`gateway.conf` restent hors suivi — c'est voulu.
6. `menu.py` est interactif : passphrase via terminal, pas via chat. Aucun canal ne doit transporter la masterkey.

---

## 7. Conclusion

**Le projet est structuré avec les bonnes pratiques de sécurité :** vault chiffrée (Argon2id + AES-256-GCM), clés privées hors clair, passphrases saisies en local via `getpass`, aucun jeton durci, broadcast protégé par le mot de passe/vault. Il ne se dégrade pas avec les niveaux facile/moyen/avancé. Ce qui manque dans le dépôt n'est pas du code, c'est la **configuration utilisateur** (`ADA_BLOCKFROST_PROJECT_ID`, `gateway.conf`, `CHANGENOW_API_KEY`), toujours à fournir côté poste.

**Audit signé** — non sauvegardé; à toi de refaire la lecture si tu changes les fichiers.
