# AUDIT — Crypto-Cold-Wallet v2

Date : 2026-11-15
Ensemble : `/home/krassimir/Desktop/Crypto-Cold-Wallet-v2`
Statut : **Audit de sécurité complet & intégration Monero (XMR) de bout en bout validés (19/19 tests unitaires OK)**

---

## 1. État du dépôt & Hygiène Git

- Remote : `https://github.com/Krassimirstefanov/Crypto-Cold-Wallet.git`
- Fichier `.gitignore` durci : exclusion stricte de tous les fichiers sensibles et d'exécution (`*.enc`, `*.salt.bin`, `security.json`, `gateway.conf`, `beta_email.conf`, `lang.txt`, `.env`, `tor_data/`, `pyvenv/`, `.venv/`, `venv/`, `__pycache__/`, `*.py[cod]`, `*.nmap`, `*.gnmap`, `*.xml`, `*.save`, `*.bak`, `*.patch`, `wallets/*`, `historique/*` avec préservation de `!wallets/.gitkeep` et `!historique/.gitkeep`).
- Aucun fichier `.enc`, `.conf`, `.save` ni cache Python n'est suivi par Git.

---

## 2. Intégration complète de Monero (XMR) de bout en bout

| Composant | Fonctionnalité implémentée |
|---|---|
| `asset_catalog.py` | Entrée `"xmr"` (`asset: "XMR"`, `network: "monero"`, `decimals: 12`, `broadcast: True`). |
| `local_keys.py` & `wallet_manager.py` | Génération et import **100 % hors-ligne** en pur Python (multiplication scalaire Ed25519, dérivation Keccak-256 `view_key = Keccak256(spend_key) mod l`, encodage/décodage de la seed Monero de **25 mots** avec vérification du 25e mot de checksum CRC32) ou import direct par clés privées (`spend_key` + `view_key`). |
| `xmr_gateway.py` & `transfer.py` | Validation cryptographique stricte des adresses Monero (`is_valid_xmr_address` / `_validate_xmr_address`) : décodage **Base58 Monero par blocs** (11 caractères $\rightarrow$ 8 octets), vérification de la longueur décodée (69 octets pour adresse standard `0x12` ou sous-adresse `0x2a`, 77 octets pour adresse intégrée `0x13`) et vérification des **4 derniers octets de checksum Keccak-256** (padding pré-NIST `0x01`). |
| `xmr_gateway.py`, `balance.py` & `menu.py` | Consultation du solde **total** et **débloqué** (`unlocked_balance`, 12 décimales) via `get_wallet_balance_xmr()` routé exclusivement à travers Tor (`socks5h://127.0.0.1:9050`, résolution DNS distante et vérification obligatoire du suffixe `.onion`). |
| `transfer.py`, `xmr_gateway.py` & `menu.py` | Envoi standard (`transfer`) et envoi intégral du solde débloqué (`sweep_all` / Max Send lorsque `amount == 0` ou `max`), restauration éphémère par seed 25 mots ou par clés `spend`/`view` (`generate_from_keys`), fermeture immédiate du wallet distant (`close_wallet`) et journalisation chiffrée (`RESEAU=XMR`). |
| `beneficiaries_manager.py` & `menu.py` | Ajout, validation et sélection de bénéficiaires Monero (`XMR` / `MONERO` sur réseau `monero` / `xmr`). |
| `privatekey_wallet.py` | Ajout de `scan_monero` (`--xmr`) pour scanner le solde total et débloqué d'une seed 25 mots ou d'une `spend_key` via Tor. |

---

## 3. Correctifs d'audit de sécurité appliqués

### 3.1 Validation cryptographique des adresses multi-chaînes avant signature
- **EVM (Ethereum, BSC, Polygon, Avalanche, Arbitrum, Optimism, ERC-20 / BEP-20)** : vérification stricte du checksum **EIP-55** (`Web3.is_checksum_address`) lorsqu'une adresse contient des majuscules/minuscules mixtes, et rejet de l'adresse nulle `0x0000...0000` (`transfer.py`, `hsh_bep20.py`, `swap_hsh_usdt.py`).
- **Bitcoin, Litecoin, Dogecoin** : vérification complète du **checksum Base58Check** (double SHA-256) pour les adresses legacy/P2SH et du **checksum Bech32 / Bech32m** (polymod BIP-173 / BIP-350) pour les adresses SegWit `bc1` / `ltc1`.
- **Monero (XMR)** : décodage Base58 par blocs + vérification du checksum **Keccak-256** sur 4 octets (`xmr_gateway.is_valid_xmr_address`).
- **Solana, Tron, XRP, Cosmos, Cardano** : vérification de décodage Base58 / Base58Check / Bech32 complet avant tout envoi ou enregistrement de bénéficiaire (`menu.py`, `transfer.py`, `swap.py`, `swap_guided.py`).

### 3.2 Séparation stricte des réseaux, frais, Max Send et swaps
- **Séparation des chaînes et jetons** : vérification stricte du couple `(asset_id, network, chain_id)` dans `asset_catalog.py`, `transfer.py`, `menu.py` et `hsh_bep20.py` (`chain_id == 56` exigé sur BSC, `chain_id == 1` sur Ethereum) pour empêcher tout envoi croisé BEP-20 $\leftrightarrow$ ERC-20.
- **Calcul des frais et Max Send** : utilisation de `Decimal` pour la conversion des montants vers les unités atomiques, récupération dynamique du `nonce` `"pending"` sur EVM (prévention de la double dépense), mode `sweep_all` pour Monero et soustraction des frais estimés lors d'un envoi maximum.
- **Sécurité des swaps (`swap.py`, `swap_guided.py`, `swap_hsh_usdt.py`)** :
  - Suppression des approbations illimitées (`MAX_UINT256`) au profit d'un `approve(spender, amount_in_wei)` limité au montant exact du swap.
  - Encadrement strict du slippage (`0.1 %` à `5.0 %` maximum) et calcul de `amountOutMin` via `getAmountsOut`.
  - Validation HTTPS/TLS ou `.onion` via Tor sur tous les endpoints RPC et API externes.

### 3.3 Permissions atomiques `0600` et niveaux d'accès (`Easy` / `Medium` / `Advanced`)
- **Permissions `0600`** : `security_core.atomic_write` et `ensure_secure_permissions` appliquent systématiquement `chmod 0600` sur `wallets/wallets.enc`, `beneficiaries.enc`, `historique/transactions.log.enc`, `security.json`, `security_access.enc` et `gateway.conf`.
- **Compatibilité `KCW2` & contrôle d'accès** : `decrypt_wallet.py`, `balance.py` et `wallet_manager.py` supportent le format `KCW2` (`Argon2id + AES-256-GCM`) et imposent l'authentification secondaire (`Medium`) ainsi que la passphrase de **25 mots** par wallet (`Advanced`, avec défi aléatoire de 5 mots pour la lecture des soldes et 25 mots pour la révélation/signature).

### 3.4 Effacement mémoire (`bytearray`) et prévention des fuites (Tor & Beta)
- **Effacement mémoire** : toutes les fonctions manipulant des secrets (`security_core.py`, `security_access.py`, `transfer.py`, `wallet_manager.py`, `decrypt_wallet.py`, `balance.py`, `privatekey_wallet.py`, `swap.py`, `swap_hsh_usdt.py`, `hsh_bep20.py`, `menu.py`) écrasent les clés privées, seeds et passphrases via des `bytearray` remis à zéro dans des blocs `finally:` suivis de `gc.collect()`.
- **Absence de fuite DNS/IP hors Tor** : dès que Tor est actif ou configuré dans `gateway.conf`, les requêtes HTTP/JSON-RPC (`xmr_gateway.py`, `balance.py`, `menu.py`, `privatekey_wallet.py`) utilisent `socks5h://127.0.0.1:9050` (résolution DNS côté proxy Tor).
- **Filtre anti-fuite de secrets (`beta_feedback.py` & `menu_debug`)** : `contains_potential_secret()` bloque tout envoi contenant une clé privée hexadécimale (64 hex), une clé WIF, une phrase mnémonique de 24/25 mots, une passphrase de wallet à 25 mots ou un en-tête `KCW2`.

---

## 4. Suite de tests unitaires

Exécution hors-ligne complète avec `python3 -B -m unittest discover -v` :

- `test_asset_catalog.py` (`MoneroAndSecurityTests`) :
  - `test_xmr_address_validation_keccak_checksum` (adresses standard `4...`, sous-adresses `8...`, adresses intégrées 106 caractères et rejet des adresses altérées)
  - `test_xmr_wallet_import_seed_and_keys` (génération et restauration offline par seed 25 mots et par clés `spend`/`view`)
  - `test_xmr_gateway_balance_and_sweep_all_via_tor` (vérification du proxy `socks5h://127.0.0.1:9050`, lecture `total`/`unlocked` 12 décimales et `sweep_all`)
  - `test_transfer_validate_xmr_address_integration` (intégration dans `transfer.py`)
  - `test_security_permissions_and_levels_and_memory_wipe` (`chmod 0600`, mode `Advanced` 25 mots et effacement mémoire)
  - `test_beta_feedback_blocks_secrets` (détection et blocage de clés privées/passphrases dans les retours Beta)
- `test_beneficiaire_selection.py` (`SelectionTests`) : 8 tests de sélection de bénéficiaires, normalisation des devises (incluant `XMR`/`MONERO`) et séparation stricte actif/réseau.
- `test_ltc_balance_offline.py` (`LtcAndXmrBalanceOfflineTests`) : 5 tests hors-ligne de lecture de solde LTC (repli Blockchair $\rightarrow$ BlockCypher) et XMR (`total` + `unlocked_balance`).

**Résultat : 19 tests exécutés — 19 OK (0 échec, 0 erreur).**
