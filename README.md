# Crypto Cold Wallet

Local, non-custodial cryptocurrency wallet manager by Красимир.

## Security first

Your masterkey, seeds, private keys and wallet passphrases are never sent to the developer. Keep every credential offline. If a credential is lost, funds cannot be recovered.

Sensitive data is encrypted at rest (`KCW2` vault format using **Argon2id + AES-256-GCM**) with strict `0600` file permissions: wallets, beneficiaries and transaction history are stored separately from the application code, and decrypted secrets are wiped from memory (`bytearray` zeroing) immediately after use.

## Supported platforms

Linux (Ubuntu, Debian, Kali, Mint), WSL, macOS with Homebrew, and Termux where the required Python version is available.

## Installation

1. Extract the project archive.
2. Open a terminal in the project directory.
3. Install the environment and dependencies:

```bash
sh install.sh
```

The installer creates a local `.venv` environment and may require Internet access to download packages.

### Termux / Android

Install Termux from F-Droid or the official project (avoid unofficial APKs), then run:

```bash
pkg update
pkg install python clang make openssl libffi rust
termux-setup-storage   # optional, only if you need shared storage
cd /path/to/Crypto-Cold-Wallet-v2
sh install.sh
```

Launch it in the terminal with `python3 menu.py`. Android/Termux normally has no Tk graphical display, so the wallet automatically uses its text interface. Keep the phone protected with a screen lock and do not place the wallet directory in shared storage.

## Launch

```bash
python3 menu.py
```

On first launch, choose the interface language, then Easy, Medium or Advanced security. The language is saved and can be changed later without an additional password.

## Security levels

- **Easy**: masterkey required at opening.
- **Medium**: masterkey plus a secondary password for transfers, history, wallet export and beneficiaries.
- **Advanced**: Medium protections plus a unique 25-word passphrase for every wallet. Five random words protect balance consultation; all 25 words are required to reveal secrets or sign a transaction.

## Features & Monero (XMR) end-to-end support

- **Multi-chain local wallets**: Bitcoin (BTC), Ethereum (ETH), Solana (SOL), Litecoin (LTC), Dogecoin (DOGE), BNB Smart Chain (BNB & BEP-20 tokens including HSH), Polygon (POL), Avalanche (AVAX), Arbitrum, Optimism, ERC-20 tokens (USDT, USDC, DAI, SHIB, SAND), XRP, Tron (TRX), Cosmos (ATOM), Cardano (ADA) and **Monero (XMR)**.
- **Monero (XMR, 12 decimals) integration**:
  - **100% offline wallet creation & import**: generate a new 25-word Monero seed (with CRC32 checksum word and Ed25519 spend/view keys), import an existing 25-word seed, or import private `spend` & `view` keys directly.
  - **Cryptographic address validation**: Monero block-based Base58 decoding (11 chars $\rightarrow$ 8 bytes) and 4-byte **Keccak-256** checksum verification for standard (`4...`), subaddress (`8...`) and integrated (106-character) addresses.
  - **Balance & Transfers over Tor**: query both **total** and **unlocked** (`unlocked_balance`) XMR balances and broadcast standard transfers or **Max Send (`sweep_all`)** via `xmr_gateway.py` routed exclusively through Tor (`socks5h://127.0.0.1:9050`).
- **Strict address & network validation**: EIP-55 checksum verification on EVM chains, Base58Check / Bech32 / Bech32m checksum verification on BTC/LTC/DOGE, strict network/chain-ID separation, exact token approvals (no unlimited `MAX_UINT256` approvals) and slippage bounds on swaps.

## Unit tests

Run the offline unit test suite (19 tests covering asset catalog, Monero address validation, seed/key import, Tor gateway balance & `sweep_all`, beneficiary selection, `0600` file permissions, `Advanced` 25-word passphrases, memory wiping and Beta secret leak protection):

```bash
python3 -B -m unittest discover -v
```

## Debug reports & Beta feedback

Debug checks `0600` permissions on all sensitive files and creates a report ID containing zero sensitive data. Beta feedback includes an automatic secret-leak filter (`contains_potential_secret`) that blocks accidental submission of private keys, WIF keys or 24/25-word mnemonics.

## Updates

The Update section is currently a placeholder. No files are moved or overwritten until a secure deployment method is implemented.

## Disclaimer

This is experimental software. Use only test funds until you have independently audited the code and backups. You are solely responsible for your credentials and transactions.
