# Crypto Cold Wallet

Local, non-custodial cryptocurrency wallet manager by Красимир.

## Security first

Your masterkey, seeds, private keys and wallet passphrases are never sent to the developer. Keep every credential offline. If a credential is lost, funds cannot be recovered.

Sensitive data is encrypted at rest: wallets, beneficiaries and transaction history are stored separately from the application code.

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
cd /path/to/Crypto-Cold-Wallet-security-v1.4
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
- **Medium**: masterkey plus a secondary password for transfers, history and beneficiaries.
- **Advanced**: Medium protections plus a unique 25-word passphrase for every wallet. Five random words protect balance consultation; all 25 words are required to reveal secrets or sign.

## Features

Create wallets, view balances, transfer funds, inspect encrypted history, use the read-only converter, manage beneficiaries, configure Tor/Web networking, generate debug reports, and access the update placeholder.

The converter currently estimates values; it does not broadcast a swap automatically. Always verify the asset and network before real transactions.

## Debug reports

Debug creates a report ID and a technical report for manual support requests. Never include passwords, seeds, private keys, addresses or balances. Automatic e-mail delivery is not configured yet.

## Updates

The Update section is currently a placeholder. No files are moved or overwritten until a secure deployment method is implemented.

## Disclaimer

This is experimental software. Use only test funds until you have independently audited the code and backups. You are solely responsible for your credentials and transactions.
