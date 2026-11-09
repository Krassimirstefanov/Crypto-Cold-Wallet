#!/usr/bin/env python3
"""
decrypt_wallet.py — Déchiffre et affiche le contenu d'un fichier wallets.enc

Usage :
    python decrypt_wallet.py
    python decrypt_wallet.py --file /chemin/vers/wallets.enc
"""

import argparse
import json
import os
import sys
from pathlib import Path
from getpass import getpass as _getpass

def get_secret(prompt: str) -> str:
    """Lit un secret sans l'afficher (getpass en TTY, input sinon)."""
    try:
        return _getpass(prompt)
    except (EOFError, OSError):
        return input(prompt)

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def decrypt_file(filepath: Path, passphrase: str) -> dict:
    raw = filepath.read_bytes()
    salt = raw[:16]
    token = raw[16:]
    key = derive_key(passphrase, salt)
    fernet = Fernet(key)
    payload = fernet.decrypt(token)
    return json.loads(payload.decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Déchiffre un fichier wallets.enc")
    parser.add_argument(
        "--file", "-f",
        default=Path(__file__).parent / "wallets" / "wallets.enc",
        help="Chemin vers le fichier wallets.enc (défaut : ./wallets/wallets.enc)",
    )
    parser.add_argument(
        "--reveal", "-r", action="store_true",
        help="Affiche les clés privées/mnémoniques en clair (sinon masquées)",
    )
    args = parser.parse_args()

    filepath = Path(args.file)

    if not filepath.exists():
        print(f"[!] Fichier introuvable : {filepath}", file=sys.stderr)
        sys.exit(1)

    passphrase = get_secret("🔑 Phrase de passe : ")
    try:
        data = decrypt_file(filepath, passphrase)
    except Exception:
        print("[!] Phrase de passe incorrecte ou fichier corrompu.", file=sys.stderr)
        sys.exit(1)

    SENSITIVE = {
        "private_key_wif", "mnemonic", "private_key_hex",
        "private_key_base58", "private_key_bytes_hex",
    }
    if args.reveal:
        print("\n✅ Contenu déchiffré :\n")
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print("\n✅ Contenu déchiffré (clés masquées — utilisez --reveal pour les voir) :\n")
        masked = {}
        for label, info in data.items():
            if isinstance(info, dict):
                masked[label] = {
                    k: ("•••••••• (masqué)" if k in SENSITIVE else v)
                    for k, v in info.items()
                }
            else:
                masked[label] = info
        print(json.dumps(masked, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
