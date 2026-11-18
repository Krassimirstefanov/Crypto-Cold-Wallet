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

import security_core as _sec
import security_access as _access


SENSITIVE = {
    "private_key_wif", "mnemonic", "private_key_hex",
    "private_key_base58", "private_key_bytes_hex",
    "private_spend_key", "private_view_key", "seed",
    "protected_secrets", "word_challenge",
}


def _wipe_secrets(obj) -> None:
    """Efface récursivement en mémoire les valeurs sensibles déchiffrées."""
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            val = obj.get(k)
            if isinstance(val, dict):
                _wipe_secrets(val)
            elif k in SENSITIVE or "private" in str(k).lower() or "secret" in str(k).lower():
                if isinstance(val, str):
                    buf = bytearray(val.encode("utf-8"))
                    for i in range(len(buf)):
                        buf[i] = 0
                obj[k] = ""


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
    if _sec.is_secure_blob(raw):
        obj = _sec.decrypt_json(raw, passphrase)
        if not isinstance(obj, dict):
            raise ValueError("Format de coffre invalide")
        return obj
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
    data = {}
    output_obj = {}
    try:
        try:
            data = decrypt_file(filepath, passphrase)
        except Exception:
            print("[!] Phrase de passe incorrecte ou fichier corrompu.", file=sys.stderr)
            sys.exit(1)

        reveal = bool(args.reveal)
        secondary_cred = None
        if reveal:
            level = _access.get_access_level()
            if level in {"medium", "advanced"}:
                secondary_cred = _access.get_verified_secondary(passphrase)
                if secondary_cred is None:
                    sys.exit(1)

        for label, info in data.items():
            if not isinstance(info, dict):
                output_obj[label] = info
                continue
            w = dict(info)
            if reveal:
                if w.get("protected_secrets"):
                    cred = _access.ask_wallet_credential(
                        w,
                        f"revealing the keys of {label}",
                        secondary_password=secondary_cred if w.get("secret_protection") == "secondary" else None,
                    )
                    if not cred:
                        for k in list(w.keys()):
                            if k in SENSITIVE:
                                w[k] = "•••••••• (masqué)"
                    else:
                        unlocked = _access.unlock_wallet_secrets(w, cred)
                        del cred
                        w.update(unlocked)
                        unlocked.clear()
                        w.pop("protected_secrets", None)
                        w.pop("word_challenge", None)
                elif _access.get_access_level() != "easy" and any(k in w for k in SENSITIVE):
                    for k in list(w.keys()):
                        if k in SENSITIVE:
                            w[k] = "•••••••• (masqué — non compartimenté)"
            else:
                for k in list(w.keys()):
                    if k in SENSITIVE:
                        w[k] = "•••••••• (masqué)"
            output_obj[label] = w

        if secondary_cred:
            del secondary_cred

        if reveal:
            print("\n✅ Contenu déchiffré :\n")
        else:
            print("\n✅ Contenu déchiffré (clés masquées — utilisez --reveal pour les voir) :\n")
        print(json.dumps(output_obj, indent=2, ensure_ascii=False))
    finally:
        _wipe_secrets(output_obj)
        _wipe_secrets(data)
        output_obj.clear()
        data.clear()
        del passphrase


if __name__ == "__main__":
    main()
