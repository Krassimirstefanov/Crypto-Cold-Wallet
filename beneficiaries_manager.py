#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Encrypted beneficiaries store for Crypto Cold Wallet.

No beneficiary is stored in plaintext. The active file is beneficiaries.enc
using the same Argon2id + AES-256-GCM vault format as wallets.enc.
Legacy Fernet beneficiaries.enc files are accepted for migration.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import security_core as sec

BASE = Path(__file__).resolve().parent
BENEFICIARIES_FILE = BASE / "beneficiaries.enc"
LEGACY_SALT_FILE = BASE / "beneficiaries.salt.bin"


class BeneficiaryAuthError(ValueError):
    pass


def _legacy_derive(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _legacy_decrypt(raw: bytes, passphrase: str):
    # v1 encoded salt directly at the start of the ciphertext.
    salt = raw[:16]
    token = raw[16:]
    key = _legacy_derive(passphrase, salt)
    payload = Fernet(key).decrypt(token)
    return json.loads(payload.decode("utf-8"))


def load_beneficiaries(passphrase: str) -> dict:
    if not BENEFICIARIES_FILE.exists():
        return {}
    raw = BENEFICIARIES_FILE.read_bytes()
    try:
        if sec.is_secure_blob(raw):
            data = sec.decrypt_json(raw, passphrase)
        else:
            data = _legacy_decrypt(raw, passphrase)
        if not isinstance(data, dict):
            raise BeneficiaryAuthError("Format bénéficiaires invalide.")
        return data
    except BeneficiaryAuthError:
        raise
    except Exception as exc:
        raise BeneficiaryAuthError("Passphrase incorrecte ou fichier corrompu.") from exc


def save_beneficiaries(data: dict, passphrase: str) -> None:
    if not isinstance(data, dict):
        raise TypeError("beneficiaries must be a dict")
    sec.save_encrypted_json(BENEFICIARIES_FILE, data, passphrase)


def migrate_plaintext(passphrase: str, plaintext_path: Path | None = None) -> bool:
    """Encrypt a legacy beneficiaries.json and securely remove the plaintext.

    Returns True when a migration was performed.
    """
    plain = plaintext_path or (BASE / "beneficiaries.json")
    if not plain.exists():
        return False
    data = json.loads(plain.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("beneficiaries.json invalide")
    save_beneficiaries(data, passphrase)
    # Best effort overwrite before unlink. SSD/filesystem wear levelling means
    # this is not a forensic secure erase guarantee, hence public releases do
    # not ship plaintext files at all.
    try:
        size = plain.stat().st_size
        with open(plain, "wb", buffering=0) as fh:
            fh.write(os.urandom(size))
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        plain.unlink(missing_ok=True)
    return True
