#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security core for Crypto Cold Wallet.

Sensitive local data format v2:
- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation
- unique 128-bit salt per encrypted blob
- unique 96-bit nonce per encrypted blob
- KDF parameters embedded in the authenticated header

The master passphrase is never written to disk.
Only ``security.json`` is plaintext; it contains the selected performance
profile and format version, never wallet data, keys, contacts, history or
password verifiers.
"""
from __future__ import annotations

import json
import os
import secrets
import struct
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from argon2.low_level import Type, hash_secret_raw
except ImportError as exc:  # pragma: no cover - installation error path
    raise RuntimeError(
        "argon2-cffi is required for the encrypted vault. "
        "Install it with: pip install argon2-cffi"
    ) from exc

BASE = Path(__file__).resolve().parent
CONFIG_FILE = BASE / "security.json"
MAGIC = b"KCW2"
FORMAT_VERSION = 2
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# memory_cost is expressed in KiB by Argon2.
PROFILES = {
    "standard": {
        "time_cost": 2,
        "memory_cost": 64 * 1024,
        "parallelism": 2,
        "label": "Standard",
    },
    "reinforced": {
        "time_cost": 3,
        "memory_cost": 128 * 1024,
        "parallelism": 2,
        "label": "Renforcé",
    },
    "maximum": {
        "time_cost": 4,
        "memory_cost": 256 * 1024,
        "parallelism": 2,
        "label": "Maximum",
    },
}
DEFAULT_PROFILE = "reinforced"

# 4 magic + 1 version + 3 unsigned ints + salt + nonce
_HEADER = struct.Struct(">4sBIII16s12s")


class SecurityError(ValueError):
    pass


class AuthenticationError(SecurityError):
    pass


def get_security_mode(default: str = DEFAULT_PROFILE) -> str:
    try:
        cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        mode = str(cfg.get("mode", "")).strip().lower()
        if mode in PROFILES:
            return mode
    except (OSError, ValueError, TypeError):
        pass
    return default


def set_security_mode(mode: str) -> None:
    mode = mode.strip().lower()
    if mode not in PROFILES:
        raise ValueError(f"Unknown security mode: {mode}")
    payload = {
        "format": FORMAT_VERSION,
        "mode": mode,
        "kdf": "Argon2id",
        "cipher": "AES-256-GCM",
    }
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)


def profile_description(mode: str) -> dict[str, Any]:
    return dict(PROFILES[mode])


def check_passphrase_strength(passphrase: str) -> bool:
    """Accept a long natural passphrase or a complex password.

    Generated 24-word phrases pass by design. A custom phrase can either be
    >= 5 whitespace-separated words and >= 24 chars, or >= 16 chars with all
    four common character classes.
    """
    if not isinstance(passphrase, str):
        return False
    if len(passphrase) >= 24 and len(passphrase.split()) >= 5:
        return True
    if len(passphrase) < 16:
        return False
    classes = (
        any(c.islower() for c in passphrase),
        any(c.isupper() for c in passphrase),
        any(c.isdigit() for c in passphrase),
        any(not c.isalnum() for c in passphrase),
    )
    return all(classes)


def generate_passphrase() -> str:
    """Generate a 24-word, 256-bit BIP39 word sequence for vault use.

    It is used only as a master passphrase. It is NOT automatically reused as
    a cryptocurrency wallet seed and is never written to disk by this module.
    """
    try:
        from mnemonic import Mnemonic
        return Mnemonic("english").generate(strength=256)
    except Exception:
        # Offline fallback: 24 independently selected words. The normal
        # installation includes `mnemonic`; this path keeps the UI usable
        # even before that dependency is available.
        words = (
            "amber anchor apple atlas autumn bamboo beacon birch breeze bridge "
            "cactus canyon cedar cipher cloud comet coral cosmos crystal dawn "
            "delta dune eagle ember fable falcon fern flame forest frost galaxy "
            "garden glacier golden harbor hazel horizon island jade jungle lagoon "
            "lantern lemon lunar maple meadow meteor mist mountain nebula ocean "
            "olive orchid pebble pine pixel planet prism quartz raven reef river "
            "rocket saffron shadow silver solar spruce stone summit thunder tiger "
            "timber tornado valley velvet violet volcano willow winter zenith"
        ).split()
        return " ".join(secrets.choice(words) for _ in range(24))


def _derive(passphrase: str, salt: bytes, time_cost: int,
            memory_cost: int, parallelism: int) -> bytes:
    if not passphrase:
        raise AuthenticationError("Empty master passphrase")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def is_secure_blob(blob: bytes) -> bool:
    return isinstance(blob, (bytes, bytearray)) and bytes(blob).startswith(MAGIC)


def encrypt_bytes(plaintext: bytes, passphrase: str, mode: str | None = None) -> bytes:
    mode = (mode or get_security_mode()).lower()
    if mode not in PROFILES:
        raise SecurityError(f"Unknown security mode: {mode}")
    p = PROFILES[mode]
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = _HEADER.pack(
        MAGIC, FORMAT_VERSION, p["time_cost"], p["memory_cost"],
        p["parallelism"], salt, nonce,
    )
    key = _derive(passphrase, salt, p["time_cost"], p["memory_cost"], p["parallelism"])
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)
    return header + ciphertext


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    if not is_secure_blob(blob) or len(blob) <= _HEADER.size:
        raise AuthenticationError("Unknown encrypted format")
    try:
        magic, version, time_cost, memory_cost, parallelism, salt, nonce = _HEADER.unpack(
            bytes(blob[:_HEADER.size])
        )
        if magic != MAGIC or version != FORMAT_VERSION:
            raise AuthenticationError("Unsupported encrypted format")
        # Defensive limits protect against malicious/corrupted headers causing
        # extreme resource allocation before authentication.
        if not (1 <= time_cost <= 10):
            raise AuthenticationError("Invalid KDF parameters")
        if not (16 * 1024 <= memory_cost <= 512 * 1024):
            raise AuthenticationError("Invalid KDF parameters")
        if not (1 <= parallelism <= 8):
            raise AuthenticationError("Invalid KDF parameters")
        key = _derive(passphrase, salt, time_cost, memory_cost, parallelism)
        return AESGCM(key).decrypt(nonce, bytes(blob[_HEADER.size:]), bytes(blob[:_HEADER.size]))
    except AuthenticationError:
        raise
    except Exception as exc:
        raise AuthenticationError("Wrong passphrase or corrupted encrypted data") from exc


def encrypt_json(data: Any, passphrase: str, mode: str | None = None) -> bytes:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return encrypt_bytes(raw, passphrase, mode)


def decrypt_json(blob: bytes, passphrase: str) -> Any:
    try:
        return json.loads(decrypt_bytes(blob, passphrase).decode("utf-8"))
    except AuthenticationError:
        raise
    except Exception as exc:
        raise AuthenticationError("Encrypted JSON is corrupted") from exc


def atomic_write(path: Path, blob: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(blob)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def save_encrypted_json(path: Path, data: Any, passphrase: str,
                        mode: str | None = None) -> None:
    atomic_write(path, encrypt_json(data, passphrase, mode))


def load_encrypted_json(path: Path, passphrase: str, default: Any = None) -> Any:
    if not path.exists():
        return default
    return decrypt_json(path.read_bytes(), passphrase)
