#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compatibility facade for the v1.4 encrypted vault.

The high experimental security. New code
must use security_core: Argon2id + AES-256-GCM, authenticated per blob.
"""
from security_core import (
    AuthenticationError,
    SecurityError,
    decrypt_bytes,
    decrypt_json,
    encrypt_bytes,
    encrypt_json,
    generate_passphrase,
    get_security_mode,
    set_security_mode,
)

__all__ = [
    "AuthenticationError", "SecurityError", "decrypt_bytes", "decrypt_json",
    "encrypt_bytes", "encrypt_json", "generate_passphrase",
    "get_security_mode", "set_security_mode",
]
