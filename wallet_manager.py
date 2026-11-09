#!/usr/bin/env python3
"""
wallet_manager.py — Générateur et gestionnaire de wallets crypto locaux
Supporte : Bitcoin (BTC), Ethereum (ETH), Solana (SOL),
           Litecoin (LTC), Dogecoin (DOGE), BNB (BSC), USDT (Erc-20)

Les wallets sont générés offline et stockés sur disque dans un fichier JSON
chiffré avec une phrase de passe (passphrase) que vous choisissez.

Utilisation :
    python wallet_manager.py create btc     # Crée un wallet Bitcoin
    python wallet_manager.py create eth     # Crée un wallet Ethereum
    python wallet_manager.py create sol     # Crée un wallet Solana
    python wallet_manager.py create ltc     # Crée un wallet Litecoin
    python wallet_manager.py create doge    # Crée un wallet Dogecoin
    python wallet_manager.py create bnb     # Crée un wallet BNB (BSC)
    python wallet_manager.py create usdt    # Crée un wallet USDT (Erc-20)
    python wallet_manager.py list           # Liste tous les wallets
    python wallet_manager.py show btc       # Affiche les infos d'un wallet
    python wallet_manager.py delete btc     # Supprime un wallet
"""

import argparse
import json
import os
import sys
from pathlib import Path
from asset_catalog import asset_icon, network_icon, icon_column
from typing import Optional

# ── Chiffrement ──
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

import security_core as _sec

# ── Bitcoin ──
from bitcoinlib.wallets import Wallet as BTCWallet
from bitcoinlib.wallets import wallet_delete_if_exists
from bitcoinlib.mnemonic import Mnemonic

# ── Ethereum ──
from web3 import Web3
from eth_account import Account as EthAccount

# ── Solana ──
from solders.keypair import Keypair
import base58

# ── Saisie sécurisée (masquée) ──
from getpass import getpass as _getpass

def get_secret(prompt: str) -> str:
    """Lit un secret (passphrase) sans l'afficher dans le terminal.
    Utilise getpass si un vrai TTY est disponible (cas normal), sinon
    retombe sur input (permet les tests automatisés sans TTY)."""
    try:
        return _getpass(prompt)
    except (EOFError, OSError):
        return input(prompt)


# ── Configuration ───────────────────────────────────────────────────────
WALLET_DIR = Path(__file__).parent / "wallets"
WALLET_FILE = WALLET_DIR / "wallets.enc"
SALT_FILE = WALLET_DIR / "salt.bin"

# ── Gestion du chiffrement ─────────────────────────────────────────────

def _get_persistent_salt() -> bytes:
    """Renvoie un sel persistant (stocké dans SALT_FILE), le crée si absent.
    Un sel stable évite de le régénérer à chaque écriture et lie le
    fichier de wallets à ce sel spécifique."""
    WALLET_DIR.mkdir(parents=True, exist_ok=True)
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    os.chmod(SALT_FILE, 0o600)
    return salt


def check_passphrase_strength(passphrase: str) -> bool:
    """Validation commune du mot de passe maître du coffre."""
    return _sec.check_passphrase_strength(passphrase)

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Dérive une clé de chiffrement à partir d'une phrase de passe + sel."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_data(data: dict, passphrase: str) -> bytes:
    """Chiffre les wallets avec Argon2id + AES-256-GCM (format KCW2)."""
    return _sec.encrypt_json(data, passphrase)


def decrypt_data(data: bytes, passphrase: str) -> Optional[dict]:
    """Déchiffre KCW2 et accepte l'ancien format Fernet pour migration."""
    if _sec.is_secure_blob(data):
        try:
            obj = _sec.decrypt_json(data, passphrase)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    # Compatibilité v1 : salt(16) + token Fernet. Une sauvegarde suivante
    # migre automatiquement le fichier vers KCW2/AES-256-GCM.
    try:
        salt = data[:16]
        token = data[16:]
        key = derive_key(passphrase, salt)
        fernet = Fernet(key)
        payload = fernet.decrypt(token)
        obj = json.loads(payload.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


# ── Persistance ────────────────────────────────────────────────────────

class WalletAuthError(ValueError):
    """Phrase de passe incorrecte (ou fichier corrompu)."""


def load_wallets(passphrase: str) -> dict:
    """Charge le fichier de wallets depuis le disque.
    Lève WalletAuthError si la phrase de passe est incorrecte ou le
    fichier corrompu (au lieu de sys.exit, pour ne pas tuer le processus)."""
    if not WALLET_FILE.exists():
        return {}
    raw = WALLET_FILE.read_bytes()
    data = decrypt_data(raw, passphrase)
    if data is None:
        raise WalletAuthError(
            "Phrase de passe incorrecte ou fichier corrompu.")
    return data


def save_wallets(wallets: dict, passphrase: str):
    """Sauvegarde les wallets sur le disque (chiffré)."""
    WALLET_DIR.mkdir(parents=True, exist_ok=True)
    encrypted = encrypt_data(wallets, passphrase)
    _sec.atomic_write(WALLET_FILE, encrypted)


# ── Génération de wallets ──────────────────────────────────────────────

def generate_btc_wallet(label: str, passphrase_wallet: str = "") -> dict:
    """
    Génère un wallet Bitcoin avec une phrase mnémonique BIP39.
    Retourne { label, network, address, private_key_wif, mnemonic }
    """
    mnemonic = Mnemonic().generate()
    wallet_delete_if_exists(f"wallet_{label}", force=True)
    w = BTCWallet.create(
        f"wallet_{label}",
        witness_type="segwit",
        keys=mnemonic,
        network="bitcoin",
    )
    key = w.get_key()
    result = {
        "label": label,
        "network": "bitcoin",
        "address": key.address,
        "private_key_wif": key.wif,
        "mnemonic": mnemonic,
        "derivation_path": "m/84'/0'/0'/0/0",
    }
  
    return result


def generate_eth_wallet(label: str) -> dict:
    """
    Génère un wallet Ethereum avec phrase mnémonique BIP39 + dérivation HD
    (m/44'/60'/0'/0/0), identique au standard de MetaMask/MyEtherWallet.
    Retourne { label, network, address, private_key_hex, mnemonic, derivation_path }
    """
    from mnemonic import Mnemonic as Bip39
    from bip32utils import BIP32Key

    mnemo = Bip39("english")
    words = mnemo.generate(strength=256)  # 24 mots
    seed = mnemo.to_seed(words)
    # Dérivation HD: m/44'/60'/0'/0/0
    master = BIP32Key.fromEntropy(seed)
    child = (master
             .ChildKey(44 + 0x80000000)
             .ChildKey(60 + 0x80000000)
             .ChildKey(0 + 0x80000000)
             .ChildKey(0)
             .ChildKey(0))
    priv_hex = child.PrivateKey().hex()
    acct = EthAccount.from_key(bytes.fromhex(priv_hex))
    result = {
        "label": label,
        "network": "ethereum",
        "address": acct.address,
        "private_key_hex": priv_hex,
        "mnemonic": words,
        "derivation_path": "m/44'/60'/0'/0/0",
    }
    return result


def generate_sol_wallet(label: str) -> dict:
    """
    Génère un wallet Solana (Ed25519).
    Retourne { label, network, address, private_key_base58 }
    """
    kp = Keypair()
    address = str(kp.pubkey())
    private_key_bytes = bytes(kp)
    private_key_b58 = base58.b58encode(private_key_bytes)
    result = {
        "label": label,
        "network": "solana",
        "address": address,
        "private_key_base58": str(private_key_b58),
        "private_key_bytes_hex": private_key_bytes.hex(),
    }
    return result


# LTC et DOGE sont des forks de Bitcoin gérés nativement par bitcoinlib.
def generate_ltc_wallet(label: str) -> dict:
    """Génère un wallet Litecoin (SegWit) avec mnémonique BIP39.
    Retourne { label, network, address, private_key_wif, mnemonic }."""
    mnemonic = Mnemonic().generate()
    wallet_delete_if_exists(f"wallet_{label}", force=True)
    w = BTCWallet.create(
        f"wallet_{label}",
        witness_type="segwit",
        keys=mnemonic,
        network="litecoin",
    )
    key = w.get_key()
    return {
        "label": label,
        "network": "litecoin",
        "address": key.address,
        "private_key_wif": key.wif,
        "mnemonic": mnemonic,
        "derivation_path": "m/84'/2'/0'/0/0",
    }


def generate_doge_wallet(label: str) -> dict:
    """Génère un wallet Dogecoin avec mnémonique BIP39.
    Retourne { label, network, address, private_key_wif, mnemonic }."""
    mnemonic = Mnemonic().generate()
    wallet_delete_if_exists(f"wallet_{label}", force=True)
    w = BTCWallet.create(
        f"wallet_{label}",
        keys=mnemonic,
        network="dogecoin",
        witness_type="legacy",
    )
    key = w.get_key()
    return {
        "label": label,
        "network": "dogecoin",
        "address": key.address,
        "private_key_wif": key.wif,
        "mnemonic": mnemonic,
        "derivation_path": "m/44'/3'/0'/0/0",
    }


# BNB (BSC) est une chaîne EVM identique à Ethereum (même courbe secp256k1).
def generate_bnb_wallet(label: str) -> dict:
    """Génère un wallet BNB (BSC) via dérivation HD EVM m/44'/60'/0'/0/0.
    Retourne { label, network, address, private_key_hex, mnemonic }."""
    from mnemonic import Mnemonic as Bip39
    from bip32utils import BIP32Key

    mnemo = Bip39("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words)
    master = BIP32Key.fromEntropy(seed)
    child = (master
             .ChildKey(44 + 0x80000000)
             .ChildKey(60 + 0x80000000)
             .ChildKey(0 + 0x80000000)
             .ChildKey(0)
             .ChildKey(0))
    priv_hex = child.PrivateKey().hex()
    acct = EthAccount.from_key(bytes.fromhex(priv_hex))
    return {
        "label": label,
        "network": "bsc",
        "address": acct.address,
        "private_key_hex": priv_hex,
        "mnemonic": words,
        "derivation_path": "m/44'/60'/0'/0/0",
    }


# USDT est un token ERC-20 (et BEP-20) : même adresse/clé qu'un wallet ETH/EVM,
# avec un champ token="USDT" pour distinguer le solde.
def generate_usdt_wallet(label: str) -> dict:
    """Génère un wallet USDT (Erc-20) — réutilise la crypto EVM.
    Retourne { label, network, token, address, private_key_hex, mnemonic }."""
    from mnemonic import Mnemonic as Bip39
    from bip32utils import BIP32Key

    mnemo = Bip39("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words)
    master = BIP32Key.fromEntropy(seed)
    child = (master
             .ChildKey(44 + 0x80000000)
             .ChildKey(60 + 0x80000000)
             .ChildKey(0 + 0x80000000)
             .ChildKey(0)
             .ChildKey(0))
    priv_hex = child.PrivateKey().hex()
    acct = EthAccount.from_key(bytes.fromhex(priv_hex))
    return {
        "label": label,
        "network": "ethereum",   # USDT repose sur la chaîne EVM sous-jacente
        "token": "USDT",
        "address": acct.address,
        "private_key_hex": priv_hex,
        "mnemonic": words,
        "derivation_path": "m/44'/60'/0'/0/0",
    }


# ── Helpers EVM génériques (Polygon, Avalanche, Arbitrum, Optimism, etc.) ──

def generate_evm_wallet(label: str, network: str, symbol: str, chain_id: int,
                         derivation_path: str = "m/44'/60'/0'/0/0") -> dict:
    """Génère un wallet sur une chaîne EVM (même crypto que Ethereum).
    Retourne { label, network, symbol, address, private_key_hex, mnemonic,
               chain_id, derivation_path }."""
    from mnemonic import Mnemonic as Bip39
    from bip32utils import BIP32Key

    mnemo = Bip39("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words)
    master = BIP32Key.fromEntropy(seed)
    child = (master
             .ChildKey(44 + 0x80000000)
             .ChildKey(60 + 0x80000000)
             .ChildKey(0 + 0x80000000)
             .ChildKey(0)
             .ChildKey(0))
    priv_hex = child.PrivateKey().hex()
    acct = EthAccount.from_key(bytes.fromhex(priv_hex))
    return {
        "label": label,
        "network": network,
        "symbol": symbol,
        "chain_id": chain_id,
        "address": acct.address,
        "private_key_hex": priv_hex,
        "mnemonic": words,
        "derivation_path": derivation_path,
    }


# Polygon (POL/MATIC), Avalanche (AVAX), Arbitrum (ARB), Optimism (OP)
def generate_polygon_wallet(label: str) -> dict:
    """Polygon PoS (chainId 137)."""
    return generate_evm_wallet(label, "polygon", "POL", 137)


def generate_avalanche_wallet(label: str) -> dict:
    """Avalanche C-Chain (chainId 43114)."""
    return generate_evm_wallet(label, "avalanche", "AVAX", 43114)


def generate_arbitrum_wallet(label: str) -> dict:
    """Arbitrum One (chainId 42161)."""
    return generate_evm_wallet(label, "arbitrum", "ETH", 42161)


def generate_optimism_wallet(label: str) -> dict:
    """Optimism (chainId 10)."""
    return generate_evm_wallet(label, "optimism", "ETH", 10)


# ── Stablecoins ERC-20 / BEP-20 supplémentaires ──

def generate_erc20_wallet(label: str, token: str) -> dict:
    """Génère un wallet pour un token ERC-20 (USDC, DAI, ...).
    Même adresse/clé qu'un wallet ETH (le token est suivi via son contrat)."""
    from mnemonic import Mnemonic as Bip39
    from bip32utils import BIP32Key

    mnemo = Bip39("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words)
    master = BIP32Key.fromEntropy(seed)
    child = (master
             .ChildKey(44 + 0x80000000)
             .ChildKey(60 + 0x80000000)
             .ChildKey(0 + 0x80000000)
             .ChildKey(0)
             .ChildKey(0))
    priv_hex = child.PrivateKey().hex()
    acct = EthAccount.from_key(bytes.fromhex(priv_hex))
    return {
        "label": label,
        "network": "ethereum",
        "token": token,
        "address": acct.address,
        "private_key_hex": priv_hex,
        "mnemonic": words,
        "derivation_path": "m/44'/60'/0'/0/0",
    }


def generate_usdc_wallet(label: str) -> dict:
    return generate_erc20_wallet(label, "USDC")


def generate_dai_wallet(label: str) -> dict:
    return generate_erc20_wallet(label, "DAI")


def generate_catalog_wallet(label: str, asset_id: str, spec: dict) -> dict:
    """Génère une adresse pour un couple actif/réseau du catalogue.

    Le coffre conserve ``asset_id`` afin que deux jetons homonymes présents
    sur des chaînes différentes ne puissent jamais être confondus.
    """
    kind = spec.get("kind")
    network = spec["network"]
    if kind == "evm_token":
        chain_ids = {"ethereum": 1, "bsc": 56, "polygon": 137}
        data = generate_evm_wallet(label, network, spec["asset"], chain_ids[network])
    elif kind == "spl":
        data = generate_sol_wallet(label)
    elif kind == "trc20":
        data = generate_trx_wallet(label)
    else:
        generator = globals()[spec["generator"]]
        data = generator(label)
    data["asset_id"] = asset_id
    data["asset"] = spec["asset"]
    if kind != "native":
        data["token"] = spec["asset"]
        data["token_kind"] = kind
        if spec.get("contract"):
            data["contract"] = spec["contract"]
        if spec.get("mint"):
            data["mint"] = spec["mint"]
        data["decimals"] = spec["decimals"]
        data["gas_asset"] = spec["gas"]
    return data


# ── Non-EVM : XRP, Tron, Cosmos, Cardano ──

def generate_xrp_wallet(label: str) -> dict:
    """Génère un wallet XRP (secp256k1 + adresse base58check 'r' alphabet Ripple)."""
    from ecdsa import SigningKey, SECP256k1
    import base58, hashlib

    sk = SigningKey.generate(curve=SECP256k1)
    priv_hex = sk.to_string().hex()
    vk = sk.get_verifying_key()
    pub = b"\x04" + vk.to_string()  # uncompressed
    # XRP account ID = RIPEMD160(SHA256(pubkey))
    rid = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    # adresse = base58check avec alphabet Ripple (préfixe 'r', version byte 0x00)
    XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
    payload = b"\x00" + rid
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum, alphabet=XRP_ALPHABET.encode()).decode()
    return {
        "label": label,
        "network": "ripple",
        "address": address,
        "private_key_hex": priv_hex,
    }


def generate_trx_wallet(label: str) -> dict:
    """Génère un wallet Tron (secp256k1 = même courbe qu'ETH, adresse TRX)."""
    from eth_keys import keys as eth_keys
    import base58
    from hashlib import sha256

    # clé identique à ETH
    sk = eth_keys.PrivateKey(os.urandom(32))
    priv_hex = sk.to_hex()[2:]
    pub = sk.public_key.to_bytes()
    # adresse TRX = base58check(0x41 + keccak256(pub)[-20:])
    from eth_utils import keccak
    addr_bytes = b"\x41" + keccak(pub)[-20:]
    checksum = sha256(sha256(addr_bytes).digest()).digest()[:4]
    address = base58.b58encode(addr_bytes + checksum).decode()
    return {
        "label": label,
        "network": "tron",
        "address": address,
        "private_key_hex": priv_hex,
    }


def _bech32_encode(hrp: str, data: bytes) -> str:
    """Encode bech32 (Cosmos/ATOM/Cardano). data = 5-bit groups already converted."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    def polymod(values):
        gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = (chk >> 25) & 1
            chk = (chk * 2 ^ v) ^ gen[b]
        for _ in range(6):
            chk = (chk * 2 ^ gen[(chk >> 25) & 1]) & 0xffffffff
        return chk ^ 1
    def hrp_expand(h):
        return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]
    vals = hrp_expand(hrp) + list(data) + [0]*6
    chk = polymod(vals)
    cs = [(chk >> 5*(5-i)) & 31 for i in range(6)]
    res = hrp + "1" + "".join(CHARSET[d & 31] for d in list(data) + cs)
    return res


def generate_atom_wallet(label: str) -> dict:
    """Génère un wallet Cosmos (ATOM) — secp256k1 + adresse bech32 'cosmos1'.

    Cosmos utilise la courbe secp256k1 (comme BTC/ETH), pas Ed25519.
    L'adresse = bech32("cosmos", RIPEMD160(SHA256(pub_compressée))).
    On stocke la clé privée hex secp256k1 pour permettre la signature."""
    from ecdsa import SigningKey, SECP256k1
    import hashlib

    sk = SigningKey.generate(curve=SECP256k1)
    priv_hex = sk.to_string().hex()
    vk = sk.get_verifying_key()
    # clé publique COMPRESSÉE (33 octets : 0x02/0x03 + X)
    pub = (b"\x02" if vk.to_string()[-1] & 1 == 0 else b"\x03") + vk.to_string()[:32]
    # account ID Cosmos = RIPEMD160(SHA256(pub_compressée))
    rid = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    # conversion 8-bit -> 5-bit pour bech32
    data5 = []
    acc = 0; bits = 0
    for byte in rid:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data5.append((acc >> bits) & 31)
    if bits:
        data5.append((acc << (5 - bits)) & 31)
    address = _bech32_encode("cosmos", bytes(data5))
    return {
        "label": label,
        "network": "cosmos",
        "address": address,
        "private_key_hex": priv_hex,
    }


def generate_ada_wallet(label: str) -> dict:
    """Génère un wallet Cardano (ADA) — Ed25519 BIP32 + adresse Shelley base 'addr1'.

    Implémentation pure-Python (sans pycardano, non buildable sur Python 3.14).
    Génère une seed BIP39 + clé ed25519, et une adresse de paiement
    (payment credential seul, sans stake) encodée en bech32 'addr1'.
    """
    from hashlib import blake2b, sha256
    import hmac, hashlib

    # 1) seed BIP39
    from mnemonic import Mnemonic as Bip39
    words = Bip39("english").generate(strength=256)
    seed_bytes = Bip39("english").to_seed(words)

    # 2) clé privée ed25519 (root) via HMAC-SHA512 du seed (BIP32-ed25519 simplifié)
    I = hmac.new(b"ed25519 seed", seed_bytes, hashlib.sha512).digest()
    key = I[:32]
    # clé publique ed25519
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(key)
    pub = priv.public_key().public_bytes_raw()

    # 3) payment credential = blake2b(pub, 224 bits) -> 28 bytes
    h = blake2b(pub, digest_size=28).digest()
    # 4) Enterprise address Shelley (payment key, no stake) :
    #    header = 0x61 (0110 0001 : payment=011, key=0, no-stake=0001),
    #    suivi du payment credential (28 bytes). C'est une adresse VALIDE
    #    pour recevoir des fonds (sans partie stake).
    payload = bytes([0x61]) + h
    # 5) bech32 'addr' (Shelley) — conversion 8-bit -> 5-bit
    data5 = []
    acc = 0; bits = 0
    for byte in payload:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data5.append((acc >> bits) & 31)
    if bits:
        data5.append((acc << (5 - bits)) & 31)
    address = _bech32_encode("addr", bytes(data5))
    return {
        "label": label,
        "network": "cardano",
        "address": address,
        "private_key_hex": key.hex(),
        "mnemonic": words,
    }


def generate_ada_wallet(label: str) -> dict:
    """Génère un wallet Cardano (ADA) — Ed25519 BIP32 + adresse Shelley base 'addr1'.

    Implémentation pure-Python (sans pycardano, non buildable sur Python 3.14).
    Génère une seed BIP39 + clé ed25519, et une adresse de paiement
    (payment credential seul, sans stake) encodée en bech32 'addr1'.
    """
    from hashlib import blake2b, sha256
    import hmac, hashlib

    # 1) seed BIP39
    from mnemonic import Mnemonic as Bip39
    words = Bip39("english").generate(strength=256)
    seed_bytes = Bip39("english").to_seed(words)

    # 2) clé privée ed25519 (root) via HMAC-SHA512 du seed (BIP32-ed25519 simplifié)
    I = hmac.new(b"ed25519 seed", seed_bytes, hashlib.sha512).digest()
    key = I[:32]
    # clé publique ed25519
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(key)
    pub = priv.public_key().public_bytes_raw()

    # 3) payment credential = blake2b(pub, 224 bits) -> 28 bytes
    h = blake2b(pub, digest_size=28).digest()
    # 4) Enterprise address Shelley (payment key, no stake) :
    #    header = 0x61 (0110 0001 : payment=011, key=0, no-stake=0001),
    #    suivi du payment credential (28 bytes). C'est une adresse VALIDE
    #    pour recevoir des fonds (sans partie stake).
    payload = bytes([0x61]) + h
    # 5) bech32 'addr' (Shelley) — conversion 8-bit -> 5-bit
    data5 = []
    acc = 0; bits = 0
    for byte in payload:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data5.append((acc >> bits) & 31)
    if bits:
        data5.append((acc << (5 - bits)) & 31)
    address = _bech32_encode("addr", bytes(data5))
    return {
        "label": label,
        "network": "cardano",
        "address": address,
        "private_key_hex": key.hex(),
        "mnemonic": words,
    }


def generate_xmr_wallet(label: str) -> dict:
    """Génère un wallet Monero (XMR) — mnémonique 25 mots + clés/spend/view.
    Génération 100% offline via la bibliothèque `monero`. L'adresse est une
    adresse standard (préfixe '4', 95 caractères base58)."""
    from monero.seed import Seed
    seed = Seed()                       # clé de dépense aléatoire + dérivation view
    return {
        "label": label,
        "network": "monero",
        "address": str(seed.public_address()),
        "mnemonic": seed.phrase,                       # 25 mots (restauration)
        "private_spend_key": seed.secret_spend_key(),  # scalaire Ed25519
        "private_view_key": seed.secret_view_key(),    # scalaire Ed25519
    }


# ── Interface CLI ──────────────────────────────────────────────────────

def cmd_create(args):
    """Crée un nouveau wallet et le sauvegarde."""
    network = args.network.lower()
    label = args.label or f"{network}_{os.urandom(4).hex()}"

    if network == "btc":
        data = generate_btc_wallet(label)
    elif network == "eth":
        data = generate_eth_wallet(label)
    elif network == "sol":
        data = generate_sol_wallet(label)
    elif network == "ltc":
        data = generate_ltc_wallet(label)
    elif network == "doge":
        data = generate_doge_wallet(label)
    elif network == "bnb":
        data = generate_bnb_wallet(label)
    elif network == "usdt":
        data = generate_usdt_wallet(label)
    elif network == "polygon":
        data = generate_polygon_wallet(label)
    elif network == "avalanche":
        data = generate_avalanche_wallet(label)
    elif network == "arbitrum":
        data = generate_arbitrum_wallet(label)
    elif network == "optimism":
        data = generate_optimism_wallet(label)
    elif network == "usdc":
        data = generate_usdc_wallet(label)
    elif network == "dai":
        data = generate_dai_wallet(label)
    elif network == "xrp":
        data = generate_xrp_wallet(label)
    elif network == "trx":
        data = generate_trx_wallet(label)
    elif network == "atom":
        data = generate_atom_wallet(label)
    elif network == "ada":
        data = generate_ada_wallet(label)
    elif network == "xmr":
        data = generate_xmr_wallet(label)
    else:
        print(f"[!] Réseau non supporté : {network}", file=sys.stderr)
        print("    Supportés : btc, eth, sol, ltc, doge, bnb, usdt, polygon, "
              "avalanche, arbitrum, optimism, usdc, dai, xrp, trx, atom, ada",
              file=sys.stderr)
        sys.exit(1)

    # Demander la phrase de passe pour le fichier
    passphrase = get_secret("🔑 Phrase de passe pour le fichier wallet (elle ne sera pas stockée) : ")
    if not check_passphrase_strength(passphrase):
        print("[!] Phrase de passe trop faible.", file=sys.stderr)
        print("    Elle doit faire >= 12 caractères et mélanger au moins 3 types "
              "parmi: minuscules, MAJUSCULES, chiffres, caractères spéciaux.",
              file=sys.stderr)
        sys.exit(1)
    wallets = load_wallets(passphrase)
    wallets[label] = data
    save_wallets(wallets, passphrase)

    print(f"\n✅ Wallet {label} ({network.upper()}) créé avec succès !")
    print(f"   Adresse  : {data['address']}")
    print(f"   Stocké dans : {WALLET_FILE}")
    print("\n⚠️  CONSERVEZ VOS CLÉS PRIVÉES EN LIEU SÛR (hors ligne de préférence).")
    print("   Sans votre phrase de passe, personne ne peut lire ce fichier.\n")


def cmd_list(args):
    """Liste tous les wallets stockés."""
    passphrase = get_secret("🔑 Phrase de passe du fichier wallet : ")
    wallets = load_wallets(passphrase)
    if not wallets:
        print("Aucun wallet trouvé.")
        return
    print(f"\n   {'Label':<24}    {'Réseau':<10} {'Adresse'}")
    print("─" * 70)
    for label, info in wallets.items():
        addr = info.get("address", "N/A")
        net = info.get("network", "N/A")
        asset = info.get("asset_id") or info.get("token") or info.get("asset") or net
        print(f"{icon_column(asset_icon(asset))} {label:<24} {icon_column(network_icon(net))} "
              f"{net:<10} {addr}")


def cmd_show(args):
    """Affiche les détails complets d'un wallet spécifique.
    Les champs sensibles (clés privées, mnémoniques) sont masqués par
    défaut pour éviter une exposition à l'écran ; ils ne s'affichent que
    si l'utilisateur le demande explicitement."""
    label = args.label
    passphrase = get_secret("🔑 Phrase de passe du fichier wallet : ")
    wallets = load_wallets(passphrase)
    if label not in wallets:
        print(f"[!] Wallet '{label}' introuvable.", file=sys.stderr)
        sys.exit(1)
    info = wallets[label]
    # Champs considérés comme secrets : jamais affichés en clair sans accord
    SENSITIVE = {
        "private_key_wif", "mnemonic", "private_key_hex",
        "private_key_base58", "private_key_bytes_hex",
    }
    reveal = input("🔓 Afficher les clés privées en clair ? (oui/non) : ").lower() == "oui"
    print(f"\n📋 Wallet : {label}")
    print("=" * 50)
    for key, val in info.items():
        if key in SENSITIVE and not reveal:
            val = "•••••••• (masqué — relance avec 'oui' pour révéler)"
        print(f"   {key:.<30} {val}")
    print()


def cmd_delete(args):
    """Supprime un wallet du fichier."""
    label = args.label
    passphrase = get_secret("🔑 Phrase de passe du fichier wallet : ")
    wallets = load_wallets(passphrase)
    if label not in wallets:
        print(f"[!] Wallet '{label}' introuvable.", file=sys.stderr)
        sys.exit(1)
    confirm = input(f"⚠️  Supprimer '{label}' ? (oui/non) : ")
    if confirm.lower() != "oui":
        print("Annulé.")
        return
    del wallets[label]
    save_wallets(wallets, passphrase)
    print(f"✅ Wallet '{label}' supprimé.")


# ── Point d'entrée ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Gestionnaire de wallets crypto locaux (BTC, ETH, SOL)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python wallet_manager.py create btc\n"
            "  python wallet_manager.py create eth --label mon_eth\n"
            "  python wallet_manager.py create sol --label ma_sol\n"
            "  python wallet_manager.py list\n"
            "  python wallet_manager.py show mon_eth\n"
            "  python wallet_manager.py delete ma_sol\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create
    p_create = subparsers.add_parser("create", help="Créer un nouveau wallet")
    p_create.add_argument("network", choices=["btc", "eth", "sol", "ltc", "doge", "bnb",
                                              "usdt", "polygon", "avalanche", "arbitrum",
                                              "optimism", "usdc", "dai", "xrp", "trx", "atom", "ada"],
                          help="Type de wallet")
    p_create.add_argument("--label", "-l", default=None,
                          help="Étiquette pour le wallet (automatique si omise)")

    # list
    subparsers.add_parser("list", help="Lister tous les wallets")

    # show
    p_show = subparsers.add_parser("show", help="Afficher les détails d'un wallet")
    p_show.add_argument("label", help="Étiquette du wallet")

    # delete
    p_del = subparsers.add_parser("delete", help="Supprimer un wallet")
    p_del.add_argument("label", help="Étiquette du wallet")

    args = parser.parse_args()

    # Routage
    if args.command == "create":
        cmd_create(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "show":
        cmd_show(args)
    elif args.command == "delete":
        cmd_delete(args)


if __name__ == "__main__":
    main()
