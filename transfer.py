#!/usr/bin/env python3
"""
transfer.py — Effectue des transferts depuis les wallets locaux
(BTC, ETH, SOL, LTC, DOGE, BNB, USDT, USDC, DAI, POL, AVAX, ARB, OP, XMR)
Nécessite une connexion Internet pour broadcast les transactions.

Usage :
    python transfer.py transfer btc <label> <adresse_dest> <montant>
    python transfer.py transfer eth <label> <adresse_dest> <montant>
    python transfer.py transfer sol <label> <adresse_dest> <montant>
    python transfer.py transfer ltc <label> <adresse_dest> <montant>
    python transfer.py transfer doge <label> <adresse_dest> <montant>
    python transfer.py transfer bnb <label> <adresse_dest> <montant>
    python transfer.py transfer usdt <label> <adresse_dest> <montant>
    python transfer.py balance btc <label>   # Voir solde avant transfert
"""

import argparse
from decimal import Decimal, ROUND_DOWN
import gc
import hashlib
import json
import os
import sys
from pathlib import Path

import requests
from getpass import getpass as _getpass

from wallet_manager import WalletAuthError

from i18n import t, get_lang, set_lang
import security_core as _sec
from asset_catalog import asset_icon, network_icon, icon_column


def get_secret(prompt: str) -> str:
    """Lit un secret sans l'afficher (getpass en TTY, input sinon)."""
    try:
        return _getpass(prompt)
    except (EOFError, OSError):
        return input(prompt)


# ── Gestion de la mémoire (effacement des secrets après signature) ─────

_SECRET_KEYS = (
    "private_key_wif",
    "mnemonic",
    "private_key_hex",
    "private_key_base58",
    "private_key_bytes_hex",
    "private_spend_key",
    "private_view_key",
    "seed",
)


def _clear_wallet_secrets(wallet_info: dict | None) -> None:
    """Écrase et supprime les clés privées / mnémoniques du dictionnaire en mémoire."""
    if isinstance(wallet_info, dict):
        for k in _SECRET_KEYS:
            if k in wallet_info:
                wallet_info[k] = ""
                del wallet_info[k]
    gc.collect()


def _to_atomic(amount: Decimal | str | int | float, decimals: int) -> int:
    """Convertit un montant humain en unités atomiques via Decimal (sans erreur float)."""
    val = Decimal(str(amount))
    if val < 0:
        raise ValueError(f"Montant négatif interdit : {amount}")
    factor = Decimal(10) ** int(decimals)
    return int((val * factor).quantize(Decimal("1"), rounding=ROUND_DOWN))


def _from_atomic(raw: int, decimals: int) -> Decimal:
    """Convertit des unités atomiques en Decimal humain."""
    return Decimal(int(raw)) / (Decimal(10) ** int(decimals))


# ── Chiffrement du journal des transferts ──────────────────────────────
# Aucun historique sensible n'est écrit en clair. Depuis v1.4, chaque ligne
# du journal est AES-256-GCM + Argon2id (format KCW2), puis encodée Base64 afin
# de conserver un enregistrement par ligne. L'ancien format Fernet reste
# lisible uniquement pour migration.
from cryptography.fernet import Fernet as _Fernet
from cryptography.hazmat.primitives import hashes as _Hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _PBKDF2
import base64 as _b64

LOG_PASS = None
TX_CONTEXT = {}


def set_log_pass(pw: str):
    global LOG_PASS
    LOG_PASS = pw


def set_transaction_context(beneficiary=None, platform=None, beneficiary_network=None):
    global TX_CONTEXT
    TX_CONTEXT = {
        "beneficiary": beneficiary or None,
        "platform": platform or None,
        "beneficiary_network": beneficiary_network or None,
    }


def _log_salt_path():
    # Legacy only. New KCW2 records carry their own Argon2id salt.
    return Path(__file__).parent / "historique" / "transactions.salt.bin"


def _legacy_log_derive(pw: str, salt: bytes) -> bytes:
    kdf = _PBKDF2(algorithm=_Hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return _b64.urlsafe_b64encode(kdf.derive(pw.encode("utf-8")))


def _log_encrypt(line: str) -> bytes:
    if not LOG_PASS:
        raise RuntimeError("Master passphrase required: plaintext history is forbidden")
    raw = _sec.encrypt_bytes(line.encode("utf-8"), LOG_PASS)
    return _b64.urlsafe_b64encode(raw)


def _log_decrypt(token: bytes) -> str:
    if not LOG_PASS:
        raise RuntimeError("Master passphrase required")
    token = token.strip()
    # New v1.4: Base64(KCW2 binary envelope).
    try:
        raw = _b64.urlsafe_b64decode(token)
        if _sec.is_secure_blob(raw):
            return _sec.decrypt_bytes(raw, LOG_PASS).decode("utf-8")
    except Exception:
        pass
    # Legacy v1: Fernet token itself was stored one token per line.
    salt_path = _log_salt_path()
    if salt_path.exists():
        salt = salt_path.read_bytes()
        key = _legacy_log_derive(LOG_PASS, salt)
        return _Fernet(key).decrypt(token).decode("utf-8")
    raise ValueError("Unknown or corrupted encrypted history record")


def _append_encrypted_history(line: str) -> None:
    if not LOG_PASS:
        # Security invariant: direct CLI use without an unlocked vault must
        # never leave transaction metadata in plaintext.
        print("[!] Historique non enregistré : coffre non déverrouillé.", file=sys.stderr)
        return
    hist = Path(__file__).parent / "historique"
    hist.mkdir(parents=True, exist_ok=True)
    enc_file = hist / "transactions.log.enc"
    token = _log_encrypt(line.rstrip("\n"))
    with open(enc_file, "ab") as fh:
        fh.write(token + b"\n")
    os.chmod(enc_file, 0o600)


def log_transaction(network: str, label_src: str, dest: str,
                    amount: float, txid: str, url: str):
    """Journalise un transfert uniquement dans le journal chiffré."""
    from datetime import datetime as _dt
    now = _dt.now().isoformat()
    # Valeurs JSON-encodées individuellement pour garder un format textuel
    # parseable sans laisser de données en clair sur disque.
    def q(v):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    line = (
        f"{now} RESEAU={network.upper()} TYPE=SEND SOURCE={q(label_src)} "
        f"DEST={q(dest)} MONTANT={amount} TXID={q(txid)} URL={q(url)} "
        f"BENEFICIAIRE={q(TX_CONTEXT.get('beneficiary'))} "
        f"PLATEFORME={q(TX_CONTEXT.get('platform'))} "
        f"BENEF_RESEAU={q(TX_CONTEXT.get('beneficiary_network'))}"
    )
    try:
        _append_encrypted_history(line)
    except Exception as e:
        print(f"[!] Journalisation impossible : {e}", file=sys.stderr)


# ── Bitcoin ──
from local_keys import ephemeral_transfer_wallet

# ── Ethereum ──
from web3 import Web3
from eth_account import Account as EthAccount

# ── Solana ──
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import transfer as sol_transfer, TransferParams
from solders.transaction import Transaction as SolTx
from solders.message import Message
from solders.hash import Hash

# ── Import du déchiffrement depuis wallet_manager ──
import importlib.util
spec = importlib.util.spec_from_file_location(
    "wallet_manager",
    Path(__file__).parent / "wallet_manager.py"
)
wm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wm)
load_wallets = wm.load_wallets
WALLET_FILE = wm.WALLET_FILE


# ── RPC / API endpoints publics (HTTPS strict) ──
BTC_API_URL = "https://blockchain.info"
LTC_API_URL = "https://api.blockchair.com/litecoin"
DOGE_API_URL = "https://api.blockchair.com/dogecoin"
ETH_RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.mevblocker.io",
    "https://rpc.ankr.com/eth",
    "https://1rpc.io/eth",
    "https://eth.drpc.org",
]
BSC_RPC = "https://bsc-dataseed.binance.org/"
POLYGON_RPC = "https://polygon-bor-rpc.publicnode.com"
AVALANCHE_RPC = "https://api.avax.network/ext/bc/C/rpc"
ARBITRUM_RPC = "https://arb1.arbitrum.io/rpc"
OPTIMISM_RPC = "https://mainnet.optimism.io"
USDT_ETH_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC_ETH_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
DAI_ETH_CONTRACT = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
SOL_RPC_URL = "https://api.mainnet-beta.solana.com"

ZERO_EVM_ADDRESS = "0x0000000000000000000000000000000000000000"


# ── Récupération des clés privées depuis le wallet chiffré ─────────────

def get_private_key(label: str, passphrase: str) -> dict:
    """Récupère les infos d'un wallet depuis le fichier chiffré."""
    wallets = load_wallets(passphrase)
    if label not in wallets:
        print(f"[!] Wallet '{label}' introuvable.", file=sys.stderr)
        sys.exit(1)
    wallet = dict(wallets[label])
    if wallet.get("protected_secrets"):
        import security_access as _access
        phrase = _access.ask_wallet_credential(wallet, "signing a transfer")
        if not phrase:
            raise WalletAuthError("Advanced wallet passphrase required")
        unlocked = dict(wallet)
        unlocked.update(_access.unlock_wallet_secrets(wallet, phrase))
        del phrase
        return unlocked
    return wallet


# ── Validation cryptographique des adresses de destination ─────────────

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58_ALPHABET)}
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_MAP = {c: i for i, c in enumerate(_BECH32_CHARSET)}


def _b58check_decode(addr: str) -> bytes | None:
    """Décode une adresse Base58Check et vérifie son checksum double-SHA256 (4 octets)."""
    if not addr or not all(c in _B58_MAP for c in addr):
        return None
    num = 0
    for ch in addr:
        num = num * 58 + _B58_MAP[ch]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    leading_zeros = len(addr) - len(addr.lstrip("1"))
    full = (b"\x00" * leading_zeros) + raw
    if len(full) < 5:
        return None
    payload, checksum = full[:-4], full[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if digest != checksum:
        return None
    return payload


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_verify(addr: str, expected_hrp: str) -> bool:
    """Vérifie le HRP, la casse unique et le checksum Bech32/Bech32m (BIP-173 / BIP-350)."""
    if not addr or (addr != addr.lower() and addr != addr.upper()):
        return False
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data_part = a[:pos], a[pos + 1:]
    if hrp != expected_hrp:
        return False
    if not all(c in _BECH32_MAP for c in data_part):
        return False
    data = [_BECH32_MAP[c] for c in data_part]
    hrp_exp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    const = _bech32_polymod(hrp_exp + data)
    if const not in (1, 0x2BC830A3):
        return False
    witver = data[0]
    if witver > 16:
        return False
    # BIP-173 (v0 -> Bech32 == 1) / BIP-350 (v1+ -> Bech32m == 0x2bc830a3)
    if witver == 0 and const != 1:
        return False
    if witver != 0 and const != 0x2BC830A3:
        return False
    return True


def _validate_btc_address(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    a = addr.strip()
    if a.lower().startswith("bc1"):
        return _bech32_verify(a, "bc")
    if a.startswith(("1", "3")) and 26 <= len(a) <= 35:
        payload = _b58check_decode(a)
        return payload is not None and len(payload) == 21 and payload[0] in (0x00, 0x05)
    return False


def _validate_ltc_address(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    a = addr.strip()
    if a.lower().startswith("ltc1"):
        return _bech32_verify(a, "ltc")
    if a.startswith(("L", "M", "3")) and 26 <= len(a) <= 35:
        payload = _b58check_decode(a)
        return payload is not None and len(payload) == 21 and payload[0] in (0x30, 0x32, 0x05)
    return False


def _validate_doge_address(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    a = addr.strip()
    if a.startswith(("D", "9", "A")) and 26 <= len(a) <= 35:
        payload = _b58check_decode(a)
        return payload is not None and len(payload) == 21 and payload[0] in (0x1E, 0x16)
    return False


def _validate_evm_address(addr: str) -> bool:
    """Valide une adresse EVM : 0x + 40 hex, non nulle, et checksum EIP-55 strict si casse mixte."""
    if not isinstance(addr, str):
        return False
    a = addr.strip()
    if not (a.startswith("0x") and len(a) == 42):
        return False
    body = a[2:]
    if not all(c in "0123456789abcdefABCDEF" for c in body):
        return False
    if a.lower() == ZERO_EVM_ADDRESS:
        return False
    # Si l'adresse utilise une casse mixte, le checksum EIP-55 DOIT être valide.
    if body != body.lower() and body != body.upper():
        return Web3.is_checksum_address(a)
    return True


def _validate_sol_address(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    a = addr.strip()
    if not (32 <= len(a) <= 44 and all(c in _B58_MAP for c in a)):
        return False
    try:
        Pubkey.from_string(a)
        return True
    except Exception:
        return False


def _validate_trx_address(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    a = addr.strip()
    if not (a.startswith("T") and len(a) == 34):
        return False
    payload = _b58check_decode(a)
    return payload is not None and len(payload) == 21 and payload[0] == 0x41


def _validate_xmr_address(addr: str) -> bool:
    """Valide une adresse Monero mainnet via décodage Base58 par blocs (11 chars -> 8 octets),
    contrôle de l'octet réseau mainnet (18='4...', 42='8...', 19='4...' intégrée) et
    vérification du checksum Keccak-256 (4 derniers octets)."""
    from xmr_gateway import is_valid_xmr_address
    return is_valid_xmr_address(addr)


_ADDR_RULES = {
    "bitcoin":   _validate_btc_address,
    "btc":       _validate_btc_address,
    "litecoin":  _validate_ltc_address,
    "ltc":       _validate_ltc_address,
    "dogecoin":  _validate_doge_address,
    "doge":      _validate_doge_address,
    "ethereum":  _validate_evm_address,
    "eth":       _validate_evm_address,
    "bsc":       _validate_evm_address,
    "bnb":       _validate_evm_address,
    "polygon":   _validate_evm_address,
    "avalanche": _validate_evm_address,
    "arbitrum":  _validate_evm_address,
    "optimism":  _validate_evm_address,
    "usdt":      _validate_evm_address,
    "usdc":      _validate_evm_address,
    "dai":       _validate_evm_address,
    "solana":    _validate_sol_address,
    "sol":       _validate_sol_address,
    "tron":      _validate_trx_address,
    "trx":       _validate_trx_address,
    "ripple":    lambda a: (isinstance(a, str) and a.startswith("r") and 25 <= len(a) <= 35
                            and all(c in "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz" for c in a)),
    "cosmos":    lambda a: (isinstance(a, str) and a.startswith("cosmos1") and len(a) >= 39),
    "cardano":   lambda a: (isinstance(a, str) and a.startswith("addr1") and len(a) >= 50),
    "monero":    _validate_xmr_address,
    "xmr":       _validate_xmr_address,
}


def validate_address(network: str, address: str) -> bool:
    """Valide le format et le checksum (EIP-55, Base58Check, Bech32/Bech32m, Ed25519, XMR)
    d'une adresse de destination avant toute construction/signature de transaction."""
    if not isinstance(address, str) or not address.strip():
        return False
    net = (network or "").strip().lower()
    rule = _ADDR_RULES.get(net)
    if rule is None:
        return False
    return bool(rule(address.strip()))


# ── Séparation stricte des réseaux ──────────────────────────────────────

_NETWORK_ALIASES = {
    "btc": "bitcoin",
    "bitcoin": "bitcoin",
    "ltc": "litecoin",
    "litecoin": "litecoin",
    "doge": "dogecoin",
    "dogecoin": "dogecoin",
    "eth": "ethereum",
    "eth_ethereum": "ethereum",
    "erc20": "ethereum",
    "ethereum": "ethereum",
    "bnb": "bsc",
    "bep20": "bsc",
    "bsc": "bsc",
    "pol": "polygon",
    "matic": "polygon",
    "polygon": "polygon",
    "avax": "avalanche",
    "avalanche": "avalanche",
    "arb": "arbitrum",
    "arbitrum": "arbitrum",
    "op": "optimism",
    "optimism": "optimism",
    "sol": "solana",
    "spl": "solana",
    "solana": "solana",
    "xmr": "monero",
    "monero": "monero",
}


def _normalize_network(net: str | None) -> str:
    if not net:
        return ""
    key = str(net).strip().lower()
    return _NETWORK_ALIASES.get(key, key)


def _ensure_network_And_destination(
    expected_network: str,
    dest_address: str,
    wallet_info: dict | None = None,
    expected_asset_id: str | None = None,
) -> None:
    """Vérifie strictement :
    1) la validité et le checksum de l'adresse de destination pour `expected_network` ;
    2) que le wallet source appartient bien au réseau `expected_network` ;
    3) que le réseau du bénéficiaire (si présent dans TX_CONTEXT) correspond à `expected_network`."""
    canon_expected = _normalize_network(expected_network)
    if not validate_address(canon_expected, dest_address):
        print(
            t("send_addr_invalid", net=expected_network.upper(), dest=str(dest_address)[:24]),
            file=sys.stderr,
        )
        sys.exit(1)

    if wallet_info is not None:
        w_net = _normalize_network(wallet_info.get("network") or wallet_info.get("reseau"))
        if w_net and w_net != canon_expected:
            print(
                f"[!] Séparation des réseaux : le wallet source est sur '{w_net}', "
                f"impossible d'envoyer sur '{canon_expected}'.",
                file=sys.stderr,
            )
            sys.exit(1)
        if expected_asset_id and wallet_info.get("asset_id"):
            if wallet_info["asset_id"] != expected_asset_id:
                print(
                    f"[!] Le wallet source ({wallet_info['asset_id']}) ne correspond pas "
                    f"au couple actif/réseau choisi ({expected_asset_id}).",
                    file=sys.stderr,
                )
                sys.exit(1)

    benef_net = _normalize_network(TX_CONTEXT.get("beneficiary_network"))
    if benef_net and benef_net != canon_expected:
        print(
            f"[!] Séparation des réseaux : le bénéficiaire est enregistré sur '{benef_net}', "
            f"incompatible avec un envoi sur '{canon_expected}'.",
            file=sys.stderr,
        )
        sys.exit(1)


def _connect_evm_rpc(rpc_url: str, expected_chain_id: int, label: str) -> Web3:
    """Connecte Web3 en HTTPS avec timeout et vérifie que le chainId du RPC correspond."""
    if not str(rpc_url).startswith("https://"):
        print(f"[!] Sécurité TLS : RPC {label} non-HTTPS refusé ({rpc_url}).", file=sys.stderr)
        sys.exit(1)
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 15}))
    if not w3.is_connected():
        print(f"[!] Impossible de se connecter au RPC {label} : {rpc_url}", file=sys.stderr)
        sys.exit(1)
    try:
        actual_chain_id = int(w3.eth.chain_id)
    except Exception as e:
        print(f"[!] Impossible de vérifier le chainId du RPC {label} : {e}", file=sys.stderr)
        sys.exit(1)
    if actual_chain_id != int(expected_chain_id):
        print(
            f"[!] Mauvais réseau RPC {label} : chainId={actual_chain_id}, "
            f"attendu={expected_chain_id}. Transfert annulé.",
            file=sys.stderr,
        )
        sys.exit(1)
    return w3


# ── Validation commune : solde >= montant + frais ─────────────────────────

def check_balance_with_fee(balance, amount, fee, ticker):
    """
    Vérifie qu'un wallet possède assez de fonds pour couvrir le montant
    envoyé PLUS les frais réseau (balance >= amount + fee), dans une seule
    devise `ticker`. Affiche clairement le détail et annule (sys.exit(1))
    si les fonds sont insuffisants ou si l'estimation des frais a échoué.

    fee is None  -> estimation des frais impossible -> annulation.
    """
    if fee is None:
        print(t("send_fee_estim_fail", ticker=ticker), file=sys.stderr)
        sys.exit(1)
    if amount is None or Decimal(str(amount)) <= 0:
        print(f"[!] Montant invalide pour {ticker} : {amount}", file=sys.stderr)
        sys.exit(1)

    balance = Decimal(str(balance))
    amount = Decimal(str(amount))
    fee = Decimal(str(fee))

    total = amount + fee
    print(f"[*] Contrôle des fonds ({ticker}) :")
    print(f"    Solde disponible   : {balance} {ticker}")
    print(f"    Montant à envoyer  : {amount} {ticker}")
    print(f"    Frais réseau est.  : {fee} {ticker}")
    print(f"    Total nécessaire   : {total} {ticker}")
    if total > balance:
        manquant = total - balance
        print(t("send_funds_insuff", manquant=manquant, ticker=ticker,
                 balance=balance, total=total), file=sys.stderr)
        sys.exit(1)
    print(f"[✓] Fonds suffisants ({ticker}).")
    return True


def check_erc20_funds(token_balance, amount, token_ticker,
                      native_balance, gas_fee, native_ticker):
    """
    Vérifie un transfert de token ERC-20 (ou équivalent) :
      - solde du token >= montant à envoyer
      - solde de la monnaie native (ETH/BNB...) >= frais de gas estimés
    Deux devises distinctes -> deux contrôles séparés.
    Annule (sys.exit(1)) en cas d'insuffisance ou d'estimation de gas impossible.
    """
    if gas_fee is None:
        print(t("send_fee_estim_fail", ticker=token_ticker), file=sys.stderr)
        sys.exit(1)
    if amount is None or Decimal(str(amount)) <= 0:
        print(f"[!] Montant invalide pour {token_ticker} : {amount}",
              file=sys.stderr)
        sys.exit(1)
    token_balance_d = Decimal(str(token_balance))
    amount_d = Decimal(str(amount))
    native_balance_d = Decimal(str(native_balance))
    gas_fee_d = Decimal(str(gas_fee))

    print(f"[*] Contrôle des fonds ({asset_icon(token_ticker)} {token_ticker} / "
          f"{asset_icon(native_ticker)} {native_ticker}) :")
    print(f"    {icon_column(asset_icon(token_ticker))} Solde {token_ticker:<6} : "
          f"{token_balance_d} {token_ticker}")
    print(f"    Montant à envoyer  : {amount_d} {token_ticker}")
    print(f"    {icon_column(asset_icon(native_ticker))} Solde {native_ticker:<6} : "
          f"{native_balance_d} {native_ticker} "
          f"(pour le gas)")
    print(f"    Frais de gas est.  : {gas_fee_d} {native_ticker}")
    if amount_d > token_balance_d:
        print(t("send_balance_insuff", tk=token_ticker, balance=token_balance_d,
                 amount=amount_d), file=sys.stderr)
        sys.exit(1)
    if gas_fee_d > native_balance_d:
        print(t("send_gas_insuff", nt=native_ticker, balance=native_balance_d,
                 fee=gas_fee_d), file=sys.stderr)
        sys.exit(1)
    print(f"[✓] Fonds suffisants ({token_ticker} + gas {native_ticker}).")
    return True


# ── Confirmation utilisateur OBLIGATOIRE avant tout broadcast ────────────

def _confirm_send(network: str, dest: str, amount, amount_ticker: str,
                  fee, fee_ticker: str):
    """
    Demande une confirmation explicite ('OUI' / 'O' / 'Y' / 'YES') avant de
    signer et diffuser une transaction RÉELLE et IRRÉVERSIBLE. Annule
    (sys.exit(0)) si la réponse n'est pas une confirmation.
    À placer APRÈS le contrôle de fonds et AVANT la signature/broadcast.
    """
    print("\n" + "─" * 56)
    print(f"  ⚠️  CONFIRMATION D'ENVOI — "
          f"{asset_icon(amount_ticker)} {network.upper()}")
    print(f"  Destination   : {dest}")
    print(f"  Montant       : {asset_icon(amount_ticker)} {amount} {amount_ticker}")
    if fee_ticker != amount_ticker:
        print(f"  Frais réseau  : {asset_icon(fee_ticker)} {fee} {fee_ticker} (monnaie native)")
        print(f"  → {amount} {amount_ticker} + frais {fee} {fee_ticker}")
    else:
        total = Decimal(str(amount)) + Decimal(str(fee))
        print(f"  Frais réseau  : {fee} {amount_ticker}")
        print(f"  TOTAL requis  : {total} {amount_ticker}")
    print("─" * 56)
    rep = input("  Taper 'OUI' pour confirmer l'envoi "
                "(toute autre réponse = annulation) : ").strip().upper()
    if rep not in ("OUI", "O", "Y", "YES"):
        print("[!] Envoi annulé par l'utilisateur (aucune transaction diffusée).")
        sys.exit(0)
    print("[*] Confirmation reçue — poursuite de la signature...")


# ── TRANSFERT BITCOIN ───────────────────────────────────────────────────

def _fetch_btc_balance_sat(addr: str) -> int:
    """Récupère le solde BTC en satoshis avec fallback mempool.space -> blockstream.info -> blockchain.info."""
    last_error = None
    for url in (
        f"https://mempool.space/api/address/{addr}",
        f"https://blockstream.info/api/address/{addr}",
    ):
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            data = r.json()
            chain = data["chain_stats"]
            mempool = data.get("mempool_stats") or {}
            return int(
                (chain["funded_txo_sum"] - chain["spent_txo_sum"])
                + (mempool.get("funded_txo_sum", 0) - mempool.get("spent_txo_sum", 0))
            )
        except Exception as e:
            last_error = e
            continue
    try:
        r = requests.get(f"{BTC_API_URL}/balance?active={addr}", timeout=15)
        r.raise_for_status()
        data = r.json()
        return int(data[addr]["final_balance"])
    except Exception as e:
        last_error = e
    try:
        r = requests.get(
            f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance",
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict) or "final_balance" not in data:
            raise ValueError("Invalid blockcypher response")
        return int(data["final_balance"])
    except Exception as e:
        last_error = e
        raise last_error


def transfer_btc(label: str, dest_address: str, amount_btc: float, passphrase: str):
    """
    Envoie du Bitcoin.
    Utilise bitcoinlib pour construire et signer la transaction (sans broadcast),
    vérifie le solde + frais et demande confirmation, puis broadcast via blockchain.info.
    """
    wallet_info = None
    wif = ""
    mnemonic = ""
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination("bitcoin", dest_address, wallet_info)
        wif = wallet_info["private_key_wif"]
        mnemonic = wallet_info.get("mnemonic", "")

        addr = wallet_info["address"]
        print(f"[*] Vérification du solde pour {addr}...")
        try:
            balance_sat = _fetch_btc_balance_sat(addr)
            balance_btc = _from_atomic(balance_sat, 8)
            print(f"[*] Solde : {balance_btc:.8f} BTC")
        except Exception as e:
            print(f"[!] Impossible de récupérer le solde : {e}", file=sys.stderr)
            print("[!] Transfert annulé : solde non vérifiable.", file=sys.stderr)
            sys.exit(1)

        if amount_btc < 0:
            print(f"[!] Montant invalide : {amount_btc} BTC", file=sys.stderr)
            sys.exit(1)

        # Estimer les fees dynamiquement (taux réseau réel)
        try:
            try:
                fee_resp = requests.get(
                    "https://mempool.space/api/v1/fees/recommended", timeout=15
                )
                fee_resp.raise_for_status()
                fee_rate = max(1, int(fee_resp.json()["halfHourFee"]))
            except Exception:
                fee_resp = requests.get(f"{BTC_API_URL}/q/estimatesmartfee/3", timeout=15)
                fee_resp.raise_for_status()
                fee_btc_kb = float(fee_resp.text)
                fee_rate = max(1, int(fee_btc_kb * 1e8 / 1024))  # sat/byte
            print(f"[*] Fee estimé : {fee_rate} sat/byte")
        except Exception as e:
            print(f"[!] Estimation des frais impossible : {e}", file=sys.stderr)
            print("[!] Transfert annulé : frais non estimables.", file=sys.stderr)
            sys.exit(1)

        with ephemeral_transfer_wallet(
            witness_type="segwit",
            keys=wif if wallet_info.get("address_records") else (mnemonic if mnemonic else wif),
            scheme="single" if wallet_info.get("address_records") else "bip32",
            network="bitcoin",
        ) as w:
            w.utxos_update(networks="bitcoin", update_balance=True, rescan_all=True)
            if not w.utxos(min_confirms=1):
                print("[!] Aucun UTXO confirmé trouvé pour ce wallet BTC.", file=sys.stderr)
                sys.exit(1)

            if Decimal(str(amount_btc)) == 0:
                # Max send : estimer la taille d'une transaction standard P2WPKH (~140 vB)
                est_fee_sat = max(200, fee_rate * 140)
                if balance_sat <= est_fee_sat:
                    print("[!] Solde BTC insuffisant pour couvrir les frais réseau.", file=sys.stderr)
                    sys.exit(1)
                send_sat = balance_sat - est_fee_sat
                amount_dec = _from_atomic(send_sat, 8)
            else:
                send_sat = _to_atomic(amount_btc, 8)
                amount_dec = _from_atomic(send_sat, 8)

            tx = w.send_to(
                to_address=dest_address,
                amount=send_sat,
                fee=fee_rate,
                broadcast=False,
            )
            fee_sat = getattr(tx, "fee", None)
            if fee_sat is None:
                print("[!] Frais de transaction indéterminables : transfert annulé.",
                      file=sys.stderr)
                sys.exit(1)
            fee_btc = _from_atomic(fee_sat, 8)

            # Vérification stricte : solde >= montant + frais (avant broadcast)
            check_balance_with_fee(balance_btc, amount_dec, fee_btc, "BTC")
            _confirm_send("btc", dest_address, amount_dec, "BTC", fee_btc, "BTC")

            tx_hex = tx.raw_hex()
            print(f"[*] Transaction hex : {tx_hex[:64]}...")

            print("[*] Broadcast de la transaction...")
            try:
                txid = _broadcast_utxo_tx("bitcoin", tx_hex)
                print(f"✅ Transaction broadcastée ! TXID : {txid}")
                print(f"   https://mempool.space/tx/{txid}")
                log_transaction("btc", label, dest_address, float(amount_dec), txid,
                                f"https://mempool.space/tx/{txid}")
            except Exception as e:
                print(f"[!] Erreur broadcast : {e}", file=sys.stderr)
    finally:
        wif = ""
        mnemonic = ""
        _clear_wallet_secrets(wallet_info)


def _broadcast_utxo_tx(network: str, tx_hex: str) -> str:
    """Diffuse une transaction brute signée (BTC, LTC, DOGE) avec repli multi-fournisseurs."""
    errors = []
    net = network.lower()

    if net == "bitcoin":
        for es_url in ("https://mempool.space/api/tx", "https://blockstream.info/api/tx"):
            try:
                r = requests.post(
                    es_url,
                    data=tx_hex,
                    headers={"Content-Type": "text/plain"},
                    timeout=30,
                )
                if r.status_code == 200 and r.text.strip():
                    return r.text.strip()
                errors.append(f"{es_url}: HTTP {r.status_code} ({r.text[:120]})")
            except Exception as exc:
                errors.append(f"{es_url}: {exc}")
        try:
            r = requests.post(
                f"{BTC_API_URL}/pushtx",
                data={"tx": tx_hex},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
            if r.status_code == 200 and r.text.strip():
                return r.text.strip()
            errors.append(f"blockchain.info: HTTP {r.status_code} ({r.text[:120]})")
        except Exception as exc:
            errors.append(f"blockchain.info: {exc}")
        try:
            r = requests.post(
                "https://api.blockcypher.com/v1/btc/main/txs/push",
                json={"tx": tx_hex},
                timeout=30,
            )
            if r.status_code in (200, 201):
                body = r.json()
                txid = (body.get("tx") or {}).get("hash") or body.get("hash")
                if txid:
                    return str(txid).strip()
            errors.append(f"blockcypher: HTTP {r.status_code} ({r.text[:120]})")
        except Exception as exc:
            errors.append(f"blockcypher: {exc}")

    elif net == "litecoin":
        # 1) litecoinspace.org (Esplora Litecoin Foundation, sans clé et sans limite stricte)
        try:
            r = requests.post(
                "https://litecoinspace.org/api/tx",
                data=tx_hex,
                headers={"Content-Type": "text/plain"},
                timeout=30,
            )
            if r.status_code == 200 and r.text.strip():
                return r.text.strip()
            errors.append(f"litecoinspace.org: HTTP {r.status_code} ({r.text[:120]})")
        except Exception as exc:
            errors.append(f"litecoinspace.org: {exc}")

        # 2) BlockCypher LTC
        try:
            r = requests.post(
                "https://api.blockcypher.com/v1/ltc/main/txs/push",
                json={"tx": tx_hex},
                timeout=30,
            )
            if r.status_code in (200, 201):
                body = r.json()
                txid = (body.get("tx") or {}).get("hash") or body.get("hash")
                if txid:
                    return str(txid).strip()
            errors.append(f"blockcypher: HTTP {r.status_code} ({r.text[:120]})")
        except Exception as exc:
            errors.append(f"blockcypher: {exc}")

        # 3) Blockchair LTC
        try:
            r = requests.post(
                f"{LTC_API_URL}/push/transaction",
                data={"data": tx_hex},
                timeout=30,
            )
            if r.status_code == 200:
                txid = (r.json().get("data") or {}).get("tx_hash") or r.text.strip()
                if txid:
                    return str(txid).strip()
            errors.append(f"blockchair: HTTP {r.status_code} ({r.text[:120]})")
        except Exception as exc:
            errors.append(f"blockchair: {exc}")

    elif net == "dogecoin":
        # 1) BlockCypher DOGE
        try:
            r = requests.post(
                "https://api.blockcypher.com/v1/doge/main/txs/push",
                json={"tx": tx_hex},
                timeout=30,
            )
            if r.status_code in (200, 201):
                body = r.json()
                txid = (body.get("tx") or {}).get("hash") or body.get("hash")
                if txid:
                    return str(txid).strip()
            errors.append(f"blockcypher: HTTP {r.status_code} ({r.text[:120]})")
        except Exception as exc:
            errors.append(f"blockcypher: {exc}")

        # 2) Blockchair DOGE
        try:
            r = requests.post(
                f"{DOGE_API_URL}/push/transaction",
                data={"data": tx_hex},
                timeout=30,
            )
            if r.status_code == 200:
                txid = (r.json().get("data") or {}).get("tx_hash") or r.text.strip()
                if txid:
                    return str(txid).strip()
            errors.append(f"blockchair: HTTP {r.status_code} ({r.text[:120]})")
        except Exception as exc:
            errors.append(f"blockchair: {exc}")

    # Repli final via les fournisseurs configurés dans bitcoinlib
    try:
        from bitcoinlib.services.services import Service
        srv = Service(network=net)
        res = srv.sendrawtransaction(tx_hex)
        txid = res.get("txid") if isinstance(res, dict) else str(res or "").strip()
        if txid:
            return str(txid).strip()
    except Exception as exc:
        errors.append(f"bitcoinlib.Service: {exc}")

    raise RuntimeError(" ; ".join(errors) if errors else f"Broadcast {net} impossible")


# ── TRANSFERT LITECOIN / DOGECOIN ─────────────────────────────────────

def _read_btc_like_balance_litoshis(network: str, address: str) -> int:
    """Lit un solde confirmé; si Blockchair ne le confirme pas, essaie BlockCypher."""
    configs = {
        "litecoin": (LTC_API_URL, "ltc"),
        "dogecoin": (DOGE_API_URL, "doge"),
    }
    if network not in configs:
        raise ValueError(f"Réseau UTXO non pris en charge : {network}")
    api, blockcypher_coin = configs[network]
    primary_error = None

    try:
        response = requests.get(f"{api}/dashboards/address/{address}", timeout=15)
        response.raise_for_status()
        data = response.json()
        entry = (data.get("data") or {}).get(address)
        if entry and entry[0].get("balance") is not None:
            return int(entry[0]["balance"])
        primary_error = "adresse absente de la réponse Blockchair"
    except Exception as exc:
        primary_error = str(exc)

    try:
        url = (f"https://api.blockcypher.com/v1/{blockcypher_coin}/main/"
               f"addrs/{address}/balance")
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        payload = response.json()
        if payload.get("final_balance") is None:
            raise ValueError("champ final_balance absent de la réponse BlockCypher")
        return int(payload["final_balance"])
    except Exception as exc:
        bcy_error = exc

    if network == "litecoin":
        try:
            r = requests.get(f"https://litecoinspace.org/api/address/{address}", timeout=15)
            r.raise_for_status()
            data = r.json()
            chain = data["chain_stats"]
            mempool = data.get("mempool_stats") or {}
            return int(
                (chain["funded_txo_sum"] - chain["spent_txo_sum"])
                + (mempool.get("funded_txo_sum", 0) - mempool.get("spent_txo_sum", 0))
            )
        except Exception:
            pass

    raise RuntimeError(
        f"Solde {network} indisponible (Blockchair : {primary_error}; "
        f"BlockCypher : {bcy_error})"
    )


def transfer_btc_like(label: str, dest_address: str, amount: float,
                      passphrase: str, network: str, witness: str):
    """Transfert générique Bitcoin-like (LTC ou DOGE) via bitcoinlib."""
    wallet_info = None
    wif = ""
    mnemonic = ""
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination(network, dest_address, wallet_info)
        wif = wallet_info["private_key_wif"]
        mnemonic = wallet_info.get("mnemonic", "")

        addr = wallet_info["address"]
        print(f"[*] Vérification du solde pour {addr}...")
        try:
            balance_litoshis = _read_btc_like_balance_litoshis(network, addr)
            bal = _from_atomic(balance_litoshis, 8)
            print(f"[*] Solde : {bal:.8f} {network.upper()}")
        except Exception as e:
            print(f"[!] Solde indisponible : {e}", file=sys.stderr)
            print(f"[!] Transfert {network.upper()} annulé : solde non vérifiable.",
                  file=sys.stderr)
            sys.exit(1)

        if amount < 0:
            print(f"[!] Montant invalide : {amount} {network.upper()}",
                  file=sys.stderr)
            sys.exit(1)

        try:
            with ephemeral_transfer_wallet(
                witness_type=witness,
                keys=wif if wallet_info.get("address_records") else (mnemonic if mnemonic else wif),
                scheme="single" if wallet_info.get("address_records") else "bip32",
                network=network,
            ) as w:
                w.utxos_update(networks=network, update_balance=True, rescan_all=True)
                if not w.utxos(min_confirms=1):
                    raise RuntimeError(
                        "Aucun UTXO confirmé trouvé pour la clé dérivée du wallet source"
                    )
                if Decimal(str(amount)) == 0:
                    # Estimation préalable des frais sur un petit envoi pour calculer le max send
                    probe_tx = w.send_to(
                        to_address=dest_address,
                        amount=max(1000, balance_litoshis // 2),
                        fee="normal",
                        broadcast=False,
                    )
                    probe_fee = int(getattr(probe_tx, "fee", 0) or 0)
                    if probe_fee <= 0 or balance_litoshis <= probe_fee:
                        raise RuntimeError("Solde insuffisant pour couvrir les frais réseau.")
                    send_atomic = balance_litoshis - probe_fee
                else:
                    send_atomic = _to_atomic(amount, 8)

                amount_dec = _from_atomic(send_atomic, 8)
                tx = w.send_to(
                    to_address=dest_address,
                    amount=send_atomic,
                    fee="normal",
                    broadcast=False,
                )
                fee_sat = getattr(tx, "fee", None)
                if fee_sat is None:
                    print(f"[!] Frais de transaction {network.upper()} indéterminables : "
                          f"transfert annulé.", file=sys.stderr)
                    sys.exit(1)
                fee_native = _from_atomic(fee_sat, 8)

                check_balance_with_fee(bal, amount_dec, fee_native, network.upper())
                _confirm_send(network, dest_address, amount_dec, network.upper(),
                              fee_native, network.upper())
                tx_hex = tx.raw_hex()
                print(f"[*] Transaction hex : {tx_hex[:64]}...")

                print("[*] Broadcast de la transaction...")
                try:
                    txid = _broadcast_utxo_tx(network, tx_hex)
                    print(f"✅ Transaction broadcastée ! TXID : {txid}")
                    explorer = (
                        "https://litecoinspace.org/tx/"
                        if network == "litecoin"
                        else "https://blockchair.com/dogecoin/transactions/"
                    )
                    print(f"   {explorer}{txid}")
                    log_transaction(
                        network,
                        label,
                        dest_address,
                        float(amount_dec),
                        txid,
                        f"{explorer}{txid}",
                    )
                except Exception as e:
                    print(f"[!] Erreur broadcast : {e}", file=sys.stderr)
        except Exception as e:
            print(f"[!] Création ou estimation de la transaction impossible : {e}",
                  file=sys.stderr)
            print(f"[!] Transfert {network.upper()} annulé.", file=sys.stderr)
            sys.exit(1)
    finally:
        wif = ""
        mnemonic = ""
        _clear_wallet_secrets(wallet_info)


def transfer_ltc(label, dest, amount, passphrase):
    transfer_btc_like(label, dest, amount, passphrase, "litecoin", "segwit")


def transfer_doge(label, dest, amount, passphrase):
    transfer_btc_like(label, dest, amount, passphrase, "dogecoin", "legacy")


# ── TRANSFERT ETHEREUM ──────────────────────────────────────────────────

def get_working_eth_rpc() -> str:
    """Teste les RPC Ethereum HTTPS et retourne le premier qui répond sur chainId=1."""
    for rpc in ETH_RPCS:
        if not rpc.startswith("https://"):
            continue
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 5}))
            if w3.is_connected() and int(w3.eth.chain_id) == 1:
                return rpc
        except Exception:
            continue
    return ETH_RPCS[0]


def transfer_eth(label: str, dest_address: str, amount_eth: float, passphrase: str):
    """Envoie de l'Ethereum (ETH) sur Ethereum Mainnet (chainId 1)."""
    wallet_info = None
    private_key_hex = ""
    signed_tx = None
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination("ethereum", dest_address, wallet_info)
        private_key_hex = wallet_info["private_key_hex"]
        from_address = Web3.to_checksum_address(wallet_info["address"])
        target_address = Web3.to_checksum_address(dest_address)

        rpc_url = get_working_eth_rpc()
        w3 = _connect_evm_rpc(rpc_url, 1, "ETH")
        print(f"[*] Connecté au RPC Ethereum via {rpc_url} (block {w3.eth.block_number})")

        balance_wei = int(w3.eth.get_balance(from_address))
        balance_eth = _from_atomic(balance_wei, 18)
        print(f"[*] Solde : {balance_eth:.6f} ETH")

        if amount_eth < 0:
            print(f"[!] Montant invalide : {amount_eth} ETH", file=sys.stderr)
            sys.exit(1)

        nonce = w3.eth.get_transaction_count(from_address, "pending")
        gas_price = int(w3.eth.gas_price)
        gas_limit = 21000
        fee_wei = gas_price * gas_limit
        fee_eth = _from_atomic(fee_wei, 18)

        if Decimal(str(amount_eth)) == 0:
            if balance_wei <= fee_wei:
                print("[!] Solde ETH insuffisant pour couvrir les frais de gas.", file=sys.stderr)
                sys.exit(1)
            amount_wei = balance_wei - fee_wei
            amount_dec = _from_atomic(amount_wei, 18)
            print(f"[*] Envoi de la totalité (moins gas) : {amount_dec} ETH")
        else:
            amount_wei = _to_atomic(amount_eth, 18)
            amount_dec = _from_atomic(amount_wei, 18)

        check_balance_with_fee(balance_eth, amount_dec, fee_eth, "ETH")
        _confirm_send("eth", target_address, amount_dec, "ETH", fee_eth, "ETH")

        tx = {
            "nonce": nonce,
            "to": target_address,
            "value": amount_wei,
            "gas": gas_limit,
            "gasPrice": gas_price,
            "chainId": 1,
        }

        signed_tx = EthAccount.sign_transaction(tx, private_key_hex)
        tx_hex = signed_tx.raw_transaction.hex()

        print("[*] Transaction signée. Broadcast...")
        try:
            tx_hash = w3.eth.send_raw_transaction(tx_hex)
            print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
            print(f"   https://etherscan.io/tx/{tx_hash.hex()}")
            log_transaction("eth", label, target_address, float(amount_dec), tx_hash.hex(),
                            f"https://etherscan.io/tx/{tx_hash.hex()}")
        except Exception as e:
            print(f"[!] Erreur broadcast : {e}", file=sys.stderr)
    finally:
        private_key_hex = ""
        del signed_tx
        _clear_wallet_secrets(wallet_info)


# ── TRANSFERT BNB (BSC, EVM) ──────────────────────────────────────────

def transfer_bnb(label: str, dest_address: str, amount_bnb: float, passphrase: str):
    """Envoie du BNB sur BSC (chaîne EVM, chainId 56)."""
    wallet_info = None
    private_key_hex = ""
    signed_tx = None
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination("bsc", dest_address, wallet_info)
        private_key_hex = wallet_info["private_key_hex"]
        from_address = Web3.to_checksum_address(wallet_info["address"])
        target_address = Web3.to_checksum_address(dest_address)

        w3 = _connect_evm_rpc(BSC_RPC, 56, "BSC")
        print(f"[*] Connecté au RPC BSC (block {w3.eth.block_number})")

        balance_wei = int(w3.eth.get_balance(from_address))
        balance_bnb = _from_atomic(balance_wei, 18)
        print(f"[*] Solde : {balance_bnb:.6f} BNB")

        if amount_bnb < 0:
            print(f"[!] Montant invalide : {amount_bnb} BNB", file=sys.stderr)
            sys.exit(1)

        nonce = w3.eth.get_transaction_count(from_address, "pending")
        gas_price = int(w3.eth.gas_price)
        gas_limit = 21000
        fee_wei = gas_price * gas_limit
        fee_bnb = _from_atomic(fee_wei, 18)

        if Decimal(str(amount_bnb)) == 0:
            if balance_wei <= fee_wei:
                print("[!] Solde BNB insuffisant pour couvrir les frais de gas.", file=sys.stderr)
                sys.exit(1)
            amount_wei = balance_wei - fee_wei
            amount_dec = _from_atomic(amount_wei, 18)
            print(f"[*] Envoi de la totalité (moins gas) : {amount_dec} BNB")
        else:
            amount_wei = _to_atomic(amount_bnb, 18)
            amount_dec = _from_atomic(amount_wei, 18)

        check_balance_with_fee(balance_bnb, amount_dec, fee_bnb, "BNB")
        _confirm_send("bnb", target_address, amount_dec, "BNB", fee_bnb, "BNB")

        tx = {
            "nonce": nonce,
            "to": target_address,
            "value": amount_wei,
            "gas": gas_limit,
            "gasPrice": gas_price,
            "chainId": 56,
        }
        signed_tx = EthAccount.sign_transaction(tx, private_key_hex)
        tx_hex = signed_tx.raw_transaction.hex()
        print("[*] Transaction signée. Broadcast...")
        try:
            tx_hash = w3.eth.send_raw_transaction(tx_hex)
            print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
            print(f"   https://bscscan.com/tx/{tx_hash.hex()}")
            log_transaction("bnb", label, target_address, float(amount_dec), tx_hash.hex(),
                            f"https://bscscan.com/tx/{tx_hash.hex()}")
        except Exception as e:
            print(f"[!] Erreur broadcast : {e}", file=sys.stderr)
    finally:
        private_key_hex = ""
        del signed_tx
        _clear_wallet_secrets(wallet_info)


# ── TRANSFERT USDT (ERC-20, EVM) ─────────────────────────────────────

def transfer_usdt(label: str, dest_address: str, amount_usdt: float, passphrase: str):
    """Envoie des USDT (token ERC-20) sur Ethereum mainnet (chainId 1)."""
    _transfer_erc20(
        label, dest_address, amount_usdt, passphrase,
        USDT_ETH_CONTRACT, 6, "USDT", "https://etherscan.io/tx/"
    )


# ── TRANSFERT EVM (Polygon, Avalanche, Arbitrum, Optimism) ──────────────

def _transfer_evm_native(label, dest, amount, passphrase, rpc_url, chain_id, symbol, explorer,
                         network_key=None):
    """Transfert de la crypto native d'une chaîne EVM (POL/AVAX/ETH-Arbitrum/ETH-Optimism)."""
    wallet_info = None
    private_key_hex = ""
    signed = None
    net_name = network_key or symbol.lower()
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination(net_name, dest, wallet_info)
        private_key_hex = wallet_info["private_key_hex"]
        from_address = Web3.to_checksum_address(wallet_info["address"])
        target_address = Web3.to_checksum_address(dest)

        w3 = _connect_evm_rpc(rpc_url, chain_id, symbol)
        print(f"[*] Connecté au RPC {symbol} (block {w3.eth.block_number})")
        balance_wei = int(w3.eth.get_balance(from_address))
        balance = _from_atomic(balance_wei, 18)
        print(f"[*] Solde : {balance:.6f} {symbol}")

        if amount < 0:
            print(f"[!] Montant invalide : {amount} {symbol}", file=sys.stderr)
            sys.exit(1)

        nonce = w3.eth.get_transaction_count(from_address, "pending")
        gas_price = int(w3.eth.gas_price)
        gas_limit = 21000
        fee_wei = gas_price * gas_limit
        fee_sym = _from_atomic(fee_wei, 18)

        if Decimal(str(amount)) == 0:
            if balance_wei <= fee_wei:
                print(f"[!] Solde {symbol} insuffisant pour couvrir les frais de gas.",
                      file=sys.stderr)
                sys.exit(1)
            amount_wei = balance_wei - fee_wei
            amount_dec = _from_atomic(amount_wei, 18)
            print(f"[*] Envoi de la totalité (moins gas) : {amount_dec} {symbol}")
        else:
            amount_wei = _to_atomic(amount, 18)
            amount_dec = _from_atomic(amount_wei, 18)

        check_balance_with_fee(balance, amount_dec, fee_sym, symbol)
        _confirm_send(net_name, target_address, amount_dec, symbol, fee_sym, symbol)

        tx = {
            "nonce": nonce, "to": target_address, "value": amount_wei,
            "gas": gas_limit, "gasPrice": gas_price, "chainId": chain_id,
        }
        signed = EthAccount.sign_transaction(tx, private_key_hex)
        tx_hex = signed.raw_transaction.hex()
        print("[*] Transaction signée. Broadcast...")
        try:
            tx_hash = w3.eth.send_raw_transaction(tx_hex)
            print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
            print(f"   {explorer}{tx_hash.hex()}")
            log_transaction(net_name, label, target_address, float(amount_dec), tx_hash.hex(),
                            f"{explorer}{tx_hash.hex()}")
        except Exception as e:
            print(f"[!] Erreur broadcast : {e}", file=sys.stderr)
    finally:
        private_key_hex = ""
        del signed
        _clear_wallet_secrets(wallet_info)


def transfer_polygon(label, dest, amount, passphrase):
    _transfer_evm_native(label, dest, amount, passphrase, POLYGON_RPC, 137, "POL",
                         "https://polygonscan.com/tx/", network_key="polygon")


def transfer_avalanche(label, dest, amount, passphrase):
    _transfer_evm_native(label, dest, amount, passphrase, AVALANCHE_RPC, 43114, "AVAX",
                         "https://snowtrace.io/tx/", network_key="avalanche")


def transfer_arbitrum(label, dest, amount, passphrase):
    _transfer_evm_native(label, dest, amount, passphrase, ARBITRUM_RPC, 42161, "ETH",
                         "https://arbiscan.io/tx/", network_key="arbitrum")


def transfer_optimism(label, dest, amount, passphrase):
    _transfer_evm_native(label, dest, amount, passphrase, OPTIMISM_RPC, 10, "ETH",
                         "https://optimistic.etherscan.io/tx/", network_key="optimism")


# ── TRANSFERT ERC-20 (USDT, USDC, DAI) ─────────────────────────────────

def _transfer_erc20(label, dest, amount, passphrase, contract, decimals, symbol, explorer):
    """Transfert d'un token ERC-20 (USDT, USDC, DAI) sur Ethereum mainnet (chainId 1)."""
    wallet_info = None
    private_key_hex = ""
    signed = None
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination("ethereum", dest, wallet_info)
        private_key_hex = wallet_info["private_key_hex"]
        from_address = Web3.to_checksum_address(wallet_info["address"])
        target_address = Web3.to_checksum_address(dest)
        contract_address = Web3.to_checksum_address(contract)

        rpc_url = get_working_eth_rpc()
        w3 = _connect_evm_rpc(rpc_url, 1, f"ETH/{symbol}")
        print(f"[*] Connecté via {rpc_url} (block {w3.eth.block_number})")

        addr_padded = from_address[2:].lower().rjust(64, "0")
        bal_resp = w3.eth.call({"to": contract_address,
                                "data": "0x70a08231" + addr_padded})
        raw_balance = int(bal_resp.hex(), 16)
        balance = _from_atomic(raw_balance, decimals)
        print(f"[*] Solde {symbol} : {balance:.6f}")

        if amount < 0:
            print(f"[!] Montant invalide : {amount} {symbol}", file=sys.stderr)
            sys.exit(1)

        if Decimal(str(amount)) == 0:
            if raw_balance <= 0:
                print(f"[!] Solde {symbol} nul : aucun jeton à envoyer.", file=sys.stderr)
                sys.exit(1)
            amount_raw = raw_balance
        else:
            amount_raw = _to_atomic(amount, decimals)

        amount_dec = _from_atomic(amount_raw, decimals)

        # Encodage sécurisé de transfer(address, uint256) après validation EIP-55
        dest_padded = target_address[2:].lower().rjust(64, "0")
        data = "0xa9059cbb" + dest_padded + hex(amount_raw)[2:].rjust(64, "0")

        nonce = w3.eth.get_transaction_count(from_address, "pending")
        gas_price = int(w3.eth.gas_price)
        try:
            est_gas = w3.eth.estimate_gas({
                "from": from_address,
                "to": contract_address,
                "value": 0,
                "data": data,
            })
            gas_limit = max(65000, int(est_gas * 1.2))
        except Exception:
            gas_limit = 65000

        fee_eth = _from_atomic(gas_price * gas_limit, 18)

        native_balance_wei = int(w3.eth.get_balance(from_address))
        native_balance_eth = _from_atomic(native_balance_wei, 18)

        check_erc20_funds(balance, amount_dec, symbol,
                          native_balance_eth, fee_eth, "ETH")
        _confirm_send(symbol.lower(), target_address, amount_dec, symbol, fee_eth, "ETH")

        tx = {
            "nonce": nonce, "to": contract_address, "value": 0,
            "gas": gas_limit, "gasPrice": gas_price, "chainId": 1, "data": data,
        }
        signed = EthAccount.sign_transaction(tx, private_key_hex)
        tx_hex = signed.raw_transaction.hex()
        print("[*] Transaction signée. Broadcast...")
        try:
            tx_hash = w3.eth.send_raw_transaction(tx_hex)
            print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
            print(f"   {explorer}{tx_hash.hex()}")
            log_transaction(symbol.lower(), label, target_address, float(amount_dec), tx_hash.hex(),
                            f"{explorer}{tx_hash.hex()}")
        except Exception as e:
            print(f"[!] Erreur broadcast : {e}", file=sys.stderr)
    finally:
        private_key_hex = ""
        del signed
        _clear_wallet_secrets(wallet_info)


def transfer_usdc(label, dest, amount, passphrase):
    _transfer_erc20(label, dest, amount, passphrase, USDC_ETH_CONTRACT, 6, "USDC",
                    "https://etherscan.io/tx/")


def transfer_dai(label, dest, amount, passphrase):
    _transfer_erc20(label, dest, amount, passphrase, DAI_ETH_CONTRACT, 18, "DAI",
                    "https://etherscan.io/tx/")


def transfer_catalog_evm_token(label, dest, amount, passphrase, asset_id, spec):
    """Transfère un ERC-20/BEP-20 défini dans ``asset_catalog``.

    Le réseau, le chainId, le contrat et l'actif de gas viennent tous de la
    même entrée : impossible de signer un USDT-BSC avec le chainId Ethereum.
    """
    chains = {
        "ethereum": (None, 1, "ETH", "https://etherscan.io/tx/"),
        "bsc": (BSC_RPC, 56, "BNB", "https://bscscan.com/tx/"),
        "polygon": (POLYGON_RPC, 137, "POL", "https://polygonscan.com/tx/"),
    }
    network = spec["network"]
    if network not in chains:
        raise ValueError(f"Réseau EVM non configuré : {network}")
    rpc_url, chain_id, gas_symbol, explorer = chains[network]
    if rpc_url is None:
        rpc_url = get_working_eth_rpc()

    wallet_info = None
    private_key = ""
    signed = None
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination(network, dest, wallet_info, expected_asset_id=asset_id)
        w3 = _connect_evm_rpc(rpc_url, chain_id, f"{asset_id} ({network})")

        private_key = wallet_info["private_key_hex"]
        source = Web3.to_checksum_address(wallet_info["address"])
        target = Web3.to_checksum_address(dest)
        contract = Web3.to_checksum_address(spec["contract"])
        decimals = int(spec["decimals"])
        symbol = spec["asset"]

        source_padded = source[2:].lower().rjust(64, "0")
        raw_balance_bytes = w3.eth.call({"to": contract, "data": "0x70a08231" + source_padded})
        raw_balance = int(raw_balance_bytes.hex(), 16)
        token_balance = _from_atomic(raw_balance, decimals)
        if amount < 0:
            raise ValueError(f"Montant invalide : {amount} {symbol}")

        if Decimal(str(amount)) == 0:
            if raw_balance <= 0:
                raise ValueError(f"Solde {symbol} nul sur {network}.")
            raw_amount = raw_balance
        else:
            raw_amount = _to_atomic(amount, decimals)

        amount_dec = _from_atomic(raw_amount, decimals)
        target_padded = target[2:].lower().rjust(64, "0")
        data = "0xa9059cbb" + target_padded + hex(raw_amount)[2:].rjust(64, "0")
        nonce = w3.eth.get_transaction_count(source, "pending")
        gas_price = int(w3.eth.gas_price)
        estimate_tx = {"from": source, "to": contract, "value": 0, "data": data}
        gas_limit = int(w3.eth.estimate_gas(estimate_tx) * 1.2)
        fee = _from_atomic(gas_price * gas_limit, 18)
        native_balance = _from_atomic(int(w3.eth.get_balance(source)), 18)

        check_erc20_funds(token_balance, amount_dec, symbol, native_balance, fee, gas_symbol)
        _confirm_send(asset_id, target, amount_dec, symbol, fee, gas_symbol)

        tx = {"nonce": nonce, "to": contract, "value": 0, "gas": gas_limit,
              "gasPrice": gas_price, "chainId": chain_id, "data": data}
        signed = EthAccount.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        txid = tx_hash.hex()
        print(f"✅ Transaction broadcastée ! TXID : {txid}")
        print(f"   {explorer}{txid}")
        log_transaction(asset_id, label, target, float(amount_dec), txid, f"{explorer}{txid}")
    finally:
        private_key = ""
        del signed
        _clear_wallet_secrets(wallet_info)


# ── Non-EVM (XRP, TRX, ATOM, ADA) : transfert non supporté depuis cet outil ──

def _unsupported_transfer(network, symbol):
    print(f"[!] Transfert {symbol} ({network}) non supporté par cet outil.")
    print(f"    Génération de wallet + lecture de solde : OK.")
    print(f"    Envoi (broadcast) : nécessite une librairie native ({symbol}) "
          f"non buildable sur Python 3.14 (coincurve/cbor2).")
    print(f"    Utilisez un wallet dédié (ex: XUMM pour XRP, TronLink pour TRX, ")
    print(f"    Keplr pour ATOM, Daedalus/Yoroi pour ADA) pour les envois.")
    sys.exit(1)


def transfer_xrp(label, dest, amount, passphrase):
    _unsupported_transfer("ripple", "XRP")


def transfer_trx(label, dest, amount, passphrase):
    _unsupported_transfer("tron", "TRX")


def transfer_atom(label, dest, amount, passphrase):
    _unsupported_transfer("cosmos", "ATOM")


def transfer_ada(label, dest, amount, passphrase):
    _unsupported_transfer("cardano", "ADA")


def transfer_xmr_from_seed(mnemonic: str, dest: str, amount: float,
                           label: str = "XMR",
                           address: str = "",
                           spend_key: str = "",
                           view_key: str = ""):
    """Transfert Monero (XMR) EN MODE NON-CUSTODIAL depuis un seed 25 mots
    ou les clés spend/view.

    Permet de transférer sans wallets.enc : l'utilisateur fournit son
    mnémonique (export papier) ou ses clés spend/view, le wallet est restauré
    temporairement dans la passerelle, la tx est signée + diffusée, puis le
    wallet est fermé et le serveur le supprime (tmpfs + cleanup). Aucun seed
    ne persiste.
    """
    import xmr_gateway as xgw

    _ensure_network_And_destination("monero", dest)

    print("[*] Connexion à la passerelle XMR (via Tor)…")
    try:
        ver = xgw.get_version()
        print(f"[✓] Passerelle XMR jointe (version {ver.get('version')}).")

        wallet_name = f"ccw_{label}"
        xgw.open_or_restore_wallet(
            wallet_name,
            mnemonic=mnemonic,
            address=address,
            spend_key=spend_key,
            view_key=view_key,
        )
        print(f"[✓] Wallet restauré côté passerelle ({wallet_name}).")

        bal = xgw.get_balance()
        unlocked = _from_atomic(int(bal.get("unlocked_balance", 0)), 12)
        total = _from_atomic(int(bal.get("balance", 0)), 12)
        print(f"[*] Solde XMR : total {total:.12f} / débloqué {unlocked:.12f}")

        XMR_MIN_FEE = Decimal("0.0001")
        amt_dec = Decimal(str(amount))
        if amt_dec == 0:
            if unlocked <= XMR_MIN_FEE:
                print("[!] Solde XMR débloqué insuffisant pour un envoi total.", file=sys.stderr)
                sys.exit(1)
            send_dec = unlocked - XMR_MIN_FEE
            check_balance_with_fee(unlocked, send_dec, XMR_MIN_FEE, "XMR")
            _confirm_send("xmr", dest, send_dec, "XMR", XMR_MIN_FEE, "XMR")
            res = xgw.sweep_all(dest)
        else:
            check_balance_with_fee(unlocked, amt_dec, XMR_MIN_FEE, "XMR")
            _confirm_send("xmr", dest, amt_dec, "XMR", XMR_MIN_FEE, "XMR")
            send_dec = amt_dec
            res = xgw.transfer(dest, send_dec)

        tx_hashes = res.get("tx_hash_list") or [res.get("tx_hash")]
        for h in tx_hashes:
            print(f"[✓] Transaction diffusée. TX hash : {h}")
            log_transaction("xmr", label, dest, float(send_dec), h,
                            f"onion://{xgw.GATEWAY_ONION}:{xgw.GATEWAY_PORT}")
    except Exception as e:
        print(f"[!] Échec du transfert XMR : {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        mnemonic = ""
        spend_key = ""
        view_key = ""
        del mnemonic, spend_key, view_key
        gc.collect()
        try:
            xgw.close_wallet()
        except Exception:
            pass


def transfer_xmr(label: str, dest: str, amount: float, passphrase: str):
    """Transfert Monero (XMR) depuis un wallet stocké dans wallets.enc via la passerelle Tor."""
    wallet_info = None
    mnemonic = ""
    spend_key = ""
    view_key = ""
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination("monero", dest, wallet_info)
        mnemonic = wallet_info.get("mnemonic", "")
        spend_key = wallet_info.get("private_spend_key", "")
        view_key = wallet_info.get("private_view_key", "")
        addr = wallet_info.get("address", "")
        if not mnemonic and not (spend_key and view_key and addr):
            print("[!] Ce wallet Monero n'a ni mnémonique 25 mots ni clés spend/view : "
                  "impossible de le restaurer côté passerelle.", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Wallet XMR '{label}' chargé (adresse: {addr}).")
        transfer_xmr_from_seed(
            mnemonic,
            dest,
            amount,
            label=label,
            address=addr,
            spend_key=spend_key,
            view_key=view_key,
        )
    finally:
        mnemonic = ""
        spend_key = ""
        view_key = ""
        _clear_wallet_secrets(wallet_info)


# ── TRANSFERT SOLANA ────────────────────────────────────────────────────

def transfer_sol(label: str, dest_address: str, amount_sol: float, passphrase: str):
    """
    Envoie des SOL sur Solana via JSON-RPC. Utilise solders pour signer.
    """
    wallet_info = None
    raw_str = ""
    keypair = None
    try:
        wallet_info = get_private_key(label, passphrase)
        _ensure_network_And_destination("solana", dest_address, wallet_info)
        raw_key = wallet_info["private_key_base58"]

        raw_str = str(raw_key)
        if raw_str.startswith("b'") and raw_str.endswith("'"):
            raw_str = raw_str[2:-1]
        elif raw_str.startswith('b"') and raw_str.endswith('"'):
            raw_str = raw_str[2:-1]
        raw_str = raw_str.strip()

        print("[*] Clé parsée, création du keypair...")

        try:
            keypair = Keypair.from_base58_string(raw_str)
        except Exception:
            try:
                key_bytes = bytes(map(int, raw_str.strip("[]").replace(" ", "").split(",")))
                keypair = Keypair.from_bytes(key_bytes)
            except Exception:
                print("[!] Impossible de reconstruire la clé privée Solana.", file=sys.stderr)
                sys.exit(1)

        pubkey = keypair.pubkey()
        dest_pubkey = Pubkey.from_string(dest_address.strip())

        def rpc(method, params):
            resp = requests.post(SOL_RPC_URL, json={"jsonrpc": "2.0", "id": 1,
                                                    "method": method, "params": params}, timeout=15)
            resp.raise_for_status()
            return resp.json()

        try:
            bal = rpc("getBalance", [str(pubkey)])
            balance_lamports = int(bal["result"]["value"])
            balance_sol = _from_atomic(balance_lamports, 9)
            print(f"[*] Solde : {balance_sol:.9f} SOL")
        except Exception as e:
            print(f"[!] Impossible de récupérer le solde : {e}", file=sys.stderr)
            sys.exit(1)

        if amount_sol < 0:
            print(f"[!] Montant invalide : {amount_sol} SOL", file=sys.stderr)
            sys.exit(1)

        FEE_LAMPORTS = 5000
        try:
            rent_resp = rpc("getMinimumBalanceForRentExemption", [0])
            RENT_EXEMPT_LAMPORTS = int(rent_resp["result"])
        except Exception:
            RENT_EXEMPT_LAMPORTS = 890880
        RESERVE_LAMPORTS = RENT_EXEMPT_LAMPORTS + FEE_LAMPORTS

        if Decimal(str(amount_sol)) == 0:
            if balance_lamports <= RESERVE_LAMPORTS:
                print(f"[!] Solde insuffisant pour couvrir le rent-exempt "
                      f"({RENT_EXEMPT_LAMPORTS} lamports) + frais "
                      f"({FEE_LAMPORTS} lamports).", file=sys.stderr)
                sys.exit(1)
            amount_lamports = balance_lamports - RESERVE_LAMPORTS
            amount_dec = _from_atomic(amount_lamports, 9)
            print(f"[*] Envoi de la totalité (moins réserve) : {amount_dec:.9f} SOL")
            print(f"    (réserve conservée : {RENT_EXEMPT_LAMPORTS} lamports "
                  f"rent-exempt + {FEE_LAMPORTS} lamports frais)")
        else:
            amount_lamports = _to_atomic(amount_sol, 9)
            amount_dec = _from_atomic(amount_lamports, 9)
            if (balance_lamports - amount_lamports) < RESERVE_LAMPORTS:
                print(f"[!] Le compte tomberait sous le minimum rent-exempt "
                      f"({RENT_EXEMPT_LAMPORTS} lamports) + frais. "
                      f"Montant max envoiable : "
                      f"{_from_atomic(max(0, balance_lamports - RESERVE_LAMPORTS), 9):.9f} SOL.",
                      file=sys.stderr)
                sys.exit(1)

        fee_sol = _from_atomic(FEE_LAMPORTS, 9)
        check_balance_with_fee(balance_sol, amount_dec, fee_sol, "SOL")
        _confirm_send("sol", dest_address.strip(), amount_dec, "SOL", fee_sol, "SOL")

        try:
            bh = rpc("getLatestBlockhash", [])
            recent_blockhash = Hash.from_string(bh["result"]["value"]["blockhash"])
        except Exception as e:
            print(f"[!] Erreur blockhash : {e}", file=sys.stderr)
            sys.exit(1)

        ix = sol_transfer(TransferParams(
            from_pubkey=pubkey, to_pubkey=dest_pubkey, lamports=amount_lamports))
        msg = Message.new_with_blockhash([ix], pubkey, recent_blockhash)
        tx = SolTx.new_unsigned(msg)
        tx.sign([keypair], recent_blockhash)
        tx_bytes = bytes(tx)
        tx_b64 = _b64.b64encode(tx_bytes).decode()

        print("[*] Broadcast de la transaction...")
        try:
            result = rpc("sendTransaction", [tx_b64, {"encoding": "base64"}])
            if "result" in result:
                sig = result["result"]
                print(f"✅ Transaction broadcastée ! Signature : {sig}")
                print(f"   https://explorer.solana.com/tx/{sig}")
                log_transaction("sol", label, dest_address.strip(), float(amount_dec), sig,
                                f"https://explorer.solana.com/tx/{sig}")
            else:
                print(f"[!] Erreur broadcast : {result.get('error')}", file=sys.stderr)
        except Exception as e:
            print(f"[!] Erreur broadcast : {e}", file=sys.stderr)
    finally:
        raw_str = ""
        del keypair
        _clear_wallet_secrets(wallet_info)


# ── SCAN DES RÉCEPTIONS SOLANA (transactions entrantes) ────────────────

def scan_sol_received(label: str, passphrase: str, limit: int = 25):
    """Interroge l'API Solana pour les transactions entrantes du wallet."""
    from datetime import datetime as _dt, timezone as _tz

    wallet_info = get_private_key(label, passphrase)
    address = wallet_info["address"]
    _clear_wallet_secrets(wallet_info)

    def rpc(method, params):
        resp = requests.post(SOL_RPC_URL, json={"jsonrpc": "2.0", "id": 1,
                                                "method": method, "params": params},
                             timeout=15)
        return resp.json()

    try:
        sig_resp = rpc("getSignaturesForAddress",
                       [address, {"limit": limit}])
        sigs = sig_resp.get("result", [])
    except Exception as e:
        print(f"[!] Erreur getSignaturesForAddress : {e}", file=sys.stderr)
        return []

    results = []
    for entry in sigs:
        sig = entry.get("signature")
        if not sig:
            continue
        try:
            tx_resp = rpc("getTransaction",
                          [sig, {"encoding": "jsonParsed",
                                 "maxSupportedTransactionVersion": 0}])
            tx = tx_resp.get("result")
            if not tx:
                continue
            block_time = tx.get("blockTime")
            ts = (_dt.fromtimestamp(block_time, tz=_tz.utc)
                  .strftime("%Y-%m-%d %H:%M:%S")
                  if block_time else "inconnue")
            meta = tx.get("meta", {})
            pre = meta.get("preBalances", [])
            post = meta.get("postBalances", [])
            account_keys = (tx.get("transaction", {})
                            .get("message", {})
                            .get("accountKeys", []))
            keys = []
            for k in account_keys:
                if isinstance(k, dict):
                    keys.append(k.get("pubkey"))
                else:
                    keys.append(k)
            if not keys or len(pre) != len(post) or address not in keys:
                continue
            idx = keys.index(address)
            delta = (post[idx] - pre[idx]) / 1e9
            if delta <= 0:
                continue
            sender = None
            for i, (a, b) in enumerate(zip(pre, post)):
                if i != idx and (b - a) < 0:
                    sender = keys[i]
                    break
            if sender is None:
                sender = "inconnu"
            results.append({
                "signature": sig,
                "sender": sender,
                "receiver": address,
                "amount_sol": delta,
                "datetime": ts,
                "url": f"https://explorer.solana.com/tx/{sig}",
            })
        except Exception as e:
            print(f"[!] Erreur getTransaction ({sig}) : {e}", file=sys.stderr)
            continue
    return results


def log_received(network: str, label: str, sender: str, receiver: str,
                 amount: float, txid: str, when: str, url: str):
    """Journalise une réception uniquement dans le journal chiffré."""
    from datetime import datetime as _dt
    stamp = when or _dt.now().isoformat()
    def q(v):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    line = (
        f"{stamp} REÇU {network.upper()} WALLET={q(label)} "
        f"EXPEDITEUR={q(sender)} DESTINATAIRE={q(receiver)} "
        f"MONTANT={amount} TXID={q(txid)} URL={q(url)}"
    )
    try:
        _append_encrypted_history(line)
    except Exception as e:
        print(f"[!] Journalisation impossible : {e}", file=sys.stderr)


# ── BALANCE (lecture seule) ────────────────────────────────────────────

def check_balance(network: str, label: str, passphrase: str):
    """Affiche le solde d'un wallet sans envoyer de fonds."""
    wallet_info = get_private_key(label, passphrase)
    address = wallet_info["address"]
    _clear_wallet_secrets(wallet_info)

    if network == "btc":
        try:
            balance = _fetch_btc_balance_sat(address) / 1e8
            print(f"[*] {label} ({address}) : {balance:.8f} BTC")
        except Exception as e:
            print(f"[!] Erreur BTC : {e}", file=sys.stderr)

    elif network == "eth":
        rpc_url = get_working_eth_rpc()
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 15}))
        if w3.is_connected():
            balance = w3.from_wei(
                w3.eth.get_balance(Web3.to_checksum_address(address)), "ether"
            )
            print(f"[*] {label} ({address}) : {balance:.6f} ETH")
        else:
            print("[!] RPC non joignable")

    elif network == "sol":
        try:
            resp = requests.post(
                SOL_RPC_URL,
                json={"jsonrpc": "2.0", "id": 1, "method": "getBalance",
                      "params": [address]},
                timeout=15,
            )
            balance = resp.json().get("result", {}).get("value", 0) / 1e9
            print(f"[*] {label} ({address}) : {balance:.9f} SOL")
        except Exception as e:
            print(f"[!] Erreur Solana : {e}", file=sys.stderr)

    elif network in ("ltc", "doge"):
        sym = "LTC" if network == "ltc" else "DOGE"
        internal_network = "litecoin" if network == "ltc" else "dogecoin"
        try:
            bal = _read_btc_like_balance_litoshis(internal_network, address) / 1e8
            print(f"[*] {label} ({address}) : {bal:.8f} {sym}")
        except Exception as e:
            print(f"[!] Erreur {network} : {e}", file=sys.stderr)

    elif network == "bnb":
        try:
            w3 = Web3(Web3.HTTPProvider(BSC_RPC, request_kwargs={"timeout": 15}))
            bal = w3.from_wei(w3.eth.get_balance(Web3.to_checksum_address(address)), "ether")
            print(f"[*] {label} ({address}) : {bal:.6f} BNB")
        except Exception as e:
            print(f"[!] Erreur BNB : {e}", file=sys.stderr)

    elif network in ("polygon", "avalanche", "arbitrum", "optimism"):
        rpcs = {"polygon": POLYGON_RPC, "avalanche": AVALANCHE_RPC,
                "arbitrum": ARBITRUM_RPC, "optimism": OPTIMISM_RPC}
        syms = {"polygon": "POL", "avalanche": "AVAX",
                "arbitrum": "ETH", "optimism": "ETH"}
        try:
            w3 = Web3(Web3.HTTPProvider(rpcs[network], request_kwargs={"timeout": 15}))
            bal = w3.from_wei(w3.eth.get_balance(Web3.to_checksum_address(address)), "ether")
            print(f"[*] {label} ({address}) : {bal:.6f} {syms[network]}")
        except Exception as e:
            print(f"[!] Erreur {network} : {e}", file=sys.stderr)

    elif network in ("xrp", "trx", "atom", "ada"):
        syms = {"xrp": "XRP", "trx": "TRX", "atom": "ATOM", "ada": "ADA"}
        print(f"[*] Solde {syms[network]} : utilisez 'python balance.py {network} {label}' "
              f"(lecture via API publique).")

    elif network == "xmr":
        try:
            import xmr_gateway as xgw
            w_full = get_private_key(label, passphrase)
            try:
                b = xgw.get_wallet_balance_xmr(w_full, label=label)
                print(f"[*] {label} ({address}) : total {b['total']:.12f} XMR / "
                      f"débloqué {b['unlocked']:.12f} XMR")
            finally:
                _clear_wallet_secrets(w_full)
        except Exception as e:
            print(f"[!] Erreur XMR : {e}", file=sys.stderr)


# ── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Effectuer des transferts depuis les wallets locaux"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # transfer
    p_t = subparsers.add_parser("transfer", help="Effectuer un transfert")
    p_t.add_argument("network", choices=["btc", "eth", "sol", "ltc", "doge", "bnb", "usdt",
                                         "polygon", "avalanche", "arbitrum", "optimism",
                                         "usdc", "dai", "xrp", "trx", "atom", "ada", "xmr"])
    p_t.add_argument("label", help="Étiquette du wallet source")
    p_t.add_argument("dest", help="Adresse de destination")
    p_t.add_argument("amount", type=float, help="Montant à envoyer (0 = tout le solde)")

    # balance
    p_b = subparsers.add_parser("balance", help="Vérifier le solde")
    p_b.add_argument("network", choices=["btc", "eth", "sol", "ltc", "doge", "bnb", "usdt",
                                         "polygon", "avalanche", "arbitrum", "optimism",
                                         "usdc", "dai", "xrp", "trx", "atom", "ada", "xmr"])
    p_b.add_argument("label", help="Étiquette du wallet")

    args = parser.parse_args()

    passphrase = get_secret("🔑 Phrase de passe du fichier wallet : ")

    if args.command == "transfer":
        if args.network == "btc":
            transfer_btc(args.label, args.dest, args.amount, passphrase)
        elif args.network == "eth":
            transfer_eth(args.label, args.dest, args.amount, passphrase)
        elif args.network == "sol":
            transfer_sol(args.label, args.dest, args.amount, passphrase)
        elif args.network == "ltc":
            transfer_ltc(args.label, args.dest, args.amount, passphrase)
        elif args.network == "doge":
            transfer_doge(args.label, args.dest, args.amount, passphrase)
        elif args.network == "bnb":
            transfer_bnb(args.label, args.dest, args.amount, passphrase)
        elif args.network == "usdt":
            transfer_usdt(args.label, args.dest, args.amount, passphrase)
        elif args.network == "polygon":
            transfer_polygon(args.label, args.dest, args.amount, passphrase)
        elif args.network == "avalanche":
            transfer_avalanche(args.label, args.dest, args.amount, passphrase)
        elif args.network == "arbitrum":
            transfer_arbitrum(args.label, args.dest, args.amount, passphrase)
        elif args.network == "optimism":
            transfer_optimism(args.label, args.dest, args.amount, passphrase)
        elif args.network == "usdc":
            transfer_usdc(args.label, args.dest, args.amount, passphrase)
        elif args.network == "dai":
            transfer_dai(args.label, args.dest, args.amount, passphrase)
        elif args.network == "xrp":
            transfer_xrp(args.label, args.dest, args.amount, passphrase)
        elif args.network == "trx":
            transfer_trx(args.label, args.dest, args.amount, passphrase)
        elif args.network == "atom":
            transfer_atom(args.label, args.dest, args.amount, passphrase)
        elif args.network == "ada":
            transfer_ada(args.label, args.dest, args.amount, passphrase)
        elif args.network == "xmr":
            transfer_xmr(args.label, args.dest, args.amount, passphrase)

    elif args.command == "balance":
        check_balance(args.network, args.label, passphrase)


if __name__ == "__main__":
    main()
