#!/usr/bin/env python3
"""
xmr_gateway.py — Client léger vers la passerelle monero-wallet-rpc (XMR).

La passerelle tourne sur la VM Debian (service monero-wallet-rpc), exposée
uniquement via un service onion Tor. Ce client s'y connecte à travers le
SOCKS Tor local (127.0.0.1:9050), avec une auth HTTP Digest.

Aucun broadcast n'est fait en direct depuis l'outil : tout passe par la
passerelle, qui est la seule à toucher le réseau Monero (elle-même 100%
routée via Tor côté serveur).

Endpoints RPC utilisés (monero-wallet-rpc) :
  - open_wallet / restore_wallet_from_keys / create_wallet
  - get_balance
  - transfer / sweep_all (création + broadcast)
  - get_version
"""

from decimal import Decimal, ROUND_DOWN
import gc
import hmac
import json
import os
import socket

try:
    import socks  # PySocks
except ImportError:  # pragma: no cover
    socks = None

import requests
from requests.auth import HTTPDigestAuth

# ── Configuration de la passerelle ──────────────────────────────────────
# L'adresse onion est l'identifiant PUBLIC du service (peut être versionnée).
# Le mot de passe RPC se configure de 3 façons (dans l'ordre) :
#   1) variable d'environnement XMR_GATEWAY_PASS
#   2) fichier gateway.conf à côté de ce script (une ligne : le mot de passe)
#   3) saisie interactive au moment du transfert (si rien n'est configuré)
# Le mot de passe n'est JAMAIS en clair dans ce fichier.
GATEWAY_ONION = os.environ.get(
    "XMR_GATEWAY_ONION",
    "5oeulmq6ctcjczlyt6jnzwgmr6g5bmcqcflnu76hvo5bupw3beoqusad.onion")
GATEWAY_PORT = 18083
GATEWAY_USER = os.environ.get("XMR_GATEWAY_USER", "xmrgw")

# Fichier de config local (à remplir par l'utilisateur) : une seule ligne
# contenant le mot de passe RPC. À ne pas partager / ne pas publier.
_CONF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "gateway.conf")

# SOCKS Tor local utilisé pour atteindre l'onion (socks5h = DNS résolu via Tor).
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_SOCKS_URI = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"


# ── Keccak-256 original (pré-NIST, padding 0x01) & Base58 Monero par blocs ──

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58_ALPHABET)}
_XMR_ENC_BLOCK_SIZES = {0: 0, 1: 2, 2: 3, 3: 5, 4: 6, 5: 7, 6: 9, 7: 10, 8: 11}
_XMR_DEC_BLOCK_SIZES = {v: k for k, v in _XMR_ENC_BLOCK_SIZES.items()}


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def keccak_256(data: bytes) -> bytes:
    """Calcule le condensat Keccak-256 (standard Monero / Ethereum, padding 0x01)."""
    rate = 136
    state = [0] * 25
    buf = bytearray(data)
    buf.append(0x01)
    while len(buf) % rate != 0:
        buf.append(0x00)
    buf[-1] ^= 0x80
    for off in range(0, len(buf), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(buf[off + i * 8 : off + (i + 1) * 8], "little")
        for r in range(24):
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] ^= d[x]
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], _KECCAK_ROT[x][y])
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
            state[0] ^= _KECCAK_RC[r]
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def xmr_base58_decode(addr: str) -> bytes | None:
    """Décode une chaîne Base58 par blocs de 8 octets / 11 caractères (spécifique Monero)."""
    if not isinstance(addr, str) or not addr:
        return None
    s = addr.strip()
    if not all(c in _B58_MAP for c in s):
        return None
    full_blocks = len(s) // 11
    rem = len(s) % 11
    if rem not in _XMR_DEC_BLOCK_SIZES:
        return None
    out = bytearray()
    total_blocks = full_blocks + (1 if rem else 0)
    for i in range(total_blocks):
        chunk = s[i * 11 : i * 11 + 11] if i < full_blocks else s[full_blocks * 11 :]
        byte_len = 8 if i < full_blocks else _XMR_DEC_BLOCK_SIZES[rem]
        val = 0
        for ch in chunk:
            val = val * 58 + _B58_MAP[ch]
        if val >= (1 << (8 * byte_len)):
            return None
        out.extend(val.to_bytes(byte_len, "big"))
    return bytes(out)


def xmr_base58_encode(data: bytes) -> str:
    """Encode des octets en Base58 par blocs de 8 octets / 11 caractères (spécifique Monero)."""
    full_blocks = len(data) // 8
    rem = len(data) % 8
    out = []
    total_blocks = full_blocks + (1 if rem else 0)
    for i in range(total_blocks):
        chunk = data[i * 8 : i * 8 + 8] if i < full_blocks else data[full_blocks * 8 :]
        char_len = 11 if i < full_blocks else _XMR_ENC_BLOCK_SIZES[rem]
        val = int.from_bytes(chunk, "big")
        chars = []
        for _ in range(char_len):
            val, r = divmod(val, 58)
            chars.append(_B58_ALPHABET[r])
        out.append("".join(reversed(chars)))
    return "".join(out)


def encode_xmr_address(pub_spend: bytes, pub_view: bytes, net_byte: int = 18,
                       payment_id: bytes | None = None) -> str:
    """Construit une adresse Monero valide avec checksum Keccak-256 (4 octets)."""
    if len(pub_spend) != 32 or len(pub_view) != 32:
        raise ValueError("Les clés publiques Monero spend/view doivent faire 32 octets.")
    payload = bytes([net_byte]) + pub_spend + pub_view + (payment_id or b"")
    checksum = keccak_256(payload)[:4]
    return xmr_base58_encode(payload + checksum)


def is_valid_xmr_address(address: str) -> bool:
    """Valide une adresse Monero mainnet par décodage Base58 par blocs,
    vérification de l'octet réseau mainnet (18='4...', 42='8...', 19='4...' intégrée)
    et vérification du checksum Keccak-256 sur 4 octets."""
    if not isinstance(address, str):
        return False
    addr = address.strip()
    if len(addr) not in (95, 106):
        return False
    raw = xmr_base58_decode(addr)
    if raw is None:
        return False
    if len(addr) == 95:
        # 1 octet réseau + 32 spend + 32 view + 4 checksum = 69 octets
        if len(raw) != 69 or raw[0] not in (18, 42):
            return False
    else:
        # 1 octet réseau (19) + 32 spend + 32 view + 8 payment_id + 4 checksum = 77 octets
        if len(raw) != 77 or raw[0] != 19:
            return False
    expected_chk = keccak_256(raw[:-4])[:4]
    return hmac.compare_digest(raw[-4:], expected_chk)


def _xmr_to_piconero(amount_xmr: Decimal | str | int | float) -> int:
    """Convertit un montant XMR en piconero (10^12) via Decimal sans perte float."""
    val = Decimal(str(amount_xmr))
    if val <= 0:
        raise ValueError("Le montant XMR doit être strictement positif.")
    return int((val * Decimal(10**12)).quantize(Decimal("1"), rounding=ROUND_DOWN))


def _ensure_secure_conf_permissions(path: str) -> None:
    """Applique les permissions 0600 sur gateway.conf s'il existe."""
    try:
        if os.path.exists(path):
            mode = os.stat(path).st_mode & 0o777
            if mode != 0o600:
                os.chmod(path, 0o600)
    except OSError:
        pass


def is_tor_configured() -> bool:
    """Indique si Tor est configuré via gateway.conf ou variable d'environnement."""
    if os.environ.get("XMR_GATEWAY_PASS") or os.environ.get("XMR_GATEWAY_ONION"):
        return True
    if os.path.exists(_CONF_PATH):
        _ensure_secure_conf_permissions(_CONF_PATH)
        try:
            with open(_CONF_PATH, "r", encoding="utf-8") as fh:
                for ln in fh:
                    s = ln.strip()
                    if s and not s.startswith("#"):
                        return True
        except OSError:
            pass
    return False


def get_tor_proxies() -> dict[str, str]:
    """Renvoie le dictionnaire de proxies requests pour forcer socks5h (DNS via Tor)."""
    return {"http": TOR_SOCKS_URI, "https": TOR_SOCKS_URI}


def _load_pass() -> str:
    """Récupère le mot de passe RPC : env > gateway.conf > saisie interactive.

    gateway.conf accepte deux formats :
      - une seule ligne : le mot de passe (login par défaut 'xmrgw')
      - ou deux lignes  user=...  et  pass=...
    """
    env_pass = os.environ.get("XMR_GATEWAY_PASS", "").strip()
    if env_pass:
        return env_pass
    global GATEWAY_USER, GATEWAY_ONION
    # 2) fichier gateway.conf
    if os.path.exists(_CONF_PATH):
        _ensure_secure_conf_permissions(_CONF_PATH)
        try:
            with open(_CONF_PATH, "r", encoding="utf-8") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()
                         and not ln.strip().startswith("#")]
            if lines:
                onion_line = next((ln for ln in lines if ln.startswith("onion=")), None)
                if onion_line:
                    GATEWAY_ONION = onion_line.split("=", 1)[1].strip()
                user_line = next((ln for ln in lines if ln.startswith("user=")), None)
                pass_line = next((ln for ln in lines if ln.startswith("pass=")), None)
                if pass_line:
                    if user_line:
                        GATEWAY_USER = user_line.split("=", 1)[1].strip()
                    return pass_line.split("=", 1)[1].strip()
                non_kv = [ln for ln in lines if "=" not in ln]
                if non_kv:
                    return non_kv[0]
        except OSError:
            pass
    # 3) saisie interactive (getpass : ne s'affiche pas à l'écran)
    import getpass
    try:
        return getpass.getpass(
            "  Mot de passe de la passerelle XMR (donné par l'émetteur) : ").strip()
    except (EOFError, OSError):
        return ""


# Chargé paresseusement au premier usage (pour permettre la saisie interactive).
GATEWAY_PASS = None


def _check_cfg():
    global GATEWAY_PASS
    if GATEWAY_PASS is None:
        GATEWAY_PASS = _load_pass()
    if not GATEWAY_PASS:
        raise RuntimeError(
            "Mot de passe de la passerelle XMR introuvable. Renseignez-le dans "
            "gateway.conf ou exportez XMR_GATEWAY_PASS.")


def _make_session() -> requests.Session:
    """Session requests routée via Tor (SOCKS) + auth Digest.

    On utilise 'socks5h://' (et non 'socks5://') : le 'h' force la résolution
    DNS à travers le proxy Tor, indispensable pour atteindre les noms .onion
    et empêcher toute fuite DNS/IP hors Tor.
    """
    s = requests.Session()
    s.proxies.update(get_tor_proxies())
    return s


def rpc_call(method: str, params: dict | None = None,
             onion: str = "", port: int = GATEWAY_PORT,
             user: str = "", password: str = "") -> dict:
    """Appel JSON-RPC unique vers la gateway, à travers Tor + Digest auth."""
    _check_cfg()
    onion = (onion or GATEWAY_ONION).strip()
    if not onion.endswith(".onion"):
        raise RuntimeError(
            f"Sécurité Tor : l'hôte de la passerelle XMR doit être un service .onion ({onion})."
        )
    user = user or GATEWAY_USER
    password = password or GATEWAY_PASS
    url = f"http://{onion}:{port}/json_rpc"
    session = _make_session()
    payload = {"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}
    resp = session.post(
        url,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        auth=HTTPDigestAuth(user, password),
        timeout=60,
    )
    resp.raise_for_status()
    body = resp.json()
    if "error" in body:
        raise RuntimeError(f"Gateway XMR error: {body['error']}")
    return body.get("result", {})


def get_version() -> dict:
    return rpc_call("get_version")


def open_or_restore_wallet(wallet_name: str, mnemonic: str = "",
                           restore_height: int = 0,
                           address: str = "",
                           spend_key: str = "",
                           view_key: str = "") -> dict:
    """Ouvre (ou restaure depuis le mnémonique 25 mots ou les clés spend/view)
    le wallet dans la gateway."""
    try:
        return rpc_call("open_wallet", {"filename": wallet_name,
                                        "password": ""})
    except Exception:
        if spend_key and view_key and address:
            try:
                return rpc_call("generate_from_keys", {
                    "filename": wallet_name,
                    "address": address,
                    "spendkey": spend_key,
                    "viewkey": view_key,
                    "restore_height": restore_height,
                    "password": "",
                })
            except Exception:
                pass
        if mnemonic:
            return rpc_call("create_wallet", {
                "filename": wallet_name,
                "seed": mnemonic,
                "language": "English",
                "restore_height": restore_height,
                "password": "",
            })
        raise


def get_balance() -> dict:
    """Renvoie {balance, unlocked_balance} en atomic units (piconero)."""
    return rpc_call("get_balance", {})


def get_wallet_balance_xmr(wallet_info: dict | None = None,
                           mnemonic: str = "",
                           label: str = "XMR",
                           address: str = "",
                           spend_key: str = "",
                           view_key: str = "") -> dict[str, float] | None:
    """Consulte le solde total et débloqué (unlocked_balance) en XMR (12 décimales)
    via la passerelle Tor socks5h://127.0.0.1:9050."""
    if not is_tor_configured():
        return None
    opened = False
    seed = mnemonic or (wallet_info or {}).get("mnemonic") or ""
    spend = spend_key or (wallet_info or {}).get("private_spend_key") or ""
    view = view_key or (wallet_info or {}).get("private_view_key") or ""
    addr = address or (wallet_info or {}).get("address") or ""
    w_label = (wallet_info or {}).get("label") or label or (addr[:12] if addr else "XMR")
    try:
        if seed or (spend and view and addr):
            open_or_restore_wallet(
                f"ccw_{w_label}",
                mnemonic=seed,
                address=addr,
                spend_key=spend,
                view_key=view,
            )
            opened = True
        bal = get_balance()
        total_xmr = int(bal.get("balance", 0)) / 1e12
        unlocked_xmr = int(bal.get("unlocked_balance", 0)) / 1e12
        return {"total": total_xmr, "unlocked": unlocked_xmr}
    finally:
        seed = ""
        spend = ""
        view = ""
        gc.collect()
        if opened:
            try:
                close_wallet()
            except Exception:
                pass


def close_wallet() -> dict:
    """Ferme le wallet actuellement ouvert côté passerelle (non-custodial :
    libère le wallet pour que le serveur puisse le supprimer)."""
    return rpc_call("close_wallet", {})


def transfer(dest_address: str, amount_xmr: Decimal | str | int | float,
             priority: str = "normal") -> dict:
    """Crée et broadcaste un transfert. Renvoie le résultat gateway
    (contient 'tx_hash' et 'tx_hash_list')."""
    if not is_valid_xmr_address(dest_address):
        raise ValueError(f"Adresse Monero de destination invalide : {dest_address[:24]}...")
    amount_atomic = _xmr_to_piconero(amount_xmr)
    params = {
        "destinations": [{"amount": amount_atomic,
                          "address": dest_address.strip()}],
        "priority": priority,
        "ring_size": 16,
        "unlock_time": 0,
    }
    return rpc_call("transfer", params)


def sweep_all(dest_address: str, priority: str = "normal") -> dict:
    """Envoie la totalité du solde débloqué (frais déduits automatiquement)."""
    if not is_valid_xmr_address(dest_address):
        raise ValueError(f"Adresse Monero de destination invalide : {dest_address[:24]}...")
    params = {
        "address": dest_address.strip(),
        "priority": priority,
        "ring_size": 16,
        "unlock_time": 0,
    }
    return rpc_call("sweep_all", params)
