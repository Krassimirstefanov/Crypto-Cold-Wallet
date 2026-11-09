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
  - transfer (création + broadcast)
  - get_version
"""

import json
import os
import socket
import socks  # PySocks

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


def _load_pass() -> str:
    """Récupère le mot de passe RPC : env > gateway.conf > saisie interactive.

    gateway.conf accepte deux formats :
      - une seule ligne : le mot de passe (login par défaut 'xmrgw')
      - ou deux lignes  user=...  et  pass=...
    """
    env_pass = os.environ.get("XMR_GATEWAY_PASS", "").strip()
    if env_pass:
        return env_pass
    global GATEWAY_USER
    # 2) fichier gateway.conf
    try:
        with open(_CONF_PATH, "r", encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh if ln.strip()
                     and not ln.strip().startswith("#")]
        if lines:
            # format user=/pass=
            user_line = next((ln for ln in lines if ln.startswith("user=")), None)
            pass_line = next((ln for ln in lines if ln.startswith("pass=")), None)
            if pass_line:
                if user_line:
                    GATEWAY_USER = user_line.split("=", 1)[1].strip()
                return pass_line.split("=", 1)[1].strip()
            # sinon : une seule ligne = le mot de passe
            return lines[0]
    except FileNotFoundError:
        pass
    # 3) saisie interactive (getpass : ne s'affiche pas à l'écran)
    import getpass
    return getpass.getpass(
        "  Mot de passe de la passerelle XMR (donné par l'émetteur) : ").strip()


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


# SOCKS Tor local utilisé pour atteindre l'onion.
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050


def _make_session() -> requests.Session:
    """Session requests routée via Tor (SOCKS) + auth Digest.

    On utilise 'socks5h://' (et non 'socks5://') : le 'h' force la résolution
    DNS à travers le proxy Tor, indispensable pour atteindre les noms .onion.
    """
    s = requests.Session()
    proxy = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
    s.proxies.update({"http": proxy, "https": proxy})
    return s


def rpc_call(method: str, params: dict | None = None,
             onion: str = "", port: int = GATEWAY_PORT,
             user: str = "", password: str = "") -> dict:
    """Appel JSON-RPC unique vers la gateway, à travers Tor + Digest auth."""
    # Configuration lue depuis l'environnement (jamais en clair dans le code).
    _check_cfg()
    onion = onion or GATEWAY_ONION
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


def open_or_restore_wallet(wallet_name: str, mnemonic: str,
                           restore_height: int = 0) -> dict:
    """Ouvre (ou restaure depuis le mnémonique) le wallet dans la gateway.

    Cette build de monero-wallet-rpc n'expose pas 'restore_wallet_from_seed',
    donc on utilise 'create_wallet' avec le seed + language (requis par l'API).
    Si le wallet existe déjà, on l'ouvre simplement.
    """
    try:
        return rpc_call("open_wallet", {"filename": wallet_name,
                                        "password": ""})
    except Exception:
        # Le wallet n'existe pas encore côté gateway -> création depuis seed.
        return rpc_call("create_wallet", {
            "filename": wallet_name,
            "seed": mnemonic,
            "language": "English",
            "restore_height": restore_height,
            "password": "",
        })


def get_balance() -> dict:
    """Renvoie {total, unlocked} en atomic units (piconero)."""
    return rpc_call("get_balance", {})


def close_wallet() -> dict:
    """Ferme le wallet actuellement ouvert côté passerelle (non-custodial :
    libère le wallet pour que le serveur puisse le supprimer)."""
    return rpc_call("close_wallet", {})


def transfer(dest_address: str, amount_xmr: float,
             priority: str = "normal") -> dict:
    """Crée et broadcaste un transfert. Renvoie le résultat gateway
    (contient 'tx_hash' et 'tx_hash_list')."""
    params = {
        "destinations": [{"amount": int(amount_xmr * 1e12),  # XMR -> piconero
                         "address": dest_address}],
        "priority": priority,
        "ring_size": 16,
        "unlock_time": 0,
    }
    return rpc_call("transfer", params)
