#!/usr/bin/env python3
"""
balance.py — Consulte le solde de tes wallets locaux (BTC, ETH, SOL)

Usage :
    python balance.py                          # Solde de tous les wallets
    python balance.py btc                      # Solde BTC seulement
    python balance.py eth                      # Solde ETH seulement
    python balance.py sol                      # Solde SOL seulement
    python balance.py btc mon_btc              # Solde d'un wallet spécifique
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests
from asset_catalog import asset_icon, network_icon, icon_column
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

# ── RPC / API ──────────────────────────────────────────────────────────
BTC_API = "https://blockchain.info"
LTC_API = "https://api.blockchair.com/litecoin"
DOGE_API = "https://api.blockchair.com/dogecoin"
BSC_RPC = "https://bsc-dataseed.binance.org/"
BSC_RPCS = ["https://bsc-rpc.publicnode.com", BSC_RPC, "https://1rpc.io/bnb"]
# EVM chains additionnelles
POLYGON_RPC = "https://polygon-bor-rpc.publicnode.com"
AVALANCHE_RPC = "https://api.avax.network/ext/bc/C/rpc"
ARBITRUM_RPC = "https://arb1.arbitrum.io/rpc"
OPTIMISM_RPC = "https://mainnet.optimism.io"
# USDC / DAI (ERC-20) sur Ethereum mainnet
USDC_ETH_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
DAI_ETH_CONTRACT = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
USDT_ETH_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
# USDT (BEP-20) sur BSC
USDT_BSC_CONTRACT = "0x55d398326f99059fF775485246999027B3197955"
HSH_BSC_CONTRACT = "0xA07eb39d960C8F1787A5B684874d2Fd897E623FA"
ETH_RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.mevblocker.io",
    "https://rpc.ankr.com/eth",
    "https://1rpc.io/eth",
    "https://eth.drpc.org",
]
SOL_RPC = "https://api.mainnet-beta.solana.com"
# ── API publiques non-EVM (lecture de solde seule) ──
XRP_API = "https://data.ripple.com/v2/accounts"
TRON_API = "https://api.trongrid.io/v1/accounts"
ATOM_API = "https://rest.cosmos.directory/cosmoshub/bank/balances"
ADA_API = "https://cardano-mainnet.blockfrost.io/api/v0/addresses"
# BlocFrost (https://blockfrost.io) exige un token project_id, jamais en dur ici.
ADA_BLOCKFROST_PROJECT_ID = os.getenv("ADA_BLOCKFROST_PROJECT_ID", "").strip()

WALLET_FILE = Path(__file__).parent / "wallets" / "wallets.enc"


# ── Déchiffrement ──────────────────────────────────────────────────────

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def decrypt_wallets(passphrase: str) -> dict:
    if not WALLET_FILE.exists():
        print(f"[!] Fichier introuvable : {WALLET_FILE}", file=sys.stderr)
        sys.exit(1)
    raw = WALLET_FILE.read_bytes()
    salt = raw[:16]
    token = raw[16:]
    key = derive_key(passphrase, salt)
    fernet = Fernet(key)
    payload = fernet.decrypt(token)
    return json.loads(payload.decode("utf-8"))


# ── Balance BTC ────────────────────────────────────────────────────────

def get_btc_balance(address: str) -> float:
    try:
        resp = requests.get(f"{BTC_API}/rawaddr/{address}", timeout=15)
        data = resp.json()
        balance_sat = data.get("final_balance", 0)
        return balance_sat / 1e8
    except Exception as e:
        return f"Erreur : {e}"


# ── Balance ETH ────────────────────────────────────────────────────────

def get_eth_balance(address: str) -> float:
    for rpc in ETH_RPCS:
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [address, "latest"],
                "id": 1,
            }
            resp = requests.post(rpc, json=payload, timeout=10)
            data = resp.json()
            if "result" in data:
                wei = int(data["result"], 16)
                return wei / 1e18
        except Exception:
            continue
    return "Aucun RPC joignable"


# ── Balance SOL ────────────────────────────────────────────────────────

def get_sol_balance(address: str) -> float:
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "getBalance",
            "params": [address],
            "id": 1,
        }
        resp = requests.post(SOL_RPC, json=payload, timeout=15)
        data = resp.json()
        if "result" in data:
            return data["result"]["value"] / 1e9
        return f"Erreur : {data}"
    except Exception as e:
        return f"Erreur : {e}"


# ── Balance LTC (blockchair + repli BlockCypher) ────────────────────────

def get_ltc_balance(address: str) -> float | str:
    """Retourne le solde LTC; l'absence d'adresse chez un fournisseur déclenche un repli."""
    blockchair_error = None
    try:
        resp = requests.get(f"{LTC_API}/dashboards/address/{address}", timeout=15)
        resp.raise_for_status()
        data = resp.json()
        entry = (data.get("data") or {}).get(address)
        if entry and entry[0].get("balance") is not None:
            # Blockchair renvoie les litoshis (1 LTC = 100 000 000 litoshis).
            return int(entry[0]["balance"]) / 1e8
        blockchair_error = "adresse absente de la réponse Blockchair"
    except Exception as exc:
        blockchair_error = str(exc)

    try:
        # BlockCypher renvoie final_balance en litoshis.
        r = requests.get(
            f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance",
            timeout=15,
        )
        r.raise_for_status()
        payload = r.json()
        if payload.get("final_balance") is None:
            raise ValueError("champ final_balance absent de la réponse BlockCypher")
        return int(payload["final_balance"]) / 1e8
    except Exception as exc:
        return ("Erreur : solde LTC indisponible "
                f"(Blockchair : {blockchair_error}; BlockCypher : {exc})")


# ── Balance DOGE (blockchair + repli BlockCypher) ────────────────────────

def get_doge_balance(address: str) -> float:
    try:
        resp = requests.get(f"{DOGE_API}/dashboards/address/{address}", timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"Blockchair HTTP {resp.status_code}")
        data = resp.json()
        if not data.get("data") or address not in data["data"]:
            return 0.0
        bal = data["data"][address][0]["balance"]
        # blockchair renvoie en base units (koinu, 1e8)
        return bal / 1e8
    except Exception:
        try:
            r = requests.get(
                f"https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance",
                timeout=15)
            if r.status_code == 200:
                return int(r.json().get("final_balance", 0)) / 1e8
        except Exception:
            pass
        return "Erreur : API DOGE injoignable (Blockchair limité, BlockCypher indisponible)"


# ── Balance BNB (BSC RPC) ───────────────────────────────────────────────

def get_bnb_balance(address: str) -> float:
    last_error = None
    for rpc in BSC_RPCS:
        try:
            payload = {
                "jsonrpc": "2.0", "method": "eth_getBalance",
                "params": [address, "latest"], "id": 1,
            }
            resp = requests.post(rpc, json=payload, timeout=15)
            data = resp.json()
            if "result" in data:
                return int(data["result"], 16) / 1e18
            last_error = data
        except Exception as exc:
            last_error = exc
    return f"Erreur : RPC BSC injoignable ({last_error})"


# ── Balance ERC-20 (USDT sur Ethereum ou BEP-20 sur BSC) ────────────────

def get_erc20_balance(address: str, rpc_url: str, contract: str,
                      decimals: int = 6) -> float:
    """Lit le solde d'un token ERC-20/BEP-20 via eth_call (transfer signature)."""
    try:
        # balanceOf(address) : selector 0x70a08231 + padded address
        addr_padded = address.lower().replace("0x", "").rjust(64, "0")
        data = "0x70a08231" + addr_padded
        payload = {
            "jsonrpc": "2.0", "method": "eth_call",
            "params": [{"to": contract, "data": data}, "latest"], "id": 1,
        }
        resp = requests.post(rpc_url, json=payload, timeout=15)
        res = resp.json().get("result")
        if res:
            return int(res, 16) / (10 ** decimals)
        return f"Erreur : {resp.json()}"
    except Exception as e:
        return f"Erreur : {e}"


def get_usdt_balance(address: str) -> float:
    """USDT ERC-20 (Ethereum) par défaut."""
    return get_erc20_balance(address, ETH_RPCS[0], USDT_ETH_CONTRACT, decimals=6)


def get_hsh_balance(address: str) -> float:
    """HashCoin HSH BEP-20 sur BNB Smart Chain."""
    last_error = None
    for rpc in BSC_RPCS:
        result = get_erc20_balance(address, rpc, HSH_BSC_CONTRACT, decimals=18)
        if not isinstance(result, str):
            return result
        last_error = result
    return f"Erreur : solde HSH indisponible ({last_error})"


# ── EVM chains (Polygon, Avalanche, Arbitrum, Optimism) ────────────────

def get_evm_balance(address: str, rpc_url: str, symbol: str) -> float:
    """Solde natif d'une chaîne EVM (MATIC, AVAX, ARB, OP, ...)."""
    try:
        payload = {
            "jsonrpc": "2.0", "method": "eth_getBalance",
            "params": [address, "latest"], "id": 1,
        }
        resp = requests.post(rpc_url, json=payload, timeout=15)
        data = resp.json()
        if "result" in data:
            return int(data["result"], 16) / 1e18
        return f"Erreur : {data}"
    except Exception as e:
        return f"Erreur : {e}"


def get_polygon_balance(address: str) -> float:
    return get_evm_balance(address, POLYGON_RPC, "MATIC")


def get_avalanche_balance(address: str) -> float:
    return get_evm_balance(address, AVALANCHE_RPC, "AVAX")


def get_arbitrum_balance(address: str) -> float:
    return get_evm_balance(address, ARBITRUM_RPC, "ARB")


def get_optimism_balance(address: str) -> float:
    return get_evm_balance(address, OPTIMISM_RPC, "OP")


# ── Stablecoins ERC-20 supplémentaires (USDC, DAI) ─────────────────────

def get_usdc_balance(address: str) -> float:
    return get_erc20_balance(address, ETH_RPCS[0], USDC_ETH_CONTRACT, decimals=6)


def get_dai_balance(address: str) -> float:
    return get_erc20_balance(address, ETH_RPCS[0], DAI_ETH_CONTRACT, decimals=18)


# ── Non-EVM : XRP, Tron, Cosmos, Cardano (lecture via API publique) ────

def get_xrp_balance(address: str) -> float:
    try:
        resp = requests.get(f"{XRP_API}/{address}/balances", timeout=15)
        d = resp.json()
        for bal in d.get("balances", []):
            if bal.get("currency") == "XRP":
                return float(bal.get("value", 0))
        return 0.0
    except Exception as e:
        return f"Erreur : {e}"


def get_trx_balance(address: str) -> float:
    try:
        # l'API tron nécessite l'adresse hex (sans le préfixe T)
        import base58
        raw = base58.b58decode(address)
        hex_addr = raw[1:-4].hex()
        resp = requests.get(f"{TRON_API}/{hex_addr}", timeout=15)
        d = resp.json()
        for b in d.get("data", [{}])[0].get("trc20", []):
            # on cherche le solde TRX natif via bandwitch/balance
            pass
        # solde TRX natif est dans data[0].balance (en SUN, 1e6)
        return int(d.get("data", [{}])[0].get("balance", 0)) / 1e6
    except Exception as e:
        return f"Erreur : {e}"


def get_atom_balance(address: str) -> float:
    try:
        resp = requests.get(f"{ATOM_API}/{address}", timeout=15)
        d = resp.json()
        for b in d.get("balances", []):
            if b.get("denom") == "uatom":
                return int(b.get("amount", 0)) / 1e6
        return 0.0
    except Exception as e:
        return f"Erreur : {e}"


def get_ada_balance(address: str) -> float:
    try:
        # Blockfrost (https://blockfrost.io) exige un token project_id.
        # Défini via la variable d'environnement ADA_BLOCKFROST_PROJECT_ID.
        token = ADA_BLOCKFROST_PROJECT_ID
        url = f"{ADA_API}/{address}"
        if token:
            url += f"?project_id={token}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            d = resp.json()
            return int(d.get("amount", 0)) / 1e6  # lovelace -> ADA
        return f"Erreur : API Blockfrost nécessite une clé (status {resp.status_code})"
    except Exception as e:
        return f"Erreur : {e}"
# ── Affichage ──────────────────────────────────────────────────────────

def show_balance(wallets: dict, network_filter: str = None, label_filter: str = None):
    """Affiche le solde de chaque entrée en donnant priorité à l'actif/token."""
    for label, info in wallets.items():
        network = str(info.get("network", "?")).lower()
        address = info.get("address", "?")
        token = str(info.get("token") or info.get("asset") or "").upper()

        if network_filter and network != network_filter and token.lower() != network_filter:
            continue
        if label_filter and label != label_filter:
            continue

        # Un token doit être lu via balanceOf(), pas comme la monnaie native du réseau.
        if token == "USDT":
            balance = get_usdt_balance(address); symbol = "USDT"
        elif token == "USDC":
            balance = get_usdc_balance(address); symbol = "USDC"
        elif token == "DAI":
            balance = get_dai_balance(address); symbol = "DAI"
        elif token == "HSH":
            balance = get_hsh_balance(address); symbol = "HSH"
        elif network == "bitcoin":
            balance = get_btc_balance(address); symbol = "BTC"
        elif network == "ethereum":
            balance = get_eth_balance(address); symbol = "ETH"
        elif network == "solana":
            balance = get_sol_balance(address); symbol = "SOL"
        elif network == "litecoin":
            balance = get_ltc_balance(address); symbol = "LTC"
        elif network == "dogecoin":
            balance = get_doge_balance(address); symbol = "DOGE"
        elif network == "bsc":
            balance = get_bnb_balance(address); symbol = "BNB"
        elif network == "polygon":
            balance = get_polygon_balance(address); symbol = "POL"
        elif network == "avalanche":
            balance = get_avalanche_balance(address); symbol = "AVAX"
        elif network == "arbitrum":
            balance = get_arbitrum_balance(address); symbol = "ETH"
        elif network == "optimism":
            balance = get_optimism_balance(address); symbol = "ETH"
        elif network == "ripple":
            balance = get_xrp_balance(address); symbol = "XRP"
        elif network == "tron":
            balance = get_trx_balance(address); symbol = "TRX"
        elif network == "cosmos":
            balance = get_atom_balance(address); symbol = "ATOM"
        elif network == "cardano":
            balance = get_ada_balance(address); symbol = "ADA"
        else:
            balance = "Erreur : actif/réseau non configuré"; symbol = "?"

        if isinstance(balance, str):
            print(f"  {icon_column(asset_icon(symbol))} {label:<24} {symbol:<6} "
                  f"{icon_column(network_icon(network))} {address:<48}  [!] {balance}")
        else:
            print(f"  {icon_column(asset_icon(symbol))} {label:<24} {symbol:<6} "
                  f"{icon_column(network_icon(network))} {address:<48}  {balance:.8f} {symbol}")

        # Une adresse BSC peut contenir BNB + plusieurs BEP-20. On affiche HSH
        # comme ligne secondaire lorsqu'il est présent et que l'entrée n'est pas déjà HSH.
        if network == "bsc" and token != "HSH":
            hsh = get_hsh_balance(address)
            if not isinstance(hsh, str) and hsh > 0:
                print(f"  {icon_column(asset_icon('HSH'))} {'↳ HSH':<24} {'HSH':<6} "
                      f"{icon_column(network_icon('bsc'))} {address:<48}  {hsh:.8f} HSH")


# ── CLI ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Consulter le solde de tes wallets")
    parser.add_argument("network", nargs="?", choices=["btc", "eth", "sol", "ltc", "doge", "bnb",
                        "usdt", "polygon", "avalanche", "arbitrum", "optimism",
                        "usdc", "dai", "hsh", "xrp", "trx", "atom", "ada"],
                        help="Filtrer par réseau (optionnel)")
    parser.add_argument("label", nargs="?", default=None,
                        help="Filtrer par label (optionnel)")
    args = parser.parse_args()

    passphrase = get_secret("Phrase de passe du fichier wallet : ")
    wallets = decrypt_wallets(passphrase)

    if not wallets:
        print("Aucun wallet trouvé.")
        return

    # Mapping : btc → bitcoin, eth → ethereum, sol → solana
    network_map = {"btc": "bitcoin", "eth": "ethereum", "sol": "solana"}
    net_filter = network_map.get(args.network) if args.network else None

    print(f"\n{'Label':<24} {'Réseau':<6} {'Adresse':<48} {'Solde'}")
    print("─" * 110)
    show_balance(wallets, net_filter, args.label)
    print()


if __name__ == "__main__":
    main()
