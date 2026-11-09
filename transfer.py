#!/usr/bin/env python3
"""
transfer.py — Effectue des transferts depuis les wallets locaux
(BTC, ETH, SOL, LTC, DOGE, BNB, USDT)
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
from bitcoinlib.keys import Key as BTCKey

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


# ── RPC / API endpoints publics ──
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


# ── Récupération des clés privées depuis le wallet chiffré ─────────────

def get_private_key(label: str, passphrase: str) -> dict:
    """Récupère les infos d'un wallet depuis le fichier chiffré."""
    wallets = load_wallets(passphrase)
    if label not in wallets:
        print(f"[!] Wallet '{label}' introuvable.", file=sys.stderr)
        sys.exit(1)
    wallet = wallets[label]
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


# ── Validation des adresses de destination ──────────────────────────────
# Préfixes/regex minimaux par réseau. On refuse une destination manifestement
# invalide AVANT toute construction/signature de transaction.
_ADDR_RULES = {
    "bitcoin":  lambda a: (a.startswith(("bc1", "1", "3")) and 26 <= len(a) <= 90),
    "litecoin": lambda a: (a.startswith(("ltc1", "L", "M")) and 26 <= len(a) <= 90),
    "dogecoin": lambda a: (a.startswith("D") and 26 <= len(a) <= 90),
    "ethereum": lambda a: (a.startswith("0x") and len(a) == 42
                           and all(c in "0123456789abcdefABCDEF" for c in a[2:])),
    "bsc":      lambda a: (a.startswith("0x") and len(a) == 42
                           and all(c in "0123456789abcdefABCDEF" for c in a[2:])),
    "polygon":  lambda a: (a.startswith("0x") and len(a) == 42
                           and all(c in "0123456789abcdefABCDEF" for c in a[2:])),
    "avalanche":lambda a: (a.startswith("0x") and len(a) == 42
                           and all(c in "0123456789abcdefABCDEF" for c in a[2:])),
    "arbitrum": lambda a: (a.startswith("0x") and len(a) == 42
                           and all(c in "0123456789abcdefABCDEF" for c in a[2:])),
    "optimism": lambda a: (a.startswith("0x") and len(a) == 42
                           and all(c in "0123456789abcdefABCDEF" for c in a[2:])),
    "solana":   lambda a: (26 <= len(a) <= 88),   # base58, pas de prefixe fixe
    "tron":     lambda a: (a.startswith("T") and 26 <= len(a) <= 34
                           and all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in a)),
    "ripple":   lambda a: (a.startswith("r") and 25 <= len(a) <= 35
                           and all(c in "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz" for c in a)),
    "cosmos":   lambda a: (a.startswith("cosmos1") and len(a) >= 39),
    "cardano":  lambda a: (a.startswith("addr1") and len(a) >= 50),
    "monero":   lambda a: (a.startswith(("4", "8")) and 95 <= len(a) <= 110
                           and all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in a)),
}


def validate_address(network: str, address: str) -> bool:
    """Valide le format (préfixe/longueur/alphabet) d'une adresse de destination.
    Renvoie True si plausible pour le réseau, False sinon.
    Les réseaux EVM partagent le même format 0x… (eth/bsc/polygon/…)."""
    net = network.lower()
    rule = _ADDR_RULES.get(net)
    if rule is None:
        return True   # réseau non listé : on ne bloque pas (ex: tokens ERC-20)
    return bool(rule(address))


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
    if amount is None or amount <= 0:
        print(f"[!] Montant invalide pour {ticker} : {amount}", file=sys.stderr)
        sys.exit(1)
    from decimal import Decimal

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
    if amount is None or amount <= 0:
        print(f"[!] Montant invalide pour {token_ticker} : {amount}",
              file=sys.stderr)
        sys.exit(1)
    print(f"[*] Contrôle des fonds ({asset_icon(token_ticker)} {token_ticker} / "
          f"{asset_icon(native_ticker)} {native_ticker}) :")
    print(f"    {icon_column(asset_icon(token_ticker))} Solde {token_ticker:<6} : "
          f"{token_balance} {token_ticker}")
    print(f"    Montant à envoyer  : {amount} {token_ticker}")
    print(f"    {icon_column(asset_icon(native_ticker))} Solde {native_ticker:<6} : "
          f"{native_balance} {native_ticker} "
          f"(pour le gas)")
    print(f"    Frais de gas est.  : {gas_fee} {native_ticker}")
    if amount > token_balance:
        print(t("send_balance_insuff", tk=token_ticker, balance=token_balance,
                 amount=amount), file=sys.stderr)
        sys.exit(1)
    if gas_fee > native_balance:
        print(t("send_gas_insuff", nt=native_ticker, balance=native_balance,
                 fee=gas_fee), file=sys.stderr)
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
        from decimal import Decimal

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

def transfer_btc(label: str, dest_address: str, amount_btc: float, passphrase: str):
    """
    Envoie du Bitcoin.
    Utilise bitcoinlib pour construire et signer la transaction,
    puis broadcast via blockchain.info.
    """
    wallet_info = get_private_key(label, passphrase)
    wif = wallet_info["private_key_wif"]
    mnemonic = wallet_info.get("mnemonic", "")

    # Vérifier le solde via API publique (annulation si indisponible)
    addr = wallet_info["address"]
    print(f"[*] Vérification du solde pour {addr}...")
    try:
        resp = requests.get(f"{BTC_API_URL}/balance?active={addr}", timeout=15)
        balance_sat = resp.json().get("balance", 0)
        balance_btc = balance_sat / 1e8
        print(f"[*] Solde : {balance_btc:.8f} BTC")
    except Exception as e:
        print(f"[!] Impossible de récupérer le solde : {e}", file=sys.stderr)
        print("[!] Transfert annulé : solde non vérifiable.", file=sys.stderr)
        sys.exit(1)

    if amount_btc <= 0:
        print(f"[!] Montant invalide : {amount_btc} BTC", file=sys.stderr)
        sys.exit(1)

    # Estimer les fees dynamiquement (taux réseau réel)
    try:
        fee_resp = requests.get(f"{BTC_API_URL}/q/estimatesmartfee/3", timeout=15)
        fee_btc_kb = float(fee_resp.text)
        fee_rate = max(1, int(fee_btc_kb * 1e8 / 1024))  # sat/byte
        print(f"[*] Fee estimé : {fee_rate} sat/byte")
    except Exception as e:
        print(f"[!] Estimation des frais impossible : {e}", file=sys.stderr)
        print("[!] Transfert annulé : frais non estimables.", file=sys.stderr)
        sys.exit(1)

    # Créer une clé bitcoinlib à partir de la WIF
    key = BTCKey(wif)

    # Créer la transaction pour obtenir les frais réels (calculés par bitcoinlib)
    with ephemeral_transfer_wallet(
        witness_type="segwit",
        keys=wif if wallet_info.get("address_records") else (mnemonic if mnemonic else wif),
        scheme="single" if wallet_info.get("address_records") else "bip32",
        network="bitcoin",
    ) as w:
        tx = w.send_to(
            to_address=dest_address,
            amount=int(amount_btc * 1e8),
            fee=fee_rate,
        )
        # Frais réels (satoshis) calculés par bitcoinlib à partir de la tx construite
        fee_sat = getattr(tx, "fee", None)
        if fee_sat is None:
            print("[!] Frais de transaction indéterminables : transfert annulé.",
                  file=sys.stderr)
            sys.exit(1)
        fee_btc = fee_sat / 1e8

        # Vérification stricte : solde >= montant + frais (avant broadcast)
        check_balance_with_fee(balance_btc, amount_btc, fee_btc, "BTC")
        _confirm_send("btc", dest_address, amount_btc, "BTC", fee_btc, "BTC")

        # Récupérer la transaction hex et la broadcast
        tx_hex = tx.raw_hex()
        print(f"[*] Transaction hex : {tx_hex[:64]}...")

        # Broadcast via blockchain.info
        print("[*] Broadcast de la transaction...")
        try:
            resp = requests.post(
                f"{BTC_API_URL}/pushtx",
                data={"tx": tx_hex},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
            if resp.status_code == 200:
                txid = resp.text.strip()
                print(f"✅ Transaction broadcastée ! TXID : {txid}")
                print(f"   https://www.blockchain.com/btc/tx/{txid}")
                log_transaction("btc", label, dest_address, amount_btc, txid,
                                f"https://www.blockchain.com/btc/tx/{txid}")
            else:
                print(f"[!] Erreur broadcast : {resp.text}", file=sys.stderr)
        except Exception as e:
            print(f"[!] Erreur réseau lors du broadcast : {e}", file=sys.stderr)

        # Nettoyage


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
        raise RuntimeError(
            f"Solde {network} indisponible (Blockchair : {primary_error}; "
            f"BlockCypher : {exc})"
        ) from exc


def transfer_btc_like(label: str, dest_address: str, amount: float,
                       passphrase: str, network: str, witness: str):
    """Transfert générique Bitcoin-like (LTC ou DOGE) via bitcoinlib."""
    wallet_info = get_private_key(label, passphrase)
    wif = wallet_info["private_key_wif"]
    mnemonic = wallet_info.get("mnemonic", "")

    # Solde en litoshis/koinu; l'absence chez Blockchair n'est pas interprétée comme zéro.
    addr = wallet_info["address"]
    print(f"[*] Vérification du solde pour {addr}...")
    try:
        balance_litoshis = _read_btc_like_balance_litoshis(network, addr)
        bal = balance_litoshis / 1e8
        print(f"[*] Solde : {bal:.8f} {network.upper()}")
    except Exception as e:
        print(f"[!] Solde indisponible : {e}", file=sys.stderr)
        print(f"[!] Transfert {network.upper()} annulé : solde non vérifiable.",
              file=sys.stderr)
        sys.exit(1)

    if amount <= 0:
        print(f"[!] Montant invalide : {amount} {network.upper()}",
              file=sys.stderr)
        sys.exit(1)

    # Bitcoinlib attend ici "low"/"normal"/"high" ou un montant total de frais,
    # pas un tarif par octet. L'estimation est faite par bitcoinlib; aucun endpoint
    # BlockCypher construit avec le nom interne "litecoin" n'est appelé.
    try:
        with ephemeral_transfer_wallet(
            witness_type=witness,
            keys=wif if wallet_info.get("address_records") else (mnemonic if mnemonic else wif),
            scheme="single" if wallet_info.get("address_records") else "bip32",
            network=network,
        ) as w:
            # Les wallets temporaires ont une base vide : récupérer les UTXO
            # confirmés avant de composer la transaction.
            w.utxos_update(networks=network, update_balance=True, rescan_all=True)
            if not w.utxos(min_confirms=1):
                raise RuntimeError(
                    "Aucun UTXO confirmé trouvé pour la clé dérivée du wallet source"
                )
            tx = w.send_to(
                to_address=dest_address,
                amount=int(amount * 1e8),
                fee="normal",
                broadcast=False,
            )
        # Frais réels (satoshis) calculés par bitcoinlib
            fee_sat = getattr(tx, "fee", None)
            if fee_sat is None:
                print(f"[!] Frais de transaction {network.upper()} indéterminables : "
                      f"transfert annulé.", file=sys.stderr)
                sys.exit(1)
            fee_native = fee_sat / 1e8

            # Vérification stricte : solde >= montant + frais (avant broadcast)
            check_balance_with_fee(bal, amount, fee_native, network.upper())
            _confirm_send(network, dest_address, amount, network.upper(),
                          fee_native, network.upper())
            tx_hex = tx.raw_hex()
            print(f"[*] Transaction hex : {tx_hex[:64]}...")

            # Broadcast : blockchair push endpoint
            api = LTC_API_URL if network == "litecoin" else DOGE_API_URL
            push_url = f"{api}/push/transaction"
            print("[*] Broadcast de la transaction...")
            try:
                resp = requests.post(push_url, data={"data": tx_hex}, timeout=30)
                if resp.status_code == 200:
                    txid = resp.json().get("data", {}).get("tx_hash") or resp.text.strip()
                    print(f"✅ Transaction broadcastée ! TXID : {txid}")
                    explorer = ("https://blockchair.com/litecoin/transactions/"
                                if network == "litecoin" else
                                "https://blockchair.com/dogecoin/transactions/")
                    print(f"   {explorer}{txid}")
                    log_transaction(network, label, dest_address, amount, txid,
                                    f"{explorer}{txid}")
                else:
                    print(f"[!] Erreur broadcast : {resp.text}", file=sys.stderr)
            except Exception as e:
                print(f"[!] Erreur réseau lors du broadcast : {e}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Création ou estimation de la transaction impossible : {e}",
              file=sys.stderr)
        print(f"[!] Transfert {network.upper()} annulé.", file=sys.stderr)
        sys.exit(1)

def transfer_ltc(label, dest, amount, passphrase):
    transfer_btc_like(label, dest, amount, passphrase, "litecoin", "segwit")


def transfer_doge(label, dest, amount, passphrase):
    transfer_btc_like(label, dest, amount, passphrase, "dogecoin", "legacy")


# ── TRANSFERT ETHEREUM ──────────────────────────────────────────────────

def get_working_eth_rpc() -> str:
    """Test les RPC Ethereum et retourne le premier qui répond."""
    for rpc in ETH_RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 5}))
            if w3.is_connected():
                return rpc
        except:
            continue
    return ETH_RPCS[0]


def transfer_eth(label: str, dest_address: str, amount_eth: float, passphrase: str):
    """
    Envoie de l'Ethereum (ETH) en appelant le RPC.
    """
    wallet_info = get_private_key(label, passphrase)
    private_key_hex = wallet_info["private_key_hex"]
    from_address = wallet_info["address"]

    rpc_url = get_working_eth_rpc()
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"[!] Impossible de se connecter au RPC : {rpc_url}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Connecté au RPC Ethereum via {rpc_url} (block {w3.eth.block_number})")

    # Vérifier le solde
    balance_wei = w3.eth.get_balance(Web3.to_checksum_address(from_address))
    balance_eth = w3.from_wei(balance_wei, 'ether')
    print(f"[*] Solde : {balance_eth:.6f} ETH")

    if amount_eth <= 0:
        print(f"[!] Montant invalide : {amount_eth} ETH", file=sys.stderr)
        sys.exit(1)

    # Récupérer le nonce
    nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(from_address))

    # Gas fees : prix réseau réel + limite standard d'une tx native (21000)
    gas_price = w3.eth.gas_price
    gas_limit = 21000
    fee_wei = gas_price * gas_limit
    fee_eth = w3.from_wei(fee_wei, 'ether')

    # Vérification stricte : solde >= montant + frais de gas (avant signature)
    check_balance_with_fee(balance_eth, amount_eth, fee_eth, "ETH")
    _confirm_send("eth", dest_address, amount_eth, "ETH", fee_eth, "ETH")

    amount_wei = w3.to_wei(amount_eth, 'ether')

    # Construire la transaction
    tx = {
        'nonce': nonce,
        'to': Web3.to_checksum_address(dest_address),
        'value': amount_wei,
        'gas': gas_limit,
        'gasPrice': gas_price,
        'chainId': 1,  # Mainnet
    }

    # Signer
    signed_tx = EthAccount.sign_transaction(tx, private_key_hex)
    tx_hex = signed_tx.raw_transaction.hex()

    print(f"[*] Transaction signée. Broadcast...")

    # Broadcast
    try:
        tx_hash = w3.eth.send_raw_transaction(tx_hex)
        print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
        print(f"   https://etherscan.io/tx/{tx_hash.hex()}")
        log_transaction("eth", label, dest_address, amount_eth, tx_hash.hex(),
                        f"https://etherscan.io/tx/{tx_hash.hex()}")
    except Exception as e:
        print(f"[!] Erreur broadcast : {e}", file=sys.stderr)


# ── TRANSFERT BNB (BSC, EVM) ──────────────────────────────────────────

def transfer_bnb(label: str, dest_address: str, amount_bnb: float, passphrase: str):
    """Envoie du BNB sur BSC (chaîne EVM, chainId 56)."""
    wallet_info = get_private_key(label, passphrase)
    private_key_hex = wallet_info["private_key_hex"]
    from_address = wallet_info["address"]

    w3 = Web3(Web3.HTTPProvider(BSC_RPC))
    if not w3.is_connected():
        print(f"[!] Impossible de se connecter au RPC BSC : {BSC_RPC}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Connecté au RPC BSC (block {w3.eth.block_number})")

    balance_wei = w3.eth.get_balance(Web3.to_checksum_address(from_address))
    balance_bnb = w3.from_wei(balance_wei, 'ether')
    print(f"[*] Solde : {balance_bnb:.6f} BNB")

    if amount_bnb <= 0:
        print(f"[!] Montant invalide : {amount_bnb} BNB", file=sys.stderr)
        sys.exit(1)

    nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(from_address))
    gas_price = w3.eth.gas_price
    gas_limit = 21000
    fee_bnb = w3.from_wei(gas_price * gas_limit, 'ether')

    # Vérification stricte : solde >= montant + frais de gas (avant signature)
    check_balance_with_fee(balance_bnb, amount_bnb, fee_bnb, "BNB")
    _confirm_send("bnb", dest_address, amount_bnb, "BNB", fee_bnb, "BNB")

    amount_wei = w3.to_wei(amount_bnb, 'ether')

    tx = {
        'nonce': nonce,
        'to': Web3.to_checksum_address(dest_address),
        'value': amount_wei,
        'gas': gas_limit,
        'gasPrice': gas_price,
        'chainId': 56,  # BSC mainnet
    }
    signed_tx = EthAccount.sign_transaction(tx, private_key_hex)
    tx_hex = signed_tx.raw_transaction.hex()
    print("[*] Transaction signée. Broadcast...")
    try:
        tx_hash = w3.eth.send_raw_transaction(tx_hex)
        print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
        print(f"   https://bscscan.com/tx/{tx_hash.hex()}")
        log_transaction("bnb", label, dest_address, amount_bnb, tx_hash.hex(),
                        f"https://bscscan.com/tx/{tx_hash.hex()}")
    except Exception as e:
        print(f"[!] Erreur broadcast : {e}", file=sys.stderr)


# ── TRANSFERT USDT (ERC-20, EVM) ─────────────────────────────────────

def transfer_usdt(label: str, dest_address: str, amount_usdt: float, passphrase: str):
    """Envoie des USDT (token ERC-20) sur Ethereum mainnet (chainId 1)."""
    wallet_info = get_private_key(label, passphrase)
    private_key_hex = wallet_info["private_key_hex"]
    from_address = wallet_info["address"]

    rpc_url = get_working_eth_rpc()
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"[!] Impossible de se connecter au RPC : {rpc_url}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Connecté au RPC via {rpc_url} (block {w3.eth.block_number})")

    # Solde USDT via eth_call (balanceOf)
    addr_padded = from_address.lower().replace("0x", "").rjust(64, "0")
    bal_resp = w3.eth.call({
        "to": Web3.to_checksum_address(USDT_ETH_CONTRACT),
        "data": "0x70a08231" + addr_padded,
    })
    balance_usdt = int(bal_resp.hex(), 16) / 1e6
    print(f"[*] Solde USDT : {balance_usdt:.6f} USDT")

    if amount_usdt <= 0:
        print(f"[!] Montant invalide : {amount_usdt} USDT", file=sys.stderr)
        sys.exit(1)

    # Encodage de transfer(address, uint256)
    dest_padded = dest_address.lower().replace("0x", "").rjust(64, "0")
    amount_raw = int(amount_usdt * 1e6)
    amount_hex = hex(amount_raw)[2:].rjust(64, "0")
    data = "0xa9059cbb" + dest_padded + amount_hex

    nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(from_address))
    gas_price = w3.eth.gas_price
    gas_limit = 60000
    fee_eth = w3.from_wei(gas_price * gas_limit, 'ether')

    # Solde natif (ETH) nécessaire au gas
    native_balance_wei = w3.eth.get_balance(Web3.to_checksum_address(from_address))
    native_balance_eth = w3.from_wei(native_balance_wei, 'ether')

    # Vérification stricte ERC-20 : token + gas natif séparés (avant signature)
    check_erc20_funds(balance_usdt, amount_usdt, "USDT",
                      native_balance_eth, fee_eth, "ETH")
    _confirm_send("usdt", dest_address, amount_usdt, "USDT", fee_eth, "ETH")

    tx = {
        'nonce': nonce,
        'to': Web3.to_checksum_address(USDT_ETH_CONTRACT),
        'value': 0,
        'gas': gas_limit,
        'gasPrice': gas_price,
        'chainId': 1,
        'data': data,
    }
    signed_tx = EthAccount.sign_transaction(tx, private_key_hex)
    tx_hex = signed_tx.raw_transaction.hex()
    print("[*] Transaction signée. Broadcast...")
    try:
        tx_hash = w3.eth.send_raw_transaction(tx_hex)
        print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
        print(f"   https://etherscan.io/tx/{tx_hash.hex()}")
        log_transaction("usdt", label, dest_address, amount_usdt, tx_hash.hex(),
                        f"https://etherscan.io/tx/{tx_hash.hex()}")
    except Exception as e:
        print(f"[!] Erreur broadcast : {e}", file=sys.stderr)


# ── TRANSFERT EVM (Polygon, Avalanche, Arbitrum, Optimism) ──────────────

def _transfer_evm_native(label, dest, amount, passphrase, rpc_url, chain_id, symbol, explorer):
    """Transfert de la crypto native d'une chaîne EVM (MATIC/AVAX/ARB/OP)."""
    wallet_info = get_private_key(label, passphrase)
    private_key_hex = wallet_info["private_key_hex"]
    from_address = wallet_info["address"]
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"[!] RPC {symbol} non joignable : {rpc_url}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Connecté au RPC {symbol} (block {w3.eth.block_number})")
    balance_wei = w3.eth.get_balance(Web3.to_checksum_address(from_address))
    balance = w3.from_wei(balance_wei, 'ether')
    print(f"[*] Solde : {balance:.6f} {symbol}")

    if amount <= 0:
        print(f"[!] Montant invalide : {amount} {symbol}", file=sys.stderr)
        sys.exit(1)

    nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(from_address))
    gas_price = w3.eth.gas_price
    gas_limit = 21000
    fee_sym = w3.from_wei(gas_price * gas_limit, 'ether')

    # Vérification stricte : solde >= montant + frais de gas (avant signature)
    check_balance_with_fee(balance, amount, fee_sym, symbol)
    _confirm_send(symbol.lower(), dest, amount, symbol, fee_sym, symbol)

    amount_wei = w3.to_wei(amount, 'ether')
    tx = {
        'nonce': nonce, 'to': Web3.to_checksum_address(dest), 'value': amount_wei,
        'gas': 21000, 'gasPrice': gas_price, 'chainId': chain_id,
    }
    signed = EthAccount.sign_transaction(tx, private_key_hex)
    tx_hex = signed.raw_transaction.hex()
    print("[*] Transaction signée. Broadcast...")
    try:
        tx_hash = w3.eth.send_raw_transaction(tx_hex)
        print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
        print(f"   {explorer}{tx_hash.hex()}")
        log_transaction(symbol.lower(), label, dest, amount, tx_hash.hex(),
                        f"{explorer}{tx_hash.hex()}")
    except Exception as e:
        print(f"[!] Erreur broadcast : {e}", file=sys.stderr)


def transfer_polygon(label, dest, amount, passphrase):
    _transfer_evm_native(label, dest, amount, passphrase, POLYGON_RPC, 137, "POL",
                         "https://polygonscan.com/tx/")


def transfer_avalanche(label, dest, amount, passphrase):
    _transfer_evm_native(label, dest, amount, passphrase, AVALANCHE_RPC, 43114, "AVAX",
                         "https://snowtrace.io/tx/")


def transfer_arbitrum(label, dest, amount, passphrase):
    _transfer_evm_native(label, dest, amount, passphrase, ARBITRUM_RPC, 42161, "ETH",
                         "https://arbiscan.io/tx/")


def transfer_optimism(label, dest, amount, passphrase):
    _transfer_evm_native(label, dest, amount, passphrase, OPTIMISM_RPC, 10, "ETH",
                         "https://optimistic.etherscan.io/tx/")


# ── TRANSFERT ERC-20 (USDC, DAI) ──────────────────────────────────────

def _transfer_erc20(label, dest, amount, passphrase, contract, decimals, symbol, explorer):
    """Transfert d'un token ERC-20 (USDC, DAI) sur Ethereum mainnet."""
    wallet_info = get_private_key(label, passphrase)
    private_key_hex = wallet_info["private_key_hex"]
    from_address = wallet_info["address"]
    rpc_url = get_working_eth_rpc()
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"[!] RPC non joignable : {rpc_url}", file=sys.stderr); sys.exit(1)
    print(f"[*] Connecté via {rpc_url} (block {w3.eth.block_number})")
    addr_padded = from_address.lower().replace("0x", "").rjust(64, "0")
    bal_resp = w3.eth.call({"to": Web3.to_checksum_address(contract),
                            "data": "0x70a08231" + addr_padded})
    balance = int(bal_resp.hex(), 16) / (10 ** decimals)
    print(f"[*] Solde {symbol} : {balance:.6f}")

    if amount <= 0:
        print(f"[!] Montant invalide : {amount} {symbol}", file=sys.stderr)
        sys.exit(1)

    # Encodage de transfer(address, uint256)
    dest_padded = dest.lower().replace("0x", "").rjust(64, "0")
    amount_raw = int(amount * (10 ** decimals))
    data = "0xa9059cbb" + dest_padded + hex(amount_raw)[2:].rjust(64, "0")

    nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(from_address))
    gas_price = w3.eth.gas_price
    gas_limit = 60000
    fee_eth = w3.from_wei(gas_price * gas_limit, 'ether')

    # Solde natif (ETH) nécessaire au gas
    native_balance_wei = w3.eth.get_balance(Web3.to_checksum_address(from_address))
    native_balance_eth = w3.from_wei(native_balance_wei, 'ether')

    # Vérification stricte ERC-20 : token + gas natif séparés (avant signature)
    check_erc20_funds(balance, amount, symbol,
                      native_balance_eth, fee_eth, "ETH")
    _confirm_send(symbol.lower(), dest, amount, symbol, fee_eth, "ETH")

    tx = {
        'nonce': nonce, 'to': Web3.to_checksum_address(contract), 'value': 0,
        'gas': 60000, 'gasPrice': gas_price, 'chainId': 1, 'data': data,
    }
    signed = EthAccount.sign_transaction(tx, private_key_hex)
    tx_hex = signed.raw_transaction.hex()
    print("[*] Transaction signée. Broadcast...")
    try:
        tx_hash = w3.eth.send_raw_transaction(tx_hex)
        print(f"✅ Transaction broadcastée ! TXID : {tx_hash.hex()}")
        print(f"   {explorer}{tx_hash.hex()}")
        log_transaction(symbol.lower(), label, dest, amount, tx_hash.hex(),
                        f"{explorer}{tx_hash.hex()}")
    except Exception as e:
        print(f"[!] Erreur broadcast : {e}", file=sys.stderr)


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
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"RPC {network} non joignable : {rpc_url}")

    wallet_info = get_private_key(label, passphrase)
    if wallet_info.get("asset_id") and wallet_info["asset_id"] != asset_id:
        raise ValueError("Le wallet source ne correspond pas au couple actif/réseau choisi")
    private_key = wallet_info["private_key_hex"]
    source = Web3.to_checksum_address(wallet_info["address"])
    target = Web3.to_checksum_address(dest)
    contract = Web3.to_checksum_address(spec["contract"])
    decimals = int(spec["decimals"])
    symbol = spec["asset"]

    source_padded = source[2:].lower().rjust(64, "0")
    raw_balance = w3.eth.call({"to": contract, "data": "0x70a08231" + source_padded})
    token_balance = int(raw_balance.hex(), 16) / (10 ** decimals)
    if amount <= 0:
        raise ValueError(f"Montant invalide : {amount} {symbol}")
    target_padded = target[2:].lower().rjust(64, "0")
    raw_amount = int(str(amount * (10 ** decimals)).split(".")[0])
    data = "0xa9059cbb" + target_padded + hex(raw_amount)[2:].rjust(64, "0")
    nonce = w3.eth.get_transaction_count(source)
    gas_price = w3.eth.gas_price
    estimate_tx = {"from": source, "to": contract, "value": 0, "data": data}
    gas_limit = int(w3.eth.estimate_gas(estimate_tx) * 1.2)
    fee = w3.from_wei(gas_price * gas_limit, "ether")
    native_balance = w3.from_wei(w3.eth.get_balance(source), "ether")
    check_erc20_funds(token_balance, amount, symbol, native_balance, fee, gas_symbol)
    _confirm_send(asset_id, dest, amount, symbol, fee, gas_symbol)
    tx = {"nonce": nonce, "to": contract, "value": 0, "gas": gas_limit,
          "gasPrice": gas_price, "chainId": chain_id, "data": data}
    signed = EthAccount.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    txid = tx_hash.hex()
    print(f"✅ Transaction broadcastée ! TXID : {txid}")
    print(f"   {explorer}{txid}")
    log_transaction(asset_id, label, dest, amount, txid, f"{explorer}{txid}")


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
                            label: str = "XMR"):
    """Transfert Monero (XMR) EN MODE NON-CUSTODIAL depuis un seed saisi.

    Permet de transférer sans wallets.enc : l'utilisateur fournit son
    mnémonique (export papier), le seed est restauré temporairement dans la
    passerelle, la tx est signée + diffusée, puis le wallet est fermé et le
    serveur le supprime (tmpfs + cleanup). Aucun seed ne persiste.
    """
    import xmr_gateway as xgw

    if not validate_address("monero", dest):
        print(t("send_addr_invalid", net="MONERO", dest=dest[:20]), file=sys.stderr)
        sys.exit(1)

    print(f"[*] Connexion à la passerelle XMR (via Tor)…")
    try:
        ver = xgw.get_version()
        print(f"[✓] Passerelle XMR jointe (version {ver.get('version')}).")

        wallet_name = f"ccw_{label}"
        xgw.open_or_restore_wallet(wallet_name, mnemonic)
        print(f"[✓] Wallet restauré côté passerelle ({wallet_name}).")

        bal = xgw.get_balance()
        unlocked = bal.get("unlocked_balance", 0) / 1e12
        total = bal.get("balance", 0) / 1e12
        print(f"[*] Solde XMR : total {total:.8f} / débloqué {unlocked:.8f}")

        XMR_MIN_FEE = 0.0001
        check_balance_with_fee(unlocked, float(amount), XMR_MIN_FEE, "XMR")

        print(f"[*] Création + diffusion via la passerelle…")
        print(f"    Destinataire : {dest}")
        print(f"    Montant      : {amount} XMR")
        res = xgw.transfer(dest, float(amount))
        tx_hashes = res.get("tx_hash_list") or [res.get("tx_hash")]
        for h in tx_hashes:
            print(f"[✓] Transaction diffusée. TX hash : {h}")
            log_transaction("xmr", label, dest, amount, h,
                            f"onion://{xgw.GATEWAY_ONION}:{xgw.GATEWAY_PORT}")
    except Exception as e:
        print(f"[!] Échec du transfert XMR : {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            xgw.close_wallet()
        except Exception:
            pass
    """Transfert Monero (XMR) via la passerelle monero-wallet-rpc.

    L'outil ne broadcaste JAMAIS en direct : il se connecte à la passerelle
    (service onion Tor sur la VM) à travers le SOCKS Tor local, restaure le
    wallet depuis le mnémonique, vérifie le solde, puis délègue la création +
    le broadcast à la passerelle. Celle-ci est elle-même derrière Tor côté
    serveur (kill-switch), donc aucune fuite clearnet.
    """
    import xmr_gateway as xgw

    wallet_info = get_private_key(label, passphrase)
    if wallet_info.get("network") != "monero":
        print(f"[!] Le wallet '{label}' n'est pas un wallet Monero.", file=sys.stderr)
        sys.exit(1)
    if not validate_address("monero", dest):
        print(t("send_addr_invalid", net="MONERO", dest=dest[:20]), file=sys.stderr)
        sys.exit(1)

    mnemonic = wallet_info.get("mnemonic")
    if not mnemonic:
        print("[!] Ce wallet Monero n'a pas de mnémonique stockée : "
              "impossible de le restaurer côté passerelle.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Wallet XMR '{label}' chargé (adresse: {wallet_info['address']}).")
    print("[*] Connexion à la passerelle XMR (via Tor)…")

    try:
        # 1) Test de disponibilité de la passerelle
        ver = xgw.get_version()
        print(f"[✓] Passerelle XMR jointe (version {ver.get('version')}).")

        # 2) Restauration / ouverture du wallet dans la passerelle
        wallet_name = f"ccw_{label}"
        xgw.open_or_restore_wallet(wallet_name, mnemonic)
        print(f"[✓] Wallet restauré côté passerelle ({wallet_name}).")

        # 3) Solde (atomic units -> XMR)
        bal = xgw.get_balance()
        unlocked = bal.get("unlocked_balance", 0) / 1e12
        total = bal.get("balance", 0) / 1e12
        print(f"[*] Solde XMR : total {total:.8f} / débloqué {unlocked:.8f}")

        # 4) Contrôle des fonds (frais réseau XMR ~ 0.0001 mini, on laisse la
        #    passerelle estimer ; on exige au moins le montant + une marge)
        XMR_MIN_FEE = 0.0001
        check_balance_with_fee(unlocked, float(amount), XMR_MIN_FEE, "XMR")

        # 5) Création + broadcast via la passerelle
        print(f"[*] Création + diffusion via la passerelle…")
        print(f"    Destinataire : {dest}")
        print(f"    Montant      : {amount} XMR")
        res = xgw.transfer(dest, float(amount))
        tx_hashes = res.get("tx_hash_list") or [res.get("tx_hash")]
        for h in tx_hashes:
            print(f"[✓] Transaction diffusée. TX hash : {h}")
            log_transaction("xmr", label, dest, amount, h,
                            f"onion://{xgw.GATEWAY_ONION}:{xgw.GATEWAY_PORT}")

    except Exception as e:
        print(f"[!] Échec du transfert XMR : {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Non-custodial : on ferme le wallet côté passerelle pour qu'il ne
        # reste pas ouvert. Le serveur supprime ensuite les fichiers (tmpfs
        # + cleanup timer), aucun seed ne persiste.
        try:
            xgw.close_wallet()
        except Exception:
            pass


# ── TRANSFERT SOLANA ────────────────────────────────────────────────────

def transfer_sol(label: str, dest_address: str, amount_sol: float, passphrase: str):
    """
    Envoie des SOL sur Solana via JSON-RPC (sans dépendre de solana.rpc.api
    qui a été retiré des versions récentes). Utilise solders pour signer.
    """
    wallet_info = get_private_key(label, passphrase)
    raw_key = wallet_info["private_key_base58"]

    # ── NETTOYAGE DU FORMAT b'...' ──
    raw_str = str(raw_key)
    if raw_str.startswith("b'") and raw_str.endswith("'"):
        raw_str = raw_str[2:-1]
    elif raw_str.startswith('b"') and raw_str.endswith('"'):
        raw_str = raw_str[2:-1]
    raw_str = raw_str.strip()

    print(f"[*] Clé parsée, création du keypair...")

    # Reconstituer le Keypair
    try:
        keypair = Keypair.from_base58_string(raw_str)
    except Exception as e:
        print(f"[!] Erreur base58 : {e}")
        try:
            # Tentative si c'est une liste de bytes
            key_bytes = bytes(map(int, raw_str.strip("[]").replace(" ", "").split(",")))
            keypair = Keypair.from_bytes(key_bytes)
        except Exception:
            print(f"[!] Impossible de reconstruire la clé.")
            print(f"[!] Début de la clé : {raw_str[:50]}...")
            sys.exit(1)

    pubkey = keypair.pubkey()
    dest_pubkey = Pubkey.from_string(dest_address)

    # ── Lectures RPC (JSON-RPC pur) ──
    def rpc(method, params):
        resp = requests.post(SOL_RPC_URL, json={"jsonrpc": "2.0", "id": 1,
                                                "method": method, "params": params}, timeout=15)
        return resp.json()

    # Solde
    try:
        bal = rpc("getBalance", [str(pubkey)])
        balance_lamports = bal["result"]["value"]
        balance_sol = balance_lamports / 1e9
        print(f"[*] Solde : {balance_sol:.9f} SOL")
    except Exception as e:
        print(f"[!] Impossible de récupérer le solde : {e}", file=sys.stderr)
        sys.exit(1)

    # Calcul du montant + réserve de frais
    # En Solana, le compte source DOIT rester "rent-exempt" : s'il descend
    # sous le minimum (~0.00089088 SOL), la tx échoue avec
    # InsufficientFundsForRent. On réserve donc RENT_EXEMPT_MIN + frais tx.
    # Frais réels d'une tx SOL native : ~5000 lamports (estimation réseau standard)
    FEE_LAMPORTS = 5000
    # Récupère le vrai minimum rent-exempt (sinon repli sur la constante connue)
    try:
        rent_resp = rpc("getMinimumBalanceForRentExemption", [0])
        RENT_EXEMPT_LAMPORTS = int(rent_resp["result"])
    except Exception:
        RENT_EXEMPT_LAMPORTS = 890880  # valeur standard mainnet (~0.00089088 SOL)
    RESERVE_LAMPORTS = RENT_EXEMPT_LAMPORTS + FEE_LAMPORTS
    if amount_sol == 0:
        # Envoi de la totalité : il faut garder le rent-exempt + les frais tx
        if balance_lamports <= RESERVE_LAMPORTS:
            print(f"[!] Solde insuffisant pour couvrir le rent-exempt "
                  f"({RENT_EXEMPT_LAMPORTS} lamports) + frais "
                  f"({FEE_LAMPORTS} lamports).", file=sys.stderr)
            sys.exit(1)
        amount_lamports = balance_lamports - RESERVE_LAMPORTS
        amount_sol = amount_lamports / 1e9
        print(f"[*] Envoi de la totalité (moins réserve) : {amount_sol:.9f} SOL")
        print(f"    (réserve conservée : {RENT_EXEMPT_LAMPORTS} lamports "
              f"rent-exempt + {FEE_LAMPORTS} lamports frais)")
    else:
        amount_lamports = int(amount_sol * 1e9)
        # Vérifie qu'il restera assez pour le rent-exempt après l'envoi
        if (balance_lamports - amount_lamports) < RESERVE_LAMPORTS:
            print(f"[!] Le compte tomberait sous le minimum rent-exempt "
                  f"({RENT_EXEMPT_LAMPORTS} lamports) + frais. "
                  f"Montant max envoiable : "
                  f"{(balance_lamports - RESERVE_LAMPORTS) / 1e9:.9f} SOL.",
                  file=sys.stderr)
            sys.exit(1)

    # Vérification stricte : solde >= montant + frais (avant broadcast)
    check_balance_with_fee(balance_lamports / 1e9, amount_sol,
                           FEE_LAMPORTS / 1e9, "SOL")
    _confirm_send("sol", dest_address, amount_sol, "SOL",
                  FEE_LAMPORTS / 1e9, "SOL")

    # Blockhash récent
    try:
        bh = rpc("getLatestBlockhash", [])
        recent_blockhash = Hash.from_string(bh["result"]["value"]["blockhash"])
    except Exception as e:
        print(f"[!] Erreur blockhash : {e}", file=sys.stderr)
        sys.exit(1)

    # Instruction + message + transaction (solders)
    ix = sol_transfer(TransferParams(
        from_pubkey=pubkey, to_pubkey=dest_pubkey, lamports=amount_lamports))
    msg = Message.new_with_blockhash([ix], pubkey, recent_blockhash)
    tx = SolTx.new_unsigned(msg)
    tx.sign([keypair], recent_blockhash)
    tx_bytes = bytes(tx)

    # Encodage base64 pour sendTransaction
    import base64 as _b64
    tx_b64 = _b64.b64encode(tx_bytes).decode()

    print("[*] Broadcast de la transaction...")
    try:
        result = rpc("sendTransaction", [tx_b64, {"encoding": "base64"}])
        if "result" in result:
            sig = result["result"]
            print(f"✅ Transaction broadcastée ! Signature : {sig}")
            print(f"   https://explorer.solana.com/tx/{sig}")
            log_transaction("sol", label, dest_address, amount_sol, sig,
                            f"https://explorer.solana.com/tx/{sig}")
        else:
            print(f"[!] Erreur broadcast : {result.get('error')}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Erreur broadcast : {e}", file=sys.stderr)


# ── SCAN DES RÉCEPTIONS SOLANA (transactions entrantes) ────────────────

def scan_sol_received(label: str, passphrase: str, limit: int = 25):
    """Interroge l'API Solana pour les transactions entrantes du wallet.

    Renvoie une liste de dicts :
      {"signature", "sender", "receiver", "amount_sol", "datetime", "url"}
    Le destinataire (= ton wallet) figure dans chaque entrée pour que
    l'historique affiche expéditeur + destinataire + TxID + date/heure.
    """
    from datetime import datetime as _dt, timezone as _tz

    wallet_info = get_private_key(label, passphrase)
    address = wallet_info["address"]

    def rpc(method, params):
        resp = requests.post(SOL_RPC_URL, json={"jsonrpc": "2.0", "id": 1,
                                                "method": method, "params": params},
                              timeout=15)
        return resp.json()

    # 1) Lister les signatures récentes de l'adresse
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
        # 2) Détail de la transaction pour extraire l'expéditeur et le montant
        try:
            tx_resp = rpc("getTransaction",
                          [sig, {"encoding": "jsonParsed",
                                 "maxSupportedTransactionVersion": 0}])
            tx = tx_resp.get("result")
            if not tx:
                continue
            # Horodatage (blockTime en secondes UTC)
            block_time = tx.get("blockTime")
            ts = (_dt.fromtimestamp(block_time, tz=_tz.utc)
                  .strftime("%Y-%m-%d %H:%M:%S")
                  if block_time else "inconnue")
            # Solde pré/post pour trouver le montant et le sens
            meta = tx.get("meta", {})
            pre = meta.get("preBalances", [])
            post = meta.get("postBalances", [])
            account_keys = (tx.get("transaction", {})
                            .get("message", {})
                            .get("accountKeys", []))
            # accountKeys peut être une liste de dict (jsonParsed)
            keys = []
            for k in account_keys:
                if isinstance(k, dict):
                    keys.append(k.get("pubkey"))
                else:
                    keys.append(k)
            if not keys or len(pre) != len(post) or address not in keys:
                continue
            idx = keys.index(address)
            delta = (post[idx] - pre[idx]) / 1e9  # en SOL
            if delta <= 0:
                continue  # ce n'est pas une réception sur ce wallet
            # L'expéditeur est l'autre compte dont le solde a diminué
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

    if network == "btc":
        try:
            resp = requests.get(f"{BTC_API_URL}/balance?active={address}", timeout=15)
            balance = resp.json().get("balance", 0) / 1e8
            print(f"[*] {label} ({address}) : {balance:.8f} BTC")
        except Exception as e:
            print(f"[!] Erreur BTC : {e}", file=sys.stderr)

    elif network == "eth":
        rpc_url = get_working_eth_rpc()
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if w3.is_connected():
            balance = w3.from_wei(
                w3.eth.get_balance(Web3.to_checksum_address(address)), 'ether'
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
            w3 = Web3(Web3.HTTPProvider(BSC_RPC))
            bal = w3.from_wei(w3.eth.get_balance(Web3.to_checksum_address(address)), 'ether')
            print(f"[*] {label} ({address}) : {bal:.6f} BNB")
        except Exception as e:
            print(f"[!] Erreur BNB : {e}", file=sys.stderr)

    elif network in ("polygon", "avalanche", "arbitrum", "optimism"):
        rpcs = {"polygon": POLYGON_RPC, "avalanche": AVALANCHE_RPC,
                "arbitrum": ARBITRUM_RPC, "optimism": OPTIMISM_RPC}
        syms = {"polygon": "MATIC", "avalanche": "AVAX",
                "arbitrum": "ARB", "optimism": "OP"}
        try:
            w3 = Web3(Web3.HTTPProvider(rpcs[network]))
            bal = w3.from_wei(w3.eth.get_balance(Web3.to_checksum_address(address)), 'ether')
            print(f"[*] {label} ({address}) : {bal:.6f} {syms[network]}")
        except Exception as e:
            print(f"[!] Erreur {network} : {e}", file=sys.stderr)

    elif network in ("xrp", "trx", "atom", "ada"):
        syms = {"xrp": "XRP", "trx": "TRX", "atom": "ATOM", "ada": "ADA"}
        print(f"[*] Solde {syms[network]} : utilisez 'python balance.py {network} {label}' "
              f"(lecture via API publique).")


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
                                         "usdc", "dai", "xrp", "trx", "atom", "ada"])
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

    elif args.command == "balance":
        check_balance(args.network, args.label, passphrase)


if __name__ == "__main__":
    main()
