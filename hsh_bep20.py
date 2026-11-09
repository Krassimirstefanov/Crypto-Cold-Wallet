#!/usr/bin/env python3
"""
hsh_bep20.py — Support HashCoin (HSH) sur BNB Smart Chain (BEP-20)

IMPORTANT
---------
HSH n'a PAS besoin d'une nouvelle clé privée ni d'une nouvelle adresse.
Il utilise l'adresse BSC/BNB 0x... déjà créée dans wallet_manager.py.

Le contrat ci-dessous est configurable par variable d'environnement afin
de pouvoir le remplacer sans modifier le code si l'adresse officielle change
ou doit être revalidée.

    export HSH_CONTRACT_ADDRESS="0x..."

Le module sait :
- lire les métadonnées du token ;
- lire le solde HSH d'une adresse BSC ;
- estimer le gas d'un transfert HSH ;
- construire, signer et diffuser un transfert HSH ;
- attendre et vérifier le reçu d'une transaction.

Le gas d'un transfert BEP-20 est payé en BNB.
"""

from __future__ import annotations

import os
from decimal import Decimal, ROUND_DOWN
from typing import Any, Optional

from web3 import Web3


BSC_CHAIN_ID = 56
DEFAULT_BSC_RPC = os.getenv("BSC_RPC_URL", "https://bsc-dataseed.binance.org/")

# Adresse HSH discutée pendant l'intégration.
# À revalider auprès d'une source officielle avant d'activer des transferts.
DEFAULT_HSH_CONTRACT = "0xA07eb39d960C8F1787A5B684874d2Fd897E623FA"
HSH_CONTRACT_ADDRESS = os.getenv("HSH_CONTRACT_ADDRESS", DEFAULT_HSH_CONTRACT)

BEP20_ABI = [
    {
        "name": "name",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "string"}],
    },
    {
        "name": "symbol",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "string"}],
    },
    {
        "name": "decimals",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
    },
    {
        "name": "balanceOf",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "name": "transfer",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
]


class HSHError(RuntimeError):
    """Erreur liée au support HSH/BEP-20."""


def get_web3(rpc_url: Optional[str] = None) -> Web3:
    """Crée une connexion Web3 à BNB Smart Chain."""
    w3 = Web3(Web3.HTTPProvider(rpc_url or DEFAULT_BSC_RPC))
    if not w3.is_connected():
        raise HSHError("Impossible de se connecter au RPC BNB Smart Chain.")
    try:
        chain_id = w3.eth.chain_id
    except Exception as exc:
        raise HSHError(f"Impossible de lire le chainId BSC : {exc}") from exc
    if chain_id != BSC_CHAIN_ID:
        raise HSHError(
            f"Mauvais réseau RPC : chainId={chain_id}, attendu={BSC_CHAIN_ID} (BSC)."
        )
    return w3


def get_hsh_contract(w3: Web3, contract_address: Optional[str] = None):
    """Retourne l'objet contrat HSH."""
    address = contract_address or HSH_CONTRACT_ADDRESS
    if not Web3.is_address(address):
        raise HSHError(f"Adresse de contrat HSH invalide : {address}")
    return w3.eth.contract(
        address=Web3.to_checksum_address(address),
        abi=BEP20_ABI,
    )


def get_hsh_token_info(
    w3: Optional[Web3] = None,
    contract_address: Optional[str] = None,
) -> dict[str, Any]:
    """Lit name/symbol/decimals directement depuis le contrat."""
    w3 = w3 or get_web3()
    contract = get_hsh_contract(w3, contract_address)
    try:
        return {
            "name": contract.functions.name().call(),
            "symbol": contract.functions.symbol().call(),
            "decimals": int(contract.functions.decimals().call()),
            "network": "BNB Smart Chain",
            "standard": "BEP-20",
            "chain_id": BSC_CHAIN_ID,
            "contract": contract.address,
        }
    except Exception as exc:
        raise HSHError(f"Impossible de lire les métadonnées HSH : {exc}") from exc


def _to_raw_amount(amount: Decimal | str | int | float, decimals: int) -> int:
    """Convertit un montant humain en unités atomiques sans utiliser float."""
    value = Decimal(str(amount))
    if value <= 0:
        raise HSHError("Le montant doit être supérieur à zéro.")
    factor = Decimal(10) ** decimals
    raw = (value * factor).quantize(Decimal("1"), rounding=ROUND_DOWN)
    return int(raw)


def _from_raw_amount(raw: int, decimals: int) -> Decimal:
    """Convertit les unités atomiques en montant lisible."""
    return Decimal(raw) / (Decimal(10) ** decimals)


def get_hsh_balance(
    address: str,
    w3: Optional[Web3] = None,
    contract_address: Optional[str] = None,
) -> Decimal:
    """Retourne le solde HSH d'une adresse BSC."""
    if not Web3.is_address(address):
        raise HSHError("Adresse BSC invalide.")

    w3 = w3 or get_web3()
    contract = get_hsh_contract(w3, contract_address)

    try:
        decimals = int(contract.functions.decimals().call())
        raw_balance = int(
            contract.functions.balanceOf(
                Web3.to_checksum_address(address)
            ).call()
        )
    except Exception as exc:
        raise HSHError(f"Impossible de lire le solde HSH : {exc}") from exc

    return _from_raw_amount(raw_balance, decimals)


def get_bnb_balance(
    address: str,
    w3: Optional[Web3] = None,
) -> Decimal:
    """Retourne le solde BNB utilisé pour payer le gas."""
    if not Web3.is_address(address):
        raise HSHError("Adresse BSC invalide.")
    w3 = w3 or get_web3()
    raw = w3.eth.get_balance(Web3.to_checksum_address(address))
    return Decimal(raw) / Decimal(10**18)


def build_hsh_transfer(
    from_address: str,
    destination: str,
    amount: Decimal | str | int | float,
    w3: Optional[Web3] = None,
    contract_address: Optional[str] = None,
) -> dict[str, Any]:
    """
    Construit une transaction HSH sans la signer.

    Utile pour inspection/confirmation dans l'interface avant signature.
    """
    if not Web3.is_address(from_address):
        raise HSHError("Adresse source BSC invalide.")
    if not Web3.is_address(destination):
        raise HSHError("Adresse destination BSC invalide.")

    w3 = w3 or get_web3()
    contract = get_hsh_contract(w3, contract_address)

    source = Web3.to_checksum_address(from_address)
    dest = Web3.to_checksum_address(destination)
    decimals = int(contract.functions.decimals().call())
    raw_amount = _to_raw_amount(amount, decimals)

    raw_balance = int(contract.functions.balanceOf(source).call())
    if raw_amount > raw_balance:
        human_balance = _from_raw_amount(raw_balance, decimals)
        raise HSHError(
            f"Solde HSH insuffisant : {human_balance} HSH disponible."
        )

    nonce = w3.eth.get_transaction_count(source, "pending")
    gas_price = w3.eth.gas_price

    base_tx = {
        "from": source,
        "nonce": nonce,
        "chainId": BSC_CHAIN_ID,
        "gasPrice": gas_price,
    }

    tx = contract.functions.transfer(dest, raw_amount).build_transaction(base_tx)

    try:
        tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.15)
    except Exception as exc:
        raise HSHError(f"Estimation du gas impossible : {exc}") from exc

    return tx


def estimate_hsh_transfer_fee(
    from_address: str,
    destination: str,
    amount: Decimal | str | int | float,
    w3: Optional[Web3] = None,
    contract_address: Optional[str] = None,
) -> dict[str, Decimal | int]:
    """Estime le gas et son coût en BNB."""
    w3 = w3 or get_web3()
    tx = build_hsh_transfer(
        from_address,
        destination,
        amount,
        w3=w3,
        contract_address=contract_address,
    )
    gas = int(tx["gas"])
    gas_price = int(tx["gasPrice"])
    fee_wei = gas * gas_price

    return {
        "gas": gas,
        "gas_price_wei": gas_price,
        "fee_wei": fee_wei,
        "fee_bnb": Decimal(fee_wei) / Decimal(10**18),
    }


def send_hsh(
    private_key_hex: str,
    destination: str,
    amount: Decimal | str | int | float,
    w3: Optional[Web3] = None,
    contract_address: Optional[str] = None,
) -> str:
    """
    Signe localement puis diffuse un transfert HSH.

    La clé privée ne quitte jamais ce processus Python.
    Retourne le hash de transaction 0x...
    """
    w3 = w3 or get_web3()

    try:
        account = w3.eth.account.from_key(private_key_hex)
    except Exception as exc:
        raise HSHError("Clé privée EVM invalide.") from exc

    tx = build_hsh_transfer(
        account.address,
        destination,
        amount,
        w3=w3,
        contract_address=contract_address,
    )

    # Vérifier qu'il existe assez de BNB pour le gas avant signature.
    fee_wei = int(tx["gas"]) * int(tx["gasPrice"])
    bnb_wei = w3.eth.get_balance(account.address)
    if bnb_wei < fee_wei:
        needed = Decimal(fee_wei) / Decimal(10**18)
        available = Decimal(bnb_wei) / Decimal(10**18)
        raise HSHError(
            f"BNB insuffisant pour le gas : {available} BNB disponible, "
            f"environ {needed} BNB requis."
        )

    try:
        signed = account.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None)
        if raw is None:
            # Compatibilité web3/eth-account plus anciens.
            raw = signed.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw)
    except Exception as exc:
        raise HSHError(f"Échec de signature/diffusion HSH : {exc}") from exc

    return tx_hash.hex()


def wait_for_hsh_transaction(
    tx_hash: str,
    w3: Optional[Web3] = None,
    timeout: int = 180,
) -> dict[str, Any]:
    """Attend le reçu et indique si la transaction a réussi."""
    w3 = w3 or get_web3()
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
    except Exception as exc:
        raise HSHError(f"Impossible d'obtenir le reçu : {exc}") from exc

    return {
        "tx_hash": tx_hash,
        "status": int(receipt.status),
        "success": int(receipt.status) == 1,
        "block_number": int(receipt.blockNumber),
        "gas_used": int(receipt.gasUsed),
    }


def get_hsh_transaction(
    tx_hash: str,
    w3: Optional[Web3] = None,
) -> dict[str, Any]:
    """Retourne les informations brutes principales d'une transaction BSC."""
    w3 = w3 or get_web3()
    try:
        tx = w3.eth.get_transaction(tx_hash)
    except Exception as exc:
        raise HSHError(f"Transaction introuvable : {exc}") from exc

    return {
        "hash": tx["hash"].hex(),
        "from": tx["from"],
        "to": tx["to"],
        "nonce": int(tx["nonce"]),
        "gas": int(tx["gas"]),
        "gas_price": int(tx["gasPrice"]),
        "block_number": tx["blockNumber"],
        "input": tx["input"].hex() if hasattr(tx["input"], "hex") else tx["input"],
    }


def find_bsc_wallet(wallets: dict, label: Optional[str] = None) -> tuple[str, dict]:
    """
    Retrouve un wallet BNB/BSC dans le dictionnaire produit par wallet_manager.py.

    Si label est fourni, exige que ce wallet soit bien un compte BSC.
    """
    if label:
        info = wallets.get(label)
        if not info:
            raise HSHError(f"Wallet '{label}' introuvable.")
        if info.get("network") != "bsc":
            raise HSHError(f"Wallet '{label}' n'est pas un wallet BSC.")
        return label, info

    matches = [
        (wallet_label, info)
        for wallet_label, info in wallets.items()
        if info.get("network") == "bsc"
    ]
    if not matches:
        raise HSHError("Aucun wallet BNB/BSC trouvé.")
    if len(matches) > 1:
        labels = ", ".join(label for label, _ in matches)
        raise HSHError(
            f"Plusieurs wallets BSC existent ({labels}). "
            "Préciser explicitement le label."
        )
    return matches[0]
