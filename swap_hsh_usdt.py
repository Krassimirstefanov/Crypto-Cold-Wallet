#!/usr/bin/env python3
"""
swap_hsh_usdt.py — Échange HSH → USDT via PancakeSwap sur BNB Smart Chain.

Intégré au wallet : utilise la clé privée BSC existante (bsc_main),
le portefeuille reste autonome sans dépendre d'un service tiers permanent.

Le gas est payé en BNB ; si tu n'as pas de BNB, le swap est impossible.
"""

from __future__ import annotations

import json
import sys
from decimal import Decimal, ROUND_DOWN
from typing import Any, Optional

from web3 import Web3

from hsh_bep20 import (
    HSHError,
    get_bnb_balance,
    get_hsh_balance,
    get_hsh_contract,
    get_web3,
)

# ── Adresses BSC officielles ────────────────────────────────────────────

# PancakeSwap Router v2 — le DEX principal sur BSC
PANCAKE_ROUTER_V2 = "0x10ED43Cf75F6EE19FCbb9a7Cd484dC17cB0dCA8d"
PANCAKE_ROUTER_V2_CHECKSUM = Web3.to_checksum_address(PANCAKE_ROUTER_V2)

# USDT BEP-20 sur BSC
USDT_ADDRESS = "0x55d398326f990597f84e726300aaC22624619418"
USDT_CHECKSUM = Web3.to_checksum_address(USDT_ADDRESS)

# HSH BEP-20
HSH_CONTRACT = "0xA07eb39d960C8F1787A5B684874d2Fd897E623FA"
HSH_CHECKSUM = Web3.to_checksum_address(HSH_CONTRACT)

# ── RPC avec fallback ────────────────────────────────────────────────────

BSC_RPC_URLS = [
    "https://bsc-dataseed.binance.org/",
    "https://bsc-dataseed.ninicoin.io",
    "https://rpc.ankr.com/bsc",
    "https://bsc.rpc.thirdweb.com",
    "https://rpc.publicgood.io/bsc/mainnet",
]


def get_web3_fallback() -> Web3:
    """Tente chaque RPC jusqu'à ce que l'un fonctionne."""
    last_err = None
    for rpc_url in BSC_RPC_URLS:
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))
            if w3.is_connected():
                chain_id = w3.eth.chain_id
                if chain_id == 56:
                    return w3
            last_err = f"chain_id={w3.eth.chain_id}, attendu 56"
        except Exception as exc:
            last_err = str(exc)
    raise HSHError(f"Aucun RPC BSC disponible. Dernier essai: {last_err}")


# ── ABI PancakeSwap Router v2 (fonctions utilisées) ─────────────────────

PANCAKE_ROUTER_ABI = [
    # approve (ERC-20)
    {
        "inputs": [
            {"name": "token", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    # swapExactTokensForTokens
    {
        "inputs": [
            {"name": "amountIn", "type": "uint256"},
            {"name": "amountOutMin", "type": "uint256"},
            {"name": "path", "type": "address[]"},
            {"name": "to", "type": "address"},
            {"name": "deadline", "type": "uint256"},
        ],
        "name": "swapExactTokensForTokens",
        "outputs": [{"name": "amounts", "type": "uint256[]"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    # getAmountsOut — pour estimer le taux de swap
    {
        "inputs": [
            {"name": "amountIn", "type": "uint256"},
            {"name": "path", "type": "address[]"},
        ],
        "name": "getAmountsOut",
        "outputs": [{"name": "amounts", "type": "uint256[]"}],
        "stateMutability": "view",
        "type": "function",
    },
    # quote
    {
        "inputs": [
            {"name": "amountIn", "type": "uint256"},
            {"name": "reserveIn", "type": "uint256"},
            {"name": "reserveOut", "type": "uint256"},
        ],
        "name": "quote",
        "outputs": [
            {"name": "amountOut", "type": "uint256"},
            {"name": "amountInMaximum", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


def get_pancake_router(w3: Web3):
    """Retourne l'objet contrat du router PancakeSwap."""
    return w3.eth.contract(
        address=PANCAKE_ROUTER_V2_CHECKSUM,
        abi=PANCAKE_ROUTER_ABI,
    )


# ── ABI ERC-20 générique (pour USDT et HSH) ─────────────────────────────

ERC20_ABI = [
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "name": "allowance",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]


def get_erc20_contract(w3: Web3, token_address: str):
    """Retourne l'objet contrat ERC-20 (USDT ou HSH)."""
    addr = Web3.to_checksum_address(token_address)
    return w3.eth.contract(address=addr, abi=ERC20_ABI)


# ── Helpers de conversion ────────────────────────────────────────────────


def _to_raw(amount: Decimal | str | int | float, decimals: int) -> int:
    val = Decimal(str(amount))
    if val <= 0:
        raise HSHError("Montant doit être > 0")
    factor = Decimal(10) ** decimals
    return int((val * factor).quantize(Decimal("1"), rounding=ROUND_DOWN))


def _from_raw(raw: int, decimals: int) -> Decimal:
    return Decimal(raw) / (Decimal(10) ** decimals)


# ── Fonction principale : swap HSH → USDT ───────────────────────────────


def swap_hsh_to_usdt(
    private_key_hex: str,
    bsc_address: str,
    hsh_amount: Decimal | str | int | float,
    min_usdt_out: Optional[Decimal] = None,
    slippage_percent: float = 5.0,
    rpc_url: Optional[str] = None,
) -> dict[str, Any]:
    """
    Échange HSH → USDT via PancakeSwap Router v2 sur BSC.

    Args :
        private_key_hex : clé privée BSC hex (depuis wallet BNB)
        bsc_address     : adresse BSC à partir de laquelle le swap est fait
        hsh_amount      : quantité HSH à échanger
        min_usdt_out    : montant USDT minimum attendu (optionnel)
                          Si None, calculé automatiquement avec le slippage
        slippage_percent: pourcentage de slippage autorisé (défaut 5%)
        rpc_url         : URL RPC BSC optionnelle (null = fallback automatique)

    Returns :
        dict avec :
            - txid         : hash de la transaction de swap
            - hsh_swapped  : montant HSH échangé (atomique)
            - usdt_received: montant USDT reçu (atomique)
            - hsh_human    : HSH échangé en format lisible
            - usdt_human   : USDT reçu en format lisible
            - gas_used     : gas utilisé (en unités)
            - gas_price_gwei: prix du gas en gwei
            - bsc_rpc      : RPC utilisé
            - deadline     : deadline de la transaction
    """
    hsh_amount_dec = Decimal(str(hsh_amount))
    if hsh_amount_dec <= 0:
        raise HSHError("Le montant HSH doit être > 0")

    # Connexion
    w3 = get_web3_fallback() if rpc_url is None else get_web3(rpc_url)

    # Récupérer les informations du token
    hsh_contract = get_hsh_contract(w3)
    hsh_decimals = int(hsh_contract.functions.decimals().call())
    hsh_raw = _to_raw(hsh_amount_dec, hsh_decimals)

    # Récupérer allowance actuelle
    hsh_erc20 = get_erc20_contract(w3, HSH_CONTRACT)
    current_allowance = hsh_erc20.functions.allowance(
        Web3.to_checksum_address(bsc_address),
        PANCAKE_ROUTER_V2_CHECKSUM,
    ).call()

    if current_allowance < hsh_raw:
        # Approuver le router
        print(f"  ↻ Approuvons {hsh_amount_dec} HSH pour PancakeSwap...")
        approve_txn = hsh_erc20.functions.approve(
            PANCAKE_ROUTER_V2_CHECKSUM,
            hsh_raw,
        ).build_transaction({
            "from": Web3.to_checksum_address(bsc_address),
            "gas": 50000,
            "gasPrice": w3.eth.gas_price,
            "nonce": w3.eth.get_transaction_count(
                Web3.to_checksum_address(bsc_address)
            ),
            "chainId": 56,
        })
        signed_approve = w3.eth.account.sign_transaction(
            approve_txn, private_key_hex
        )
        approve_txid = w3.eth.send_raw_transaction(signed_approve.raw_transaction)
        w3.eth.wait_for_transaction_receipt(approve_txid, timeout=120)
        print(f"  ✓ Approbation envoyée : {w3.to_hex(approve_txid)}")

    # Estimer le taux de swap
    router = get_pancake_router(w3)
    try:
        amounts = router.functions.getAmountsOut(
            hsh_raw,
            [HSH_CHECKSUM, USDT_CHECKSUM],
        ).call()
        usdt_out_raw = amounts[-1]
    except Exception as exc:
        raise HSHError(f"Impossible d'estimer le taux de swap : {exc}") from exc

    usdt_decimals = 6  # USDT a 6 décimales
    usdt_out_dec = _from_raw(usdt_out_raw, usdt_decimals)

    # Slippage : amountOutMin = usdt_out * (1 - slippage/100)
    min_out_raw = int(
        usdt_out_raw * (1 - slippage_percent / 100)
    )

    if min_usdt_out is not None:
        min_out_raw = max(
            min_out_raw,
            _to_raw(min_usdt_out, usdt_decimals),
        )

    deadline = w3.eth.get_block("latest")["timestamp"] + 300  # 5 min

    # Construire la transaction de swap
    swap_txn = router.functions.swapExactTokensForTokens(
        hsh_raw,
        min_out_raw,
        [HSH_CHECKSUM, USDT_CHECKSUM],
        Web3.to_checksum_address(bsc_address),
        deadline,
    ).build_transaction({
        "from": Web3.to_checksum_address(bsc_address),
        "gas": 300000,
        "gasPrice": w3.eth.gas_price,
        "nonce": w3.eth.get_transaction_count(
            Web3.to_checksum_address(bsc_address)
        ),
        "chainId": 56,
    })

    # Signer et envoyer
    signed_swap = w3.eth.account.sign_transaction(
        swap_txn, private_key_hex
    )
    swap_txid = w3.eth.send_raw_transaction(signed_swap.raw_transaction)

    # Attendre la confirmation
    receipt = w3.eth.wait_for_transaction_receipt(swap_txid, timeout=180)

    # Lire le montant USDT reçu (déduction du gas, si applicable)
    usdt_balance_before = get_erc20_contract(w3, USDT_ADDRESS).functions.balanceOf(
        Web3.to_checksum_address(bsc_address)
    ).call()
    usdt_balance_after = get_erc20_contract(w3, USDT_ADDRESS).functions.balanceOf(
        Web3.to_checksum_address(bsc_address)
    ).call()
    usdt_received_raw = usdt_balance_after - usdt_balance_before
    usdt_received_dec = _from_raw(usdt_received_raw, usdt_decimals)

    return {
        "txid": w3.to_hex(swap_txid),
        "hsh_swapped_raw": hsh_raw,
        "usdt_received_raw": usdt_received_raw,
        "hsh_human": _from_raw(hsh_raw, hsh_decimals),
        "usdt_human": usdt_received_dec,
        "gas_used": receipt["gasUsed"],
        "gas_price_gwei": receipt["gasPrice"] / 1e9,
        "bsc_rpc": w3.provider.url if hasattr(w3.provider, "url") else "inconnu",
        "deadline": deadline,
        "bsc_address": bsc_address,
        "usdt_balance_after": _from_raw(usdt_balance_after, usdt_decimals),
        "hsh_balance_after": get_hsh_balance(bsc_address, w3),
    }


# ── Guide utilisateur ────────────────────────────────────────────────────


def print_swap_guide(step: str = "start") -> None:
    """Affiche un guide étape par étape pour l'échange HSH → USDT."""
    guides = {
        "start": """
╔══════════════════════════════════════════════════════════════════════╗
║  GUIDE D'ÉCHANGE HSH → USDT (BNB Smart Chain)                      ║
╚══════════════════════════════════════════════════════════════════════╝

PRÉREQUIS :
  • Wallet BNB (bsc_main) avec au moins 0.002 BNB pour le gas
  • 1240 HSH reçus sur le wallet
  • Connexion Internet

ÉTAPE 1 — Vérifier le solde BNB (gas)
  ./menu.py → choix 2 → passphrase
  Le wallet bsc_main doit afficher BNB > 0.002

ÉTAPE 2 — Lancer le swap
  ./menu.py → choix 5 (Échanger)
  → source : hsh
  → montant : 1240 (ou le montant que tu veux)
  → Le swap s'exécute via PancakeSwap sur BSC

ÉTAPE 3 — Vérifier le résultat
  ./menu.py → choix 2 → passphrase
  Le wallet bsc_main doit maintenant afficher :
    🔶 bsc_main    BNB  0x...  0.XXX BNB  (gas utilisé)
    🟡 HashCoin (HSH): X.XXX HSH  (solde restant)
    💲 USDT: X.XXX USDT  (nouveau solde)

POINTS D'ATTENTION :
  • Si le swap échoue avec "insufficient BNB pour le gas", tu as
    besoin d'acheter/transferrer du BNB sur ce wallet
  • Le slippage est de 5% par défaut : le taux peut varier
  • Les transactions sont on-chain, vérifiables sur BscScan :
    https://bscscan.com/tx/<TXID>
""",
        "no_bnb": """
╔══════════════════════════════════════════════════════════════════════╗
║  ERREUR : BNB INSUFFISANT POUR LE GAS                               ║
╚══════════════════════════════════════════════════════════════════════╝

Le swap nécessite du BNB pour payer le gas (environ 0.002-0.005 BNB).

 SOLUTIONS :
  1. Transférer du BNB depuis un autre wallet vers bsc_main
  2. Acheter BNB sur un exchange et le retraverser sur bsc_main
  3. Utiliser un autre wallet qui a du BNB (à créer)

Le gas pour un swap HSH→USDT est estimé à ~0.002 BNB (150 000 gas ×
prix du gas ~1-2 Gwei). Vérifie avec :
  ./menu.py → choix 2 → passphrase
  → section bsc_main : BNB solde
""",
        "done": """
╔══════════════════════════════════════════════════════════════════════╗
║  SWAP TERMINÉ                                                       ║
╚══════════════════════════════════════════════════════════════════════╝

Ton échange HSH → USDT est terminé.

Ce qui a été fait :
  • HSH échangé : {hsh_human} HSH
  • USDT reçu   : {usdt_human} USDT
  • Transaction : {txid}
  • Gas utilisé : {gas_used} (prix : {gas_price} Gwei)
  • RPC utilisé : {rpc}

Vérification :
  ./menu.py → choix 2 → passphrase
  Le solde USDT du wallet bsc_main doit être visible.

Sur BscScan :
  https://bscscan.com/tx/{txid}

Note : si le swap échoue à l'avenir (RPC HS, réseau congestionné),
réessaie simplement — le wallet lui-même gère les RPC alternatifs.
""",
    }
    print(guides.get(step, guides["start"]))


# ── Intégration menu — affichage USDT ────────────────────────────────────


USDT_SYMBOL = "💲"
USDT_NETWORK = "bsc"  # USDT BEP-20 sur BSC — même adresse que BNB


def get_usdt_balance(bsc_address: str) -> Decimal:
    """Lit le solde USDT BEP-20 sur BSC pour une adresse."""
    w3 = get_web3_fallback()
    usdt = get_erc20_contract(w3, USDT_ADDRESS)
    raw = usdt.functions.balanceOf(Web3.to_checksum_address(bsc_address)).call()
    return _from_raw(raw, 6)


# ── Export pour le menu ──────────────────────────────────────────────────

__all__ = [
    "swap_hsh_to_usdt",
    "get_usdt_balance",
    "print_swap_guide",
    "PANCAKE_ROUTER_V2",
    "USDT_ADDRESS",
    "HSH_CONTRACT",
    "BSC_RPC_URLS",
]
