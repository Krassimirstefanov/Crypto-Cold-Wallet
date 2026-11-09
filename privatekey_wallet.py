#!/usr/bin/env python3
"""
Multi-Blockchain Wallet Scanner - Pentest Tool
Scanne les balances de toutes les blockchains majeures à partir d'une clé privée.

⚠️  SÉCURITÉ : ne hardcodez JAMAIS une vraie clé privée dans ce fichier.
    Passez-la via l'argument --key ou via la variable d'environnement
    SCANNER_PRIVATE_KEY. La clé n'est jamais écrite sur disque par ce script.
"""

import json
import sys
import argparse
import os
from web3 import Web3

# ============================================================
# CONFIGURATION — la clé N'est PAS hardcodée ici.
# Priorité : --key > variable d'env SCANNER_PRIVATE_KEY > invite interactive.
# ============================================================
PRIVATE_KEY = None
# RPC ENDPOINTS
# ============================================================
RPC_URLS = {
    "Ethereum Mainnet": {
        "url": "https://eth.llamarpc.com",
        "chain_id": 1,
        "native": "ETH",
        "native_decimals": 18
    },
    "BSC Mainnet": {
        "url": "https://bsc-dataseed.binance.org/",
        "chain_id": 56,
        "native": "BNB",
        "native_decimals": 18
    },
    "Polygon Mainnet": {
        "url": "https://polygon-rpc.com",
        "chain_id": 137,
        "native": "MATIC",
        "native_decimals": 18
    },
    "Avalanche C-Chain": {
        "url": "https://api.avax.network/ext/bc/C/rpc",
        "chain_id": 43114,
        "native": "AVAX",
        "native_decimals": 18
    },
    "Arbitrum One": {
        "url": "https://arb1.arbitrum.io/rpc",
        "chain_id": 42161,
        "native": "ETH",
        "native_decimals": 18
    },
    "Optimism": {
        "url": "https://mainnet.optimism.io",
        "chain_id": 10,
        "native": "ETH",
        "native_decimals": 18
    },
    "Fantom Opera": {
        "url": "https://rpc.ftm.tools/",
        "chain_id": 250,
        "native": "FTM",
        "native_decimals": 18
    }
}

# ============================================================
# TOKENS PAR CHAINE (contrats standards)
# ============================================================
TOKENS_BY_CHAIN = {
    "Ethereum Mainnet": {
        "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "BUSD": "0x4Fabb145d64652a948d72533023f6E7A623C7C53",
        "DAI": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "WBTC": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "SHIB": "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE",
        "LINK": "0x514910771AF9Ca656af840dff83E8264EcF986CA",
        "UNI": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
        "MATIC": "0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0"
    },
    "BSC Mainnet": {
        "BUSD": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
        "USDT": "0x55d398326f99059fF775485246999027B3197955",
        "USDC": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
        "WBNB": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
        "DAI": "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3",
        "BTCB": "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c",
        "ETH": "0x2170Ed0880ac9A755fd29B2688956BD959F933F8",
        "CAKE": "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82",
        "XRP": "0x1D2F0da169ceB9fC7B3144628dB156f3F6c60dBE",
        "ADA": "0x3EE2200Efb3400fAbB9AacF31297cBdD1d435D47",
        "DOT": "0x7083609fCE4d1d8Dc0C979AAb8c869Ea2C873402"
    },
    "Polygon Mainnet": {
        "USDT": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
        "USDC": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
        "DAI": "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063",
        "WETH": "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619",
        "WBTC": "0x1bfd67037b42cf73acF2047067bd4F2C47D9BfD6",
        "MATIC": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
        "BUSD": "0xdAb529f40E671A1D4bF91361c21bf9f0C9712ab7",
        "LINK": "0x53E0bca35eC356BD5ddDFebbD1Fc0fD03FaBad39"
    },
    "Avalanche C-Chain": {
        "USDT": "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7",
        "USDC": "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
        "DAI": "0xd586E7F844cEa2F87f50152665BCbc2C279D8d70",
        "WETH": "0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB",
        "WBTC": "0x50b7545627a5162F82A992c33b87aDc75187B218",
        "AVAX": "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7"
    },
    "Arbitrum One": {
        "USDT": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
        "USDC": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        "DAI": "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1",
        "WETH": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
        "WBTC": "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f",
        "LINK": "0xf97f4df75117a78c1A5a0DBb814Af92458539FB4"
    },
    "Optimism": {
        "USDT": "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58",
        "USDC": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
        "DAI": "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1",
        "WETH": "0x4200000000000000000000000000000000000006",
        "WBTC": "0x68f180fcCe6836688e9084f035309E29Bf0A2095",
        "LINK": "0x350a791Bfc2C21F9Ed5d10980Dad2e2638ffa7f6"
    },
    "Fantom Opera": {
        "USDT": "0x049d68029688eAbF473097a2fC38ef61633A3C7A",
        "USDC": "0x04068DA6C83AFCFA0e13ba15A6696662335D5B75",
        "DAI": "0x8D11eC38a3EB5E956B052f67Da8Bdc9bef8Abf3E",
        "WETH": "0x74b23882a30290451A17c44f4F05243b6b58C76d",
        "WBTC": "0x321162Cd933E2Be498Cd2267a90534A804051b11",
        "LINK": "0xb3654dc3D10Ea7645f8319668E8F54d2574FBdC8",
        "FTM": "0x21be370D5312f44cB42ce377BC9b8a0cEF1A4C83"
    }
}

# ============================================================
# ABI MINIMAL ERC20
# ============================================================
MINIMAL_ERC20_ABI = json.loads('''
[
  {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
  {"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
  {"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
  {"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"}
]
''')


def format_balance(balance, decimals):
    """Formate un solde avec ses décimales."""
    return balance / (10 ** decimals)


def check_native_balance(w3, address, chain_name, chain_info):
    """Vérifie le solde natif (ETH, BNB, MATIC, etc.)"""
    try:
        balance = w3.eth.get_balance(address)
        formatted = format_balance(balance, chain_info["native_decimals"])
        if formatted > 0:
            return f"  [{chain_info['native']}] {formatted:.6f} {chain_info['native']}"
        return None
    except Exception as e:
        return f"  [!] Erreur solde natif: {e}"


def check_token_balances(w3, address, chain_name, tokens):
    """Vérifie les soldes de tous les tokens ERC20."""
    results = []
    for symbol, contract_address in tokens.items():
        try:
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(contract_address),
                abi=MINIMAL_ERC20_ABI
            )
            balance = contract.functions.balanceOf(
                Web3.to_checksum_address(address)
            ).call()
            if balance > 0:
                decimals = contract.functions.decimals().call()
                formatted = format_balance(balance, decimals)
                results.append(f"  [{symbol}] {formatted:.6f} {symbol}")
        except Exception as e:
            # On ignore silencieusement les erreurs individuelles de token
            pass
    return results


def scan_wallet(private_key):
    """Scanne toutes les blockchains pour une clé privée donnée."""
    
    # Dériver l'adresse publique
    w3_temp = Web3()
    account = w3_temp.eth.account.from_key(private_key)
    address = account.address
    
    print("=" * 64)
    print(f"  MULTI-BLOCKCHAIN WALLET SCANNER")
    print(f"  Adresse : {address}")
    print("=" * 64)
    print(f"  Clé privée : {private_key[:8]}...{private_key[-4:]}")
    print("=" * 64)
    
    total_usd_estimate = 0
    found_any = False
    
    for chain_name, chain_info in RPC_URLS.items():
        print(f"\n{'─' * 64}")
        print(f"  🌐 {chain_name} (Chain ID: {chain_info['chain_id']})")
        print(f"{'─' * 64}")
        
        try:
            w3 = Web3(Web3.HTTPProvider(chain_info["url"], request_kwargs={"timeout": 10}))
            
            if not w3.is_connected():
                print(f"  ⚠️  Impossible de se connecter au RPC")
                continue
            
            # 1. Balance native
            native_result = check_native_balance(w3, address, chain_name, chain_info)
            if native_result:
                print(native_result)
                found_any = True
            else:
                print(f"  [{chain_info['native']}] 0.000000 {chain_info['native']}")
            
            # 2. Balances tokens
            if chain_name in TOKENS_BY_CHAIN:
                token_results = check_token_balances(w3, address, chain_name, TOKENS_BY_CHAIN[chain_name])
                if token_results:
                    found_any = True
                    for r in token_results:
                        print(r)
                else:
                    print(f"  (aucun token avec solde > 0)")
            
            # 3. Derniers blocs / transactions (vérification activité)
            try:
                nonce = w3.eth.get_transaction_count(address)
                if nonce > 0:
                    print(f"  📜 {nonce} transactions (nonce)")
            except:
                pass
                
        except Exception as e:
            print(f"  ❌ Erreur de connexion: {e}")
    
    print(f"\n{'=' * 64}")
    if not found_any:
        print("  ❌ Aucun solde trouvé sur aucune blockchain.")
        print("  Suggestions :")
        print("    - Vérifiez que la clé privée est correcte (format hex)")
        print("    - Essayez sur testnet plutôt que mainnet")
        print("    - La clé est peut-être au format WIF (Bitcoin), pas EVM")
    else:
        print("  ✅ Soldes trouvés - cf. ci-dessus")
    print(f"{'=' * 64}")
    
    return address, found_any


# ============================================================
# POUR TRON (non-EVM, nécessite TronPy)
# ============================================================
def scan_tron(private_key_hex):
    """Optionnel: scanne Tron (USDT TRC20). Nécessite: pip install tronpy"""
    try:
        from tronpy import Tron
        from tronpy.keys import PrivateKey
        
        print(f"\n{'─' * 64}")
        print("  🌐 Tron Network (TRC20 Tokens)")
        print(f"{'─' * 64}")
        
        client = Tron(network='mainnet')
        
        # Convertir la clé hex en format Tron
        priv_key = PrivateKey(bytes.fromhex(private_key_hex))
        addr = priv_key.public_key.to_base58check_address()
        
        print(f"  Adresse Tron : {addr}")
        
        # Balance TRX native
        trx_balance = client.get_account_balance(addr)
        print(f"  [TRX] {trx_balance:.6f} TRX")
        
        # USDT TRC20
        usdt_trc20 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
        contract = client.get_contract(usdt_trc20)
        try:
            usdt_balance = contract.functions.balanceOf(addr) / 1e6
            if usdt_balance > 0:
                print(f"  [USDT] {usdt_balance:.2f} USDT (TRC20)")
        except:
            pass
        
        return True
    except ImportError:
        print("\n  ⚠️  TronPy non installé. Pour scanner Tron : pip install tronpy")
        return False
    except Exception as e:
        print(f"  ❌ Erreur Tron: {e}")
        return False


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Multi-Blockchain Wallet Scanner (pentest/recon)")
    parser.add_argument(
        "--key", "-k",
        help="Clé privée (hex, sans 0x). Évitez de la passer en clair sur "
             "une ligne de commande partagée ; préférez la variable "
             "d'environnement SCANNER_PRIVATE_KEY.")
    args = parser.parse_args()

    # Résolution de la clé : --key > env > invite interactive
    key = args.key or os.environ.get("SCANNER_PRIVATE_KEY")
    if not key:
        key = input("🔑 Clé privée (hex, sans 0x) : ").strip()

    if not key:
        print("❌ Aucune clé privée fournie. Arrêt.")
        sys.exit(1)

    # Enlever 0x si présent
    if key.startswith("0x"):
        key = key[2:]

    # Validation minimale : doit ressembler à une clé EVM (64 hex)
    if len(key) != 64 or any(c not in "0123456789abcdefABCDEF" for c in key):
        print("❌ Format de clé invalide : attendu 64 caractères hex (EVM).")
        sys.exit(1)

    print("\n" + "█" * 64)
    print("  WALLET SCANNER v2.0 - Multi-Blockchain")
    print("  🔒 Usage autorisé - Pentest")
    print("█" * 64)

    # Scan EVM chains
    address, found = scan_wallet(key)

    # Scan Tron optionnel
    scan_tron(key)

    print(f"\n✅ Scan terminé.")
