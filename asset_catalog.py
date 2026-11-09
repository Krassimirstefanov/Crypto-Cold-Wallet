"""Catalogue unique des actifs et de leurs réseaux.

Une clé représente toujours un couple actif/réseau. Cela évite de confondre,
par exemple, USDT Ethereum et USDT Solana lors du solde ou du broadcast.
"""

import unicodedata

ASSETS = {
    # Actifs natifs existants (un seul réseau, conformément à la consigne).
    "btc": {"asset": "BTC", "network": "bitcoin", "name": "Bitcoin (BTC)", "kind": "native", "generator": "generate_btc_wallet", "broadcast": True},
    "eth_ethereum": {"asset": "ETH", "network": "ethereum", "name": "ETH - Ethereum", "kind": "native", "generator": "generate_eth_wallet", "broadcast": True},
    "sol": {"asset": "SOL", "network": "solana", "name": "SOL - Solana", "kind": "native", "generator": "generate_sol_wallet", "broadcast": True},
    "ltc": {"asset": "LTC", "network": "litecoin", "name": "Litecoin (LTC)", "kind": "native", "generator": "generate_ltc_wallet", "broadcast": True},
    "doge": {"asset": "DOGE", "network": "dogecoin", "name": "Dogecoin (DOGE)", "kind": "native", "generator": "generate_doge_wallet", "broadcast": True},
    "bnb": {"asset": "BNB", "network": "bsc", "name": "BSC - BNB Smart Chain (BNB)", "kind": "native", "generator": "generate_bnb_wallet", "broadcast": True},
    "polygon": {"asset": "POL", "network": "polygon", "name": "POL - Polygon", "kind": "native", "generator": "generate_polygon_wallet", "broadcast": True},
    "avalanche": {"asset": "AVAX", "network": "avalanche", "name": "Avalanche C-Chain (AVAX)", "kind": "native", "generator": "generate_avalanche_wallet", "broadcast": True},
    "arbitrum": {"asset": "ETH", "network": "arbitrum", "name": "Arbitrum One (ETH)", "kind": "native", "generator": "generate_arbitrum_wallet", "broadcast": True},
    "optimism": {"asset": "ETH", "network": "optimism", "name": "OP Mainnet (ETH)", "kind": "native", "generator": "generate_optimism_wallet", "broadcast": True},
    "xrp": {"asset": "XRP", "network": "ripple", "name": "XRP Ledger (XRP)", "kind": "native", "generator": "generate_xrp_wallet", "broadcast": False},
    "trx": {"asset": "TRX", "network": "tron", "name": "TRX - Tron", "kind": "native", "generator": "generate_trx_wallet", "broadcast": False},
    "atom": {"asset": "ATOM", "network": "cosmos", "name": "Cosmos Hub (ATOM)", "kind": "native", "generator": "generate_atom_wallet", "broadcast": False},
    "ada": {"asset": "ADA", "network": "cardano", "name": "Cardano (ADA)", "kind": "native", "generator": "generate_ada_wallet", "broadcast": False},
    "xmr": {"asset": "XMR", "network": "monero", "name": "Monero (XMR)", "kind": "native", "generator": "generate_xmr_wallet", "broadcast": False},

    # Couples relevés sur les captures. Les variantes BEP-20 sont explicitement
    # nommées Binance-Peg : ce ne sont pas les jetons natifs des émetteurs.
    "eth_bsc": {"asset": "ETH", "network": "bsc", "name": "BSC - BNB Smart Chain (BEP20) · ETH Binance-Peg", "kind": "evm_token", "contract": "0x2170Ed0880ac9A755fd29B2688956BD959F933F8", "decimals": 18, "gas": "BNB", "broadcast": True},
    "usdt_ethereum": {"asset": "USDT", "network": "ethereum", "name": "ETH - Ethereum (ERC20) · USDT", "kind": "evm_token", "contract": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "decimals": 6, "gas": "ETH", "broadcast": True},
    "usdt_bsc": {"asset": "USDT", "network": "bsc", "name": "BSC - BNB Smart Chain (BEP20) · USDT Binance-Peg", "kind": "evm_token", "contract": "0x55d398326f99059fF775485246999027B3197955", "decimals": 18, "gas": "BNB", "broadcast": True},
    "usdt_polygon": {"asset": "USDT", "network": "polygon", "name": "POL - Polygon · USDT0", "kind": "evm_token", "contract": "0xc2132D05D31c914a87C6611C10748Aeb04B58e8F", "decimals": 6, "gas": "POL", "broadcast": True},
    "usdt_tron": {"asset": "USDT", "network": "tron", "name": "TRX - Tron (TRC20) · USDT", "kind": "trc20", "contract": "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj", "decimals": 6, "gas": "TRX", "broadcast": False},
    "usdt_solana": {"asset": "USDT", "network": "solana", "name": "SOL - Solana · USDT", "kind": "spl", "mint": "Es9vMFrzaCERmJfrF4H2FYD4KConky11McCe8BenwNYB", "decimals": 6, "gas": "SOL", "broadcast": False},
    "usdc_ethereum": {"asset": "USDC", "network": "ethereum", "name": "ETH - Ethereum (ERC20) · USDC", "kind": "evm_token", "contract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "decimals": 6, "gas": "ETH", "broadcast": True},
    "usdc_bsc": {"asset": "USDC", "network": "bsc", "name": "BSC - BNB Smart Chain (BEP20) · USDC Binance-Peg", "kind": "evm_token", "contract": "0x8AC76a51cc950d9822D68b83Fe1Ad97B32Cd580d", "decimals": 18, "gas": "BNB", "broadcast": True},
    "usdc_polygon": {"asset": "USDC", "network": "polygon", "name": "POL - Polygon · USDC", "kind": "evm_token", "contract": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "decimals": 6, "gas": "POL", "broadcast": True},
    "usdc_solana": {"asset": "USDC", "network": "solana", "name": "SOL - Solana · USDC", "kind": "spl", "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "decimals": 6, "gas": "SOL", "broadcast": False},
    "dai_ethereum": {"asset": "DAI", "network": "ethereum", "name": "ETH - Ethereum (ERC20) · DAI", "kind": "evm_token", "contract": "0x6B175474E89094C44Da98b954EedeAC495271d0F", "decimals": 18, "gas": "ETH", "broadcast": True},
    "dai_bsc": {"asset": "DAI", "network": "bsc", "name": "BSC - BNB Smart Chain (BEP20) · DAI Binance-Peg", "kind": "evm_token", "contract": "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", "decimals": 18, "gas": "BNB", "broadcast": True},
    "dai_polygon": {"asset": "DAI", "network": "polygon", "name": "POL - Polygon · DAI", "kind": "evm_token", "contract": "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", "decimals": 18, "gas": "POL", "broadcast": True},
    "sand_ethereum": {"asset": "SAND", "network": "ethereum", "name": "ETH - Ethereum (ERC20) · SAND", "kind": "evm_token", "contract": "0x3845badAde8e6dFF049820680d1F14bD3903a5d0", "decimals": 18, "gas": "ETH", "broadcast": True},
    "shib_ethereum": {"asset": "SHIB", "network": "ethereum", "name": "ETH - Ethereum (ERC20) · SHIB", "kind": "evm_token", "contract": "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", "decimals": 18, "gas": "ETH", "broadcast": True},
    "shib_bsc": {"asset": "SHIB", "network": "bsc", "name": "BSC - BNB Smart Chain (BEP20) · SHIB Binance-Peg", "kind": "evm_token", "contract": "0x2859e4544C4bB03966803b044A93563Bd2D0DD4D", "decimals": 18, "gas": "BNB", "broadcast": True},
    "pol_ethereum": {"asset": "POL", "network": "ethereum", "name": "ETH - Ethereum (ERC20) · POL", "kind": "evm_token", "contract": "0x455e53CBB86018Ac2B8092FdCd39d8444AffC3F6", "decimals": 18, "gas": "ETH", "broadcast": True},
    "trump_solana": {"asset": "TRUMP", "network": "solana", "name": "SOL - Solana · TRUMP", "kind": "spl", "mint": "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN", "decimals": 6, "gas": "SOL", "broadcast": False},
}

# Glyphes sobres, monochromes et adaptés aux terminaux. On évite ici les
# images et les emoji colorés dont la largeur varie selon le système.
ASSET_ICONS = {
    "BTC": "₿", "ETH": "♦", "SOL": "◎", "LTC": "Ł", "DOGE": "Ð",
    "BNB": "◆", "USDT": "₮", "USDC": "$", "DAI": "◈", "POL": "⬡",
    "AVAX": "▲", "XRP": "✕", "TRX": "◇", "ATOM": "⚛", "ADA": "₳",
    "XMR": "ɱ", "SAND": "▣", "SHIB": "◉", "TRUMP": "★", "HSH": "H",
}

NETWORK_ICONS = {
    "bitcoin": "₿", "ethereum": "♦", "solana": "◎", "litecoin": "Ł",
    "dogecoin": "Ð", "bsc": "◆", "polygon": "⬡", "avalanche": "▲",
    "arbitrum": "◇", "optimism": "○", "ripple": "✕", "tron": "◇",
    "cosmos": "⚛", "cardano": "₳", "monero": "ɱ",
}

NETWORK_NAMES = {
    "bitcoin": "Bitcoin", "ethereum": "Ethereum", "solana": "Solana",
    "litecoin": "Litecoin", "dogecoin": "Dogecoin",
    "bsc": "BNB Smart Chain", "polygon": "Polygon",
    "avalanche": "Avalanche", "arbitrum": "Arbitrum One",
    "optimism": "OP Mainnet", "ripple": "XRP Ledger", "tron": "Tron",
    "cosmos": "Cosmos Hub", "cardano": "Cardano", "monero": "Monero",
}


def asset_icon(value, default="¤"):
    """Icône d'un ticker ou d'un ``asset_id`` du catalogue."""
    key = str(value or "")
    spec = ASSETS.get(key)
    ticker = spec["asset"] if spec else key.upper()
    return ASSET_ICONS.get(ticker, NETWORK_ICONS.get(key.lower(), default))


def network_icon(value, default="◇"):
    key = str(value or "").strip().lower()
    aliases = {"btc": "bitcoin", "eth": "ethereum", "erc20": "ethereum",
               "sol": "solana", "spl": "solana", "ltc": "litecoin",
               "doge": "dogecoin", "bnb": "bsc", "bep20": "bsc",
               "pol": "polygon", "matic": "polygon", "avax": "avalanche",
               "arb": "arbitrum", "op": "optimism", "xrp": "ripple",
               "trx": "tron", "trc20": "tron", "atom": "cosmos",
               "ada": "cardano", "xmr": "monero"}
    return NETWORK_ICONS.get(aliases.get(key, key), default)


def display_width(text):
    """Largeur monospace approximative, sans dépendance externe."""
    width = 0
    for char in str(text):
        if unicodedata.combining(char) or ord(char) == 0xFE0F:
            continue
        width += 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
    return width


def icon_column(icon, width=2):
    return str(icon) + " " * max(0, width - display_width(icon))


def catalog_label(asset_id):
    """Libellé compact : icône actif + ticker · icône réseau + réseau."""
    spec = ASSETS[asset_id]
    asset = f"{icon_column(asset_icon(spec['asset']))} {spec['asset']}"
    network = f"{icon_column(network_icon(spec['network']))} {NETWORK_NAMES[spec['network']]}"
    if spec["kind"] == "evm_token":
        standard = {"ethereum": "ERC20", "bsc": "BEP20"}.get(
            spec["network"], "token"
        )
    else:
        standard = {"spl": "SPL", "trc20": "TRC20"}.get(spec["kind"])
    suffix = f" ({standard})" if standard else ""
    return f"{asset}  ·  {network}{suffix}"


def get(asset_id):
    return ASSETS.get(asset_id)


def creation_entries():
    return list(ASSETS.items())


def broadcast_entries():
    return [(key, value) for key, value in ASSETS.items() if value.get("broadcast")]
