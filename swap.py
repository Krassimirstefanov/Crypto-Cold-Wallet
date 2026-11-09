"""swap.py — Conversion non-custodiale de n'importe quelle crypto vers XMR.

Utilise l'API publique ChangeNOW (https://changenow.io). Le serveur XMR
(Monero gateway) n'est PAS sollicité ici : le swap se fait côté client via
ChangeNOW, qui envoie directement du XMR vers l'adresse de réception de
l'utilisateur. Le serveur XMR ne sert que pour RENVOYER ce XMR (transit).

Flux :
  1. estimate(from, amount)        -> combien de XMR pour X source
  2. create_swap(from, xmr_addr, amount_from)
                                  -> adresse de dépôt (sur la blockchain source)
                                     + id de transaction ChangeNOW
  3. l'utilisateur envoie la source à l'adresse de dépôt (via transfer_*)
  4. ChangeNOW envoie le XMR vers xmr_addr
  5. (option) get_status(id)       -> statut du swap

Tous les appels passent par Tor (SOCKS 127.0.0.1:9050) pour masquer l'IP
vis-à-vis du fournisseur. La clé API est lue depuis l'environnement
CHANGENOW_API_KEY (jamais en dur dans le code).

Exigences : requests + PySocks (socks).
"""
from __future__ import annotations

import os
import sys
import time

try:
    import requests
except ImportError:  # pragma: no cover
    print("[!] Module 'requests' manquant (pip install requests)", file=sys.stderr)
    sys.exit(1)

API_BASE = "https://api.changenow.io"
TOR_SOCKS = "socks5h://127.0.0.1:9050"  # 'h' => DNS resolgu via Tor
DEFAULT_TO = "xmr"


def _api_key() -> str:
    return os.environ.get("CHANGENOW_API_KEY", "").strip()


def _session() -> requests.Session:
    s = requests.Session()
    s.proxies.update({"http": TOR_SOCKS, "https": TOR_SOCKS})
    key = _api_key()
    if key:
        s.headers.update({"x-api-key": key})
    return s


def _is_onion_or_proxy() -> bool:
    return True  # on force toujours Tor pour ce module


def estimate(from_ticker: str, amount: float, to_ticker: str = DEFAULT_TO) -> dict:
    """Retourne l'estimation : montant de `to` obtenu pour `amount` de `from`."""
    s = _session()
    url = f"{API_BASE}/v2/exchange/estimated-amount"
    params = {"from": from_ticker.lower(), "to": to_ticker.lower(),
              "amount": str(amount)}
    r = s.get(url, params=params, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"ChangeNOW estimate {r.status_code}: {r.text[:200]}")
    return r.json()


def create_swap(from_ticker: str, xmr_receive_address: str,
                amount_from: float, to_ticker: str = DEFAULT_TO,
                extra_id: str | None = None) -> dict:
    """Crée un échange source -> XMR.

    Renvoie le JSON ChangeNOW contenant :
      - id            : id de transaction (à garder pour le statut)
      - payinAddress  : adresse de dépôt (blockchain source) où envoyer la source
      - payinExtraId  : (optionnel) memo/tag pour certaines devises
      - amountFrom    : montant exact à envoyer
      - amountTo      : montant de XMR estimé à la réception
    """
    if not _api_key():
        raise RuntimeError("CHANGENOW_API_KEY non défini (export CHANGENOW_API_KEY=... ).")
    s = _session()
    url = f"{API_BASE}/v2/exchange"
    body = {
        "from": from_ticker.lower(),
        "to": to_ticker.lower(),
        "amount": str(amount_from),
        "address": xmr_receive_address,
        "flow": "standard",
    }
    if extra_id:
        body["extraId"] = extra_id
    r = s.post(url, json=body, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"ChangeNOW create {r.status_code}: {r.text[:200]}")
    return r.json()


def get_status(tx_id: str, from_ticker: str | None = None,
               to_ticker: str | None = None) -> dict:
    """Statut d'un swap par son id (ChangeNOW v2 : GET /v2/exchange/status/{id})."""
    s = _session()
    url = f"{API_BASE}/v2/exchange/status/{tx_id}"
    r = s.get(url, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"ChangeNOW status {r.status_code}: {r.text[:200]}")
    return r.json()


def list_currencies() -> list:
    """Liste des devises supportées (utile pour valider un ticker)."""
    s = _session()
    r = s.get(f"{API_BASE}/v2/currencies?active=true", timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"ChangeNOW currencies {r.status_code}: {r.text[:200]}")
    return r.json()


if __name__ == "__main__":
    # Test rapide (nécessite CHANGENOW_API_KEY exportée)
    if not _api_key():
        print("Export CHANGENOW_API_KEY pour tester.")
        sys.exit(0)
    try:
        est = estimate("btc", 0.01)
        print("ESTIMATE btc->xmr:", est)
    except Exception as e:
        print("ESTIMATE err:", e)
