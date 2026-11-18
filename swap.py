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

from decimal import Decimal
import os
import sys

try:
    import requests
except ImportError:  # pragma: no cover
    print("[!] Module 'requests' manquant (pip install requests)", file=sys.stderr)
    sys.exit(1)

from xmr_gateway import is_valid_xmr_address

API_BASE = "https://api.changenow.io"
TOR_SOCKS = "socks5h://127.0.0.1:9050"  # 'h' => DNS résolu via Tor
DEFAULT_TO = "xmr"


def _api_key() -> str:
    return os.environ.get("CHANGENOW_API_KEY", "").strip()


def _session() -> requests.Session:
    if not API_BASE.startswith("https://"):
        raise RuntimeError("Sécurité TLS : API_BASE doit utiliser HTTPS.")
    s = requests.Session()
    s.proxies.update({"http": TOR_SOCKS, "https": TOR_SOCKS})
    key = _api_key()
    if key:
        s.headers.update({"x-api-key": key})
    return s


def _is_onion_or_proxy() -> bool:
    return True  # on force toujours Tor pour ce module


def _validate_positive_amount(amount: float | Decimal | str) -> Decimal:
    val = Decimal(str(amount))
    if val <= 0:
        raise ValueError(f"Montant de swap invalide (doit être > 0) : {amount}")
    return val


def estimate(from_ticker: str, amount: float, to_ticker: str = DEFAULT_TO) -> dict:
    """Retourne l'estimation : montant de `to` obtenu pour `amount` de `from`."""
    amt = _validate_positive_amount(amount)
    s = _session()
    url = f"{API_BASE}/v2/exchange/estimated-amount"
    params = {"from": from_ticker.strip().lower(), "to": to_ticker.strip().lower(),
              "amount": str(amt)}
    r = s.get(url, params=params, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"ChangeNOW estimate {r.status_code}: {r.text[:200]}")
    return r.json()


def create_swap(from_ticker: str, xmr_receive_address: str,
                amount_from: float, to_ticker: str = DEFAULT_TO,
                extra_id: str | None = None,
                min_amount_to: float | Decimal | None = None,
                max_slippage_percent: float = 5.0) -> dict:
    """Crée un échange source -> XMR avec contrôle de destination et slippage.

    Renvoie le JSON ChangeNOW contenant :
      - id            : id de transaction (à garder pour le statut)
      - payinAddress  : adresse de dépôt (blockchain source) où envoyer la source
      - payinExtraId  : (optionnel) memo/tag pour certaines devises
      - amountFrom    : montant exact à envoyer
      - amountTo      : montant de XMR estimé à la réception
    """
    if not _api_key():
        raise RuntimeError("CHANGENOW_API_KEY non défini (export CHANGENOW_API_KEY=... ).")
    amt = _validate_positive_amount(amount_from)
    if not (0 < max_slippage_percent <= 50.0):
        raise ValueError("max_slippage_percent doit être compris entre 0 et 50%.")

    target_to = to_ticker.strip().lower()
    if target_to == "xmr" and not is_valid_xmr_address(xmr_receive_address):
        raise ValueError(
            f"Adresse Monero de réception invalide : {xmr_receive_address[:24]}..."
        )

    s = _session()
    url = f"{API_BASE}/v2/exchange"
    body = {
        "from": from_ticker.strip().lower(),
        "to": target_to,
        "amount": str(amt),
        "address": xmr_receive_address.strip(),
        "flow": "standard",
    }
    if extra_id:
        body["extraId"] = extra_id
    r = s.post(url, json=body, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"ChangeNOW create {r.status_code}: {r.text[:200]}")
    data = r.json()
    if not data.get("payinAddress"):
        raise RuntimeError("Réponse ChangeNOW invalide : payinAddress manquant.")

    if min_amount_to is not None and data.get("amountTo") is not None:
        expected_min = Decimal(str(min_amount_to)) * (
            Decimal("1") - Decimal(str(max_slippage_percent)) / Decimal("100")
        )
        actual_to = Decimal(str(data["amountTo"]))
        if actual_to < expected_min:
            raise RuntimeError(
                f"Slippage excessif sur le swap : reçu estimé {actual_to} < "
                f"minimum accepté {expected_min}."
            )
    return data


def get_status(tx_id: str, from_ticker: str | None = None,
               to_ticker: str | None = None) -> dict:
    """Statut d'un swap par son id (ChangeNOW v2 : GET /v2/exchange/status/{id})."""
    if not tx_id or not str(tx_id).strip():
        raise ValueError("Identifiant de transaction ChangeNOW invalide.")
    s = _session()
    url = f"{API_BASE}/v2/exchange/status/{str(tx_id).strip()}"
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
