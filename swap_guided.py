"""swap_guided.py — Conversion "guidée" vers XMR, SANS API tierce.

Aucun appel à un fournisseur de swap (pas de clé, pas de compte). On utilise
uniquement les cours publics CoinGecko (déjà disponibles dans le projet) pour
estimer combien de XMR on obtient pour une crypto source, puis on affiche les
instructions pour effectuer le swap manuellement (l'utilisateur fait le swap
sur un service externe de son choix, ou en peer-to-peer).

Le serveur XMR (Monero gateway) n'est PAS sollicité ici : il ne sert que pour
RENVOYER du XMR déjà détenu (transit/signature). Ce module ne fait que calculer
et guider.

Fonctions :
  estimate_to_xmr(from_ticker, amount_from) -> dict (taux, xmr estimé, USD)
  print_guide(from_ticker, amount_from, xmr_receive_address) -> affiche les
      instructions à l'écran.
"""
from __future__ import annotations

import sys

try:
    # Réutilise les prix CoinGecko déjà chargés par le projet.
    from menu import get_prices_usd
except Exception:  # pragma: no cover
    def get_prices_usd():
        return None


def estimate_to_xmr(from_ticker: str, amount_from: float) -> dict | None:
    """Estime le montant de XMR obtenu pour `amount_from` de `from_ticker`.

    Retourne None si les prix sont indisponibles.
    """
    prices = get_prices_usd()
    if not prices:
        return None
    src = prices.get(from_ticker.lower())
    xmr = prices.get("xmr")
    if not src or not xmr:
        return None
    usd = amount_from * src
    xmr_amount = usd / xmr
    return {
        "from": from_ticker.lower(),
        "amount_from": amount_from,
        "rate_src_usd": src,
        "xmr_usd": xmr,
        "usd_value": usd,
        "xmr_estimated": xmr_amount,
    }


def print_guide(from_ticker: str, amount_from: float,
                xmr_receive_address: str) -> None:
    """Affiche le guide de swap manuel vers XMR."""
    est = estimate_to_xmr(from_ticker, amount_from)
    print("\n" + "─" * 54)
    print("  CONVERSION GUIDÉE VERS XMR (sans API / sans compte)")
    print("─" * 54)
    if est is None:
        print("  [!] Cours indisponibles (CoinGecko injoignable).")
        print("      Vérifiez votre connexion / Tor.")
        return
    print(f"  Source           : {est['amount_from']} {est['from'].upper()}")
    print(f"  Valeur estimée   : {est['usd_value']:.2f} USD")
    print(f"  Taux XMR         : 1 XMR ≈ {est['xmr_usd']:.2f} USD")
    print(f"  ⇒ XMR estimé     : {est['xmr_estimated']:.8f} XMR")
    print()
    print("  Adresse XMR de RÉCEPTION (à fournir au service de swap) :")
    print(f"    {xmr_receive_address}")
    print()
    print("  ÉTAPES (swap manuel, hors-ligne de ce wallet) :")
    print("    1) Allez sur un service de swap (ex: ChangeNOW, SimpleSwap,")
    print("       FixedFloat, ou un pair P2P).")
    print(f"    2) Choisissez : {from_ticker.upper()} → XMR.")
    print("    3) Collez l'adresse XMR ci-dessus comme adresse de réception.")
    print(f"    4) Envoyez {est['amount_from']} {from_ticker.upper()} à l'adresse")
    print("       de dépôt fournie par le service (via l'option d'envoi")
    print("       de cette crypto dans le menu).")
    print("    5) Le service envoie le XMR vers votre adresse ci-dessus.")
    print("    6) Pour RENVOYER ce XMR à quelqu'un : menu → Transaction →")
    print("       XMR → 🔑 Transférer depuis un seed (passe par le serveur).")
    print("─" * 54)


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        tk, amt = sys.argv[1], float(sys.argv[2])
        addr = sys.argv[3] if len(sys.argv) > 3 else "4AYesauQUdb5wh8FHoLMFsN4pZokdNxtaMeKvZ1X2NcZFswPGhp7CMydmniZcWUS6vaucnmzKmbrEVkr7oyjrpoo57aw73T"
        print_guide(tk, amt, addr)
    else:
        print("Usage: python swap_guided.py <from> <amount> [xmr_address]")
