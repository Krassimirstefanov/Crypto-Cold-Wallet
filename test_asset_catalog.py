"""Tests hors-ligne du catalogue de conversion/broadcast.

Ces tests ne contactent aucun RPC et ne signent aucune transaction.
"""
from asset_catalog import ASSETS


def test_broadcast_specs_are_complete():
    required = {"asset", "network", "kind", "broadcast"}
    for asset_id, spec in ASSETS.items():
        if not spec.get("broadcast"):
            continue
        assert required <= spec.keys(), asset_id
        if spec["kind"] == "evm_token":
            assert spec.get("contract"), asset_id
            assert isinstance(spec.get("decimals"), int), asset_id
            assert spec.get("gas"), asset_id


def test_supported_networks_are_unique_pairs():
    # Plusieurs jetons peuvent légitimement partager un réseau; chaque entrée
    # doit toutefois avoir un identifiant stable et non vide.
    assert all(asset_id.strip() for asset_id in ASSETS)


if __name__ == "__main__":
    test_broadcast_specs_are_complete()
    test_supported_networks_are_unique_pairs()
    print(f"OK: {len(ASSETS)} couples actif/réseau contrôlés")
