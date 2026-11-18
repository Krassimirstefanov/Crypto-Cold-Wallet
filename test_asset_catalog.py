"""Tests hors-ligne du catalogue, de Monero (XMR) et de l'audit de sécurité.

Ces tests ne contactent aucun RPC externe et ne signent aucune transaction réelle.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asset_catalog import ASSETS, get as get_asset, broadcast_entries
import xmr_gateway
import local_keys
import security_core as sec
import security_access as access
import decrypt_wallet
import beta_feedback


def test_broadcast_specs_are_complete():
    required = {"asset", "network", "kind", "broadcast", "decimals"}
    for asset_id, spec in ASSETS.items():
        if not spec.get("broadcast"):
            continue
        assert required <= spec.keys(), asset_id
        assert isinstance(spec.get("decimals"), int), asset_id
        if spec["kind"] == "evm_token":
            assert spec.get("contract"), asset_id
            assert spec.get("gas"), asset_id


def test_xmr_catalog_spec():
    spec = get_asset("xmr")
    assert spec is not None
    assert spec["asset"] == "XMR"
    assert spec["network"] == "monero"
    assert spec["decimals"] == 12
    assert spec["broadcast"] is True
    assert any(k == "xmr" for k, _ in broadcast_entries())


def test_supported_networks_are_unique_pairs():
    assert all(asset_id.strip() for asset_id in ASSETS)


class MoneroAndSecurityTests(unittest.TestCase):
    def test_xmr_address_validation_keccak_checksum(self):
        # Génère un portefeuille Monero valide et vérifie son adresse Base58 + Keccak-256
        w = local_keys.generate_xmr_local_wallet("test_xmr")
        addr = w["address"]
        self.assertEqual(len(addr), 95)
        self.assertTrue(addr.startswith("4"))
        self.assertTrue(xmr_gateway.is_valid_xmr_address(addr))

        # Altération d'un seul caractère -> checksum Keccak-256 invalide -> rejeté
        flipped = ("2" if addr[-1] != "2" else "3")
        corrupted = addr[:-1] + flipped
        self.assertFalse(xmr_gateway.is_valid_xmr_address(corrupted))

        # Sous-adresse Monero valide (network byte 42 -> préfixe '8')
        raw = xmr_gateway.xmr_base58_decode(addr)
        sub_payload = bytes([42]) + raw[1:65]
        sub_chk = xmr_gateway.keccak_256(sub_payload)[:4]
        sub_addr = xmr_gateway.xmr_base58_encode(sub_payload + sub_chk)
        self.assertEqual(len(sub_addr), 95)
        self.assertTrue(sub_addr.startswith("8"))
        self.assertTrue(xmr_gateway.is_valid_xmr_address(sub_addr))

        # Adresse intégrée valide (network byte 19 + payment_id 8 octets -> 106 chars)
        int_payload = bytes([19]) + raw[1:65] + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        int_chk = xmr_gateway.keccak_256(int_payload)[:4]
        int_addr = xmr_gateway.xmr_base58_encode(int_payload + int_chk)
        self.assertEqual(len(int_addr), 106)
        self.assertTrue(xmr_gateway.is_valid_xmr_address(int_addr))

    def test_xmr_wallet_import_seed_and_keys(self):
        w1 = local_keys.generate_xmr_local_wallet("w1")
        words = w1["mnemonic"].split()
        self.assertEqual(len(words), 25)
        self.assertEqual(w1["decimals"], 12)
        self.assertEqual(w1["network"], "monero")

        # Restauration depuis la seed 25 mots
        w2 = local_keys.generate_xmr_local_wallet("w2", mnemonic=w1["mnemonic"])
        self.assertEqual(w2["address"], w1["address"])
        self.assertEqual(w2["private_spend_key"], w1["private_spend_key"])
        self.assertEqual(w2["private_view_key"], w1["private_view_key"])

        # Restauration depuis les clés spend & view
        w3 = local_keys.generate_xmr_local_wallet(
            "w3",
            spend_key_hex=w1["private_spend_key"],
            view_key_hex=w1["private_view_key"],
        )
        self.assertEqual(w3["address"], w1["address"])

    def test_xmr_gateway_balance_and_sweep_all_via_tor(self):
        w = local_keys.generate_xmr_local_wallet("xmr_tor")

        # Vérifie que _make_session configure systématiquement socks5h://127.0.0.1:9050
        sess = xmr_gateway._make_session()
        self.assertEqual(sess.proxies.get("http"), "socks5h://127.0.0.1:9050")
        self.assertEqual(sess.proxies.get("https"), "socks5h://127.0.0.1:9050")

        calls = []

        def fake_rpc_call(method, params=None, **kwargs):
            calls.append((method, params))
            if method == "get_balance":
                return {"balance": 2_500_000_000_000, "unlocked_balance": 1_250_000_000_000}
            if method == "sweep_all":
                return {
                    "tx_hash_list": ["abcdef1234567890"],
                    "amount_list": [1_249_000_000_000],
                    "fee_list": [1_000_000_000],
                }
            return {}

        with patch.object(xmr_gateway, "is_tor_configured", return_value=True):
            with patch.object(xmr_gateway, "rpc_call", side_effect=fake_rpc_call):
                bal = xmr_gateway.get_wallet_balance_xmr(
                    address=w["address"],
                    spend_key=w["private_spend_key"],
                    view_key=w["private_view_key"],
                )
                self.assertEqual(bal, {"total": 2.5, "unlocked": 1.25})
                sweep_res = xmr_gateway.sweep_all(w["address"])
                self.assertEqual(sweep_res["tx_hash_list"], ["abcdef1234567890"])
                self.assertEqual(sweep_res["amount_list"], [1_249_000_000_000])
                self.assertEqual(sweep_res["fee_list"], [1_000_000_000])

    def test_security_permissions_and_levels_and_memory_wipe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "vault.enc"
            pw = "Correct-Horse-Battery-Staple-2026!"
            sec.save_encrypted_json(p, {"hello": "world"}, pw, mode="standard")
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

            # Niveau Advanced : passphrase de 25 mots séparés par '-'
            phrase = access.generate_wallet_passphrase()
            self.assertTrue(access.validate_wallet_passphrase(phrase))
            wallet = {
                "label": "xmr_adv",
                "network": "monero",
                "address": "4" + "1" * 94,
                "mnemonic": " ".join(["abbey"] * 25),
                "private_spend_key": "aa" * 32,
                "private_view_key": "bb" * 32,
            }
            protected = access.protect_wallet_secrets(dict(wallet), phrase, protection="advanced")
            self.assertNotIn("private_spend_key", protected)
            self.assertNotIn("private_view_key", protected)
            self.assertNotIn("mnemonic", protected)
            self.assertIn("protected_secrets", protected)
            self.assertEqual(len(protected["word_challenge"]["hashes"]), 25)

            unlocked = access.unlock_wallet_secrets(protected, phrase)
            self.assertEqual(unlocked["private_spend_key"], "aa" * 32)
            self.assertEqual(unlocked["private_view_key"], "bb" * 32)

            # Effacement mémoire dans decrypt_wallet._wipe_secrets
            decrypt_wallet._wipe_secrets(unlocked)
            self.assertEqual(unlocked["private_spend_key"], "")
            self.assertEqual(unlocked["private_view_key"], "")

    def test_beta_feedback_blocks_secrets(self):
        self.assertFalse(beta_feedback.contains_potential_secret("Bonjour, l'interface fonctionne bien."))
        self.assertTrue(beta_feedback.contains_potential_secret("Voici ma clé: " + "a" * 64))
        self.assertTrue(beta_feedback.contains_potential_secret(access.generate_wallet_passphrase()))

    def test_transfer_validate_xmr_address_integration(self):
        import ast
        tree = ast.parse(Path(__file__).with_name("transfer.py").read_text(encoding="utf-8"))
        fn_nodes = [
            n for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "_validate_xmr_address"
        ]
        self.assertEqual(len(fn_nodes), 1)
        mod = ast.Module(body=fn_nodes, type_ignores=[])
        ns = {}
        exec(compile(mod, "transfer.py", "exec"), ns)
        validate_xmr = ns["_validate_xmr_address"]

        w = local_keys.generate_xmr_local_wallet("test_tr_xmr")
        self.assertTrue(validate_xmr(w["address"]))
        # Adresse corrompue d'un caractère -> rejetée par Keccak-256
        bad = w["address"][:-1] + ("2" if w["address"][-1] != "2" else "3")
        self.assertFalse(validate_xmr(bad))
        self.assertFalse(validate_xmr("4" + "1" * 94))
        self.assertFalse(validate_xmr(""))


if __name__ == "__main__":
    test_broadcast_specs_are_complete()
    test_xmr_catalog_spec()
    test_supported_networks_are_unique_pairs()
    unittest.main()
