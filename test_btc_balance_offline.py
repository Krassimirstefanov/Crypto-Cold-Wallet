"""Tests hors-ligne de la lecture du solde BTC (SegWit bc1q... et Legacy) avec fallback."""

import ast
from pathlib import Path
import unittest
from unittest.mock import patch

import balance
import requests


TEST_BTC_ADDR = "bc1qyj8whk6zu9c577k0xf65pyptyuxaa4z4rhuyda"


class FakeResponse:
    def __init__(self, payload, status=200, text=""):
        self.payload = payload
        self.status_code = status
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


def _load_menu_read_balance():
    tree = ast.parse(Path(__file__).with_name("menu.py").read_text(encoding="utf-8"))
    selected = ast.Module(
        body=[
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name in ("_req_kwargs", "_read_balance")
        ],
        type_ignores=[],
    )
    ns = {
        "NET_KILLED": False,
        "WEB_ENABLED": True,
        "TOR_PROC": None,
        "TOR_PORT": 9050,
    }
    exec(compile(selected, "menu.py", "exec"), ns)
    return ns["_read_balance"], ns["_req_kwargs"]


_read_balance, _req_kwargs = _load_menu_read_balance()


class BtcBalanceOfflineTests(unittest.TestCase):
    def test_req_kwargs_does_not_force_tor_when_tor_proc_is_none(self):
        kw = _req_kwargs(15)
        self.assertEqual(kw, {"timeout": 15})
        self.assertNotIn("proxies", kw)

    def test_menu_read_balance_parses_mempool_space(self):
        resp = FakeResponse(
            {
                "chain_stats": {"funded_txo_sum": 150_000, "spent_txo_sum": 25_000},
                "mempool_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0},
            }
        )
        with patch.object(requests, "get", return_value=resp) as mock_get:
            bal = _read_balance("btc", TEST_BTC_ADDR)
            self.assertAlmostEqual(bal, 0.00125)
            mock_get.assert_called_once()
            self.assertEqual(
                mock_get.call_args.args[0],
                f"https://mempool.space/api/address/{TEST_BTC_ADDR}",
            )

    def test_menu_read_balance_falls_back_to_blockstream_on_failure(self):
        responses = [
            FakeResponse({}, status=503),
            FakeResponse(
                {
                    "chain_stats": {"funded_txo_sum": 300_000, "spent_txo_sum": 50_000},
                    "mempool_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0},
                }
            ),
        ]
        with patch.object(requests, "get", side_effect=responses) as mock_get:
            bal = _read_balance("btc", TEST_BTC_ADDR)
            self.assertAlmostEqual(bal, 0.0025)
            self.assertEqual(mock_get.call_count, 2)
            self.assertEqual(
                mock_get.call_args_list[0].args[0],
                f"https://mempool.space/api/address/{TEST_BTC_ADDR}",
            )
            self.assertEqual(
                mock_get.call_args_list[1].args[0],
                f"https://blockstream.info/api/address/{TEST_BTC_ADDR}",
            )

    def test_menu_read_balance_falls_back_to_blockchain_info(self):
        responses = [
            FakeResponse({}, status=500),
            FakeResponse({}, status=500),
            FakeResponse({TEST_BTC_ADDR: {"final_balance": 420_000}}),
        ]
        with patch.object(requests, "get", side_effect=responses) as mock_get:
            bal = _read_balance("btc", TEST_BTC_ADDR)
            self.assertAlmostEqual(bal, 0.0042)
            self.assertEqual(mock_get.call_count, 3)
            self.assertEqual(
                mock_get.call_args_list[2].args[0],
                f"https://blockchain.info/balance?active={TEST_BTC_ADDR}",
            )

    def test_menu_read_balance_falls_back_to_blockcypher_when_cloudflare_blocks(self):
        responses = [
            FakeResponse({}, status=403),
            FakeResponse({}, status=429),
            FakeResponse({}, status=403),
            FakeResponse({"final_balance": 750_000}),
        ]
        with patch.object(requests, "get", side_effect=responses) as mock_get:
            bal = _read_balance("btc", TEST_BTC_ADDR)
            self.assertAlmostEqual(bal, 0.0075)
            self.assertEqual(mock_get.call_count, 4)
            self.assertEqual(
                mock_get.call_args_list[3].args[0],
                f"https://api.blockcypher.com/v1/btc/main/addrs/{TEST_BTC_ADDR}/balance",
            )

    def test_balance_get_btc_balance_mempool_and_fallback(self):
        responses = [
            FakeResponse({}, status=502),
            FakeResponse(
                {"chain_stats": {"funded_txo_sum": 500_000, "spent_txo_sum": 100_000}}
            ),
        ]
        with patch.object(balance.requests, "get", side_effect=responses) as mock_get:
            bal = balance.get_btc_balance(TEST_BTC_ADDR)
            self.assertAlmostEqual(bal, 0.004)
            self.assertEqual(mock_get.call_count, 2)


if __name__ == "__main__":
    unittest.main()
