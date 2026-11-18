"""Tests hors-ligne du repli LTC. Aucun RPC, signature ou broadcast."""

from unittest.mock import patch

import balance


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


def test_ltc_balance_reads_confirmed_blockchair_balance():
    with patch.object(balance.requests, "get", return_value=FakeResponse({
        "data": {"ltc-address": [{"balance": 2_854_000}]}
    })) as get:
        assert balance.get_ltc_balance("ltc-address") == 0.02854
        get.assert_called_once()


def test_ltc_balance_falls_back_when_blockchair_has_no_address():
    responses = [
        FakeResponse({"data": {}}),
        FakeResponse({"final_balance": 2_854_000}),
    ]
    with patch.object(balance.requests, "get", side_effect=responses) as get:
        assert balance.get_ltc_balance("ltc-address") == 0.02854
        assert get.call_count == 2
        assert get.call_args_list[1].args[0] == (
            "https://api.blockcypher.com/v1/ltc/main/"
            "addrs/ltc-address/balance"
        )


def test_ltc_balance_falls_back_after_blockchair_http_error():
    responses = [
        FakeResponse({}, status=404),
        FakeResponse({"final_balance": 2_854_000}),
    ]
    with patch.object(balance.requests, "get", side_effect=responses):
        assert balance.get_ltc_balance("ltc-address") == 0.02854


def test_ltc_balance_reports_unavailable_instead_of_false_zero():
    with patch.object(balance.requests, "get", side_effect=RuntimeError("offline")):
        result = balance.get_ltc_balance("ltc-address")
    assert isinstance(result, str)
    assert "indisponible" in result


import unittest


class LtcAndXmrBalanceOfflineTests(unittest.TestCase):
    def test_ltc_confirmed_blockchair(self):
        test_ltc_balance_reads_confirmed_blockchair_balance()

    def test_ltc_fallback_missing_address(self):
        test_ltc_balance_falls_back_when_blockchair_has_no_address()

    def test_ltc_fallback_http_error(self):
        test_ltc_balance_falls_back_after_blockchair_http_error()

    def test_ltc_unavailable(self):
        test_ltc_balance_reports_unavailable_instead_of_false_zero()

    def test_xmr_balance_total_and_unlocked(self):
        import xmr_gateway
        with patch.object(xmr_gateway, "get_wallet_balance_xmr", return_value={"total": 3.5, "unlocked": 1.75}):
            res = balance.get_xmr_balance({"address": "4" + "1" * 94, "network": "monero"})
            self.assertEqual(res, {"total": 3.5, "unlocked": 1.75})

    def test_btc_menu_read_balance_mempool_and_blockstream_fallback(self):
        from test_btc_balance_offline import _read_balance, TEST_BTC_ADDR
        with patch.object(balance.requests, "get", return_value=FakeResponse({
            "chain_stats": {"funded_txo_sum": 250_000, "spent_txo_sum": 50_000}
        })) as mock_get:
            self.assertAlmostEqual(_read_balance("btc", TEST_BTC_ADDR), 0.002)
            mock_get.assert_called_once()
            self.assertEqual(
                mock_get.call_args.args[0],
                f"https://mempool.space/api/address/{TEST_BTC_ADDR}",
            )

        responses = [
            FakeResponse({}, status=503),
            FakeResponse({"chain_stats": {"funded_txo_sum": 350_000, "spent_txo_sum": 50_000}}),
        ]
        with patch.object(balance.requests, "get", side_effect=responses) as mock_get:
            self.assertAlmostEqual(_read_balance("btc", TEST_BTC_ADDR), 0.003)
            self.assertEqual(mock_get.call_count, 2)
            self.assertEqual(
                mock_get.call_args_list[1].args[0],
                f"https://blockstream.info/api/address/{TEST_BTC_ADDR}",
            )


if __name__ == "__main__":
    unittest.main()
