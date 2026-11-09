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
