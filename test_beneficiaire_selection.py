"""Offline regression tests: execute the actual menu functions without startup/secrets."""
import ast
import contextlib
import io
from pathlib import Path
import types
import unittest
from asset_catalog import get, broadcast_entries


def menu_namespace(filename='menu.py'):
    tree = ast.parse(Path(__file__).with_name(filename).read_text())
    names = {'_beneficiary_wallet_matches', '_beneficiary_wallet_to_network',
             '_choose_any_beneficiary_destination'}
    selected = ast.Module(body=[n for n in tree.body
                               if isinstance(n, ast.FunctionDef) and n.name in names],
                          type_ignores=[])
    ns = dict(get_asset=get, _TRANSFER_NETWORKS=[(k, '') for k, _ in broadcast_entries()],
              t=lambda s: s, icon_cell=lambda s: '', network_icon=lambda s: '',
              pad_display=lambda s, n: s)
    exec(compile(selected, filename, 'exec'), ns)
    return ns


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.ns = menu_namespace()
        self.wallets = [dict(devise=a, reseau=n, adresse='test-address', plateforme='Test')
                        for a, n in [('USDT', 'ethereum'), ('BNB', 'bsc')] +
                        [('USDT', 'tron')] * 10]
        self.ns['_load_beneficiaries_for_transfer'] = lambda pw: {
            'Test Person': dict(pseudonyme='test', wallets=self.wallets)}
        self.calls = []
        self.validations = []
        self.ns['transfer'] = types.SimpleNamespace(validate_address=self.validate)

    def validate(self, network, address):
        self.validations.append((network, address))
        return self.valid

    def run_selection(self, index=0, valid=True):
        self.valid = valid
        def choose(items, prompt):
            self.calls.append(items)
            return items[0 if len(self.calls) == 1 else index]
        self.ns['_numbered_choice'] = choose
        with contextlib.redirect_stdout(io.StringIO()):
            return self.ns['_choose_any_beneficiary_destination']('dummy')

    def test_twelve_visible_two_compatible(self):
        result = self.run_selection()
        self.assertEqual(len(self.calls[1]), 12)
        self.assertIn('12 wallet(s) enregistré(s), 2 compatible(s)', self.calls[0][0][1])
        self.assertEqual(result[0], 'usdt_ethereum')
        self.assertEqual(len(self.wallets), 12)

    def test_unsupported_blocked_before_validation(self):
        self.assertIsNone(self.run_selection(2))
        self.assertEqual(self.validations, [])
        self.assertIn('Transfert indisponible', self.calls[1][2][1])

    def test_invalid_address_still_blocked(self):
        self.assertIsNone(self.run_selection(valid=False))
        self.assertEqual(len(self.validations), 1)

    def test_only_unsupported_wallets_remain_visible(self):
        self.wallets[:] = self.wallets[2:]
        self.assertIsNone(self.run_selection())
        self.assertIn('10 wallet(s) enregistré(s), 0 compatible(s)', self.calls[0][0][1])

    def test_asset_and_chain_remain_distinct(self):
        resolve = self.ns['_beneficiary_wallet_to_network']
        self.assertEqual(resolve(dict(devise='USDT', reseau='bsc')), 'usdt_bsc')
        self.assertIsNone(resolve(dict(devise='USDT', reseau='tron')))
        self.assertIsNone(resolve(dict(devise='UNKNOWN', reseau='ethereum')))

    def test_full_currency_names(self):
        resolve = self.ns['_beneficiary_wallet_to_network']
        for currency, network, expected in [
            ('BITCOIN', 'bitcoin', 'btc'), ('ETHERUM', 'ethereum', 'eth_ethereum'),
            ('ETHEREUM', 'ethereum', 'eth_ethereum'), ('SOLANA', 'solana', 'sol'),
            ('LITECOIN', 'litecoin', 'ltc'), ('POLYGON', 'polygon', 'polygon'),
            (' bitcoin ', ' bitcoin ', 'btc'),
        ]:
            with self.subTest(currency=currency):
                wallet = dict(devise=currency, reseau=network)
                before = wallet.copy()
                self.assertEqual(resolve(wallet), expected)
                self.assertEqual(wallet, before)

    def test_currency_alias_does_not_override_network(self):
        resolve = self.ns['_beneficiary_wallet_to_network']
        self.assertIsNone(resolve(dict(devise='BITCOIN', reseau='ethereum')))
        self.assertIsNone(resolve(dict(devise='SOLANA', reseau='bsc')))

    def test_cancel(self):
        self.ns['_numbered_choice'] = lambda *args: None
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(self.ns['_choose_any_beneficiary_destination']('dummy'))

if __name__ == '__main__':
    unittest.main()
