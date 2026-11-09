"""Key generation without a wallet database; temporary transfer state stays in RAM."""
from contextlib import contextmanager


def generate_utxo_wallet(label, network):
    from mnemonic import Mnemonic
    from bitcoinlib.keys import HDKey
    purpose, coin, witness = {
        'bitcoin': (84, 0, 'segwit'),
        'litecoin': (84, 2, 'segwit'),
        'dogecoin': (44, 3, 'legacy'),
    }[network]
    words = Mnemonic('english').generate(strength=256)
    path = f"m/{purpose}'/{coin}'/0'/0/0"
    root = HDKey.from_seed(Mnemonic.to_seed(words), network=network, witness_type=witness)
    derive = getattr(root, 'key_for_path', None) or root.subkey_for_path
    key = derive(path)
    return {'label': label, 'network': network, 'address': key.address(),
            'private_key_wif': key.wif_key(), 'mnemonic': words, 'derivation_path': path}


@contextmanager
def ephemeral_transfer_wallet(**kwargs):
    """No fallback to bitcoinlib's on-disk wallet or cache database.

    This avoids persistent key copies; it does not promise secure RAM erasure.
    """
    from bitcoinlib.wallets import Wallet
    if 'db_uri' in kwargs or 'db_cache_uri' in kwargs:
        raise ValueError('Database locations cannot be overridden for a temporary wallet.')
    # bitcoinlib reopens the database internally. A named shared-memory URI,
    # held open by this anchor, lets its connections see the same RAM database.
    import sqlite3
    from uuid import uuid4
    name = 'ccw_' + uuid4().hex
    memory_uri = f'file:{name}?mode=memory&cache=shared'
    anchor = sqlite3.connect(memory_uri, uri=True)
    session = engine = None
    try:
        wallet = Wallet.create('temporary-transfer',
            db_uri=f'sqlite:///{memory_uri}&uri=true',
            db_cache_uri='sqlite:///:memory:', **kwargs)
        session = wallet.session
        engine = session.get_bind()
        yield wallet
    finally:
        try:
            if session is not None:
                session.close()
        finally:
            if engine is not None:
                engine.dispose()
            anchor.close()
