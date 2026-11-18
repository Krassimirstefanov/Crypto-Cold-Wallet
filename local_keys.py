"""Key generation without a wallet database; temporary transfer state stays in RAM."""
from contextlib import contextmanager
import os
import secrets
import zlib

from xmr_gateway import encode_xmr_address, keccak_256

# Ordre du sous-groupe premier Ed25519 (l = 2^252 + 27742317777372353535851937790883648493)
_ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
_ED25519_P = (1 << 255) - 19
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_BY = (4 * pow(5, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202


def _ed25519_point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    p = _ED25519_P
    a = ((y1 - x1) * (y2 - x2)) % p
    b = ((y1 + x1) * (y2 + x2)) % p
    c = (2 * t1 * t2 * _ED25519_D) % p
    d = (2 * z1 * z2) % p
    e = (b - a) % p
    f = (d - c) % p
    g = (d + c) % p
    h = (b + a) % p
    return (e * f) % p, (g * h) % p, (f * g) % p, (e * h) % p


def _ed25519_scalarmult_base(scalar_le: bytes) -> bytes:
    """Calcule la clé publique Ed25519 (32 octets compressés) depuis un scalaire Monero 32 octets LE."""
    k = int.from_bytes(scalar_le, "little") % _ED25519_L
    p = _ED25519_P
    base = (_ED25519_BX, _ED25519_BY, 1, (_ED25519_BX * _ED25519_BY) % p)
    res = None
    cur = base
    while k > 0:
        if k & 1:
            res = _ed25519_point_add(res, cur)
        cur = _ed25519_point_add(cur, cur)
        k >>= 1
    if res is None:
        return b"\x01" + (b"\x00" * 31)
    x, y, z, _ = res
    z_inv = pow(z, p - 2, p)
    x_aff = (x * z_inv) % p
    y_aff = (y * z_inv) % p
    out = bytearray(y_aff.to_bytes(32, "little"))
    out[31] |= (x_aff & 1) << 7
    return bytes(out)


def _sc_reduce32(data32: bytes) -> bytes:
    """Réduit un entier 256 bits little-endian modulo l (ordre Ed25519)."""
    val = int.from_bytes(data32, "little") % _ED25519_L
    if val == 0:
        val = 1
    return val.to_bytes(32, "little")


# Liste de 1626 mots English pour l'encodage déterministe 25 mots hors-ligne si `monero` absent
def _xmr_wordlist() -> list[str]:
    try:
        from monero.wordlists import English
        return list(English().wordlist)
    except Exception:
        try:
            from mnemonic import Mnemonic
            base = list(Mnemonic("english").wordlist)  # 2048 mots
            return base[:1626]
        except Exception:
            return [f"word{i}" for i in range(1626)]


def _seed_bytes_to_25_words(seed32: bytes) -> str:
    wl = _xmr_wordlist()
    n = len(wl)
    words = []
    for i in range(0, 32, 4):
        val = int.from_bytes(seed32[i : i + 4], "little")
        w1 = val % n
        w2 = ((val // n) + w1) % n
        w3 = (((val // n) // n) + w2) % n
        words.extend([wl[w1], wl[w2], wl[w3]])
    prefix_concat = "".join(w[:3] for w in words).encode("utf-8")
    chk_idx = zlib.crc32(prefix_concat) % 24
    words.append(words[chk_idx])
    return " ".join(words)


def _words_25_to_seed_bytes(phrase: str) -> bytes:
    words = phrase.strip().lower().split()
    if len(words) not in (24, 25):
        raise ValueError("Une phrase mnémonique Monero doit comporter 25 mots (ou 24 mots sans checksum).")
    wl = _xmr_wordlist()
    idx_map = {w.lower(): i for i, w in enumerate(wl)}
    if all(w in idx_map for w in words[:24]):
        if len(words) == 25:
            prefix_concat = "".join(w[:3] for w in words[:24]).encode("utf-8")
            expected = words[zlib.crc32(prefix_concat) % 24]
            if words[24] != expected:
                raise ValueError("Checksum du 25e mot Monero invalide.")
        n = len(wl)
        out = bytearray()
        for i in range(0, 24, 3):
            w1, w2, w3 = idx_map[words[i]], idx_map[words[i + 1]], idx_map[words[i + 2]]
            val = w1 + n * ((w2 - w1) % n) + n * n * ((w3 - w2) % n)
            out.extend(val.to_bytes(4, "little"))
        return bytes(out)
    return keccak_256(" ".join(words).encode("utf-8"))


def generate_xmr_local_wallet(label: str, mnemonic: str | None = None,
                              spend_key_hex: str | None = None,
                              view_key_hex: str | None = None) -> dict:
    """Crée ou importe un wallet Monero (XMR, 12 décimales) 100% hors-ligne."""
    try:
        from monero.seed import Seed
        if mnemonic:
            seed = Seed(mnemonic.strip())
        elif spend_key_hex:
            seed = Seed(spend_key_hex.strip())
        else:
            seed = Seed()
        spend_hex = seed.secret_spend_key()
        view_hex = view_key_hex.strip().lower() if view_key_hex else seed.secret_view_key()
        return {
            "label": label,
            "network": "monero",
            "asset": "XMR",
            "asset_id": "xmr",
            "decimals": 12,
            "address": str(seed.public_address()),
            "mnemonic": seed.phrase,
            "private_spend_key": spend_hex,
            "private_view_key": view_hex,
        }
    except Exception:
        if spend_key_hex:
            raw_spend = bytes.fromhex(spend_key_hex.strip().removeprefix("0x"))
            if len(raw_spend) != 32:
                raise ValueError("La clé spend Monero doit faire 32 octets (64 caractères hex).")
            spend_scalar = _sc_reduce32(raw_spend)
            phrase = mnemonic.strip() if mnemonic else _seed_bytes_to_25_words(spend_scalar)
        elif mnemonic:
            raw_seed = _words_25_to_seed_bytes(mnemonic)
            spend_scalar = _sc_reduce32(raw_seed)
            phrase = mnemonic.strip()
        else:
            spend_scalar = _sc_reduce32(secrets.token_bytes(32))
            phrase = _seed_bytes_to_25_words(spend_scalar)

        if view_key_hex:
            raw_view = bytes.fromhex(view_key_hex.strip().removeprefix("0x"))
            if len(raw_view) != 32:
                raise ValueError("La clé view Monero doit faire 32 octets (64 caractères hex).")
            view_scalar = _sc_reduce32(raw_view)
        else:
            view_scalar = _sc_reduce32(keccak_256(spend_scalar))

        pub_spend = _ed25519_scalarmult_base(spend_scalar)
        pub_view = _ed25519_scalarmult_base(view_scalar)
        address = encode_xmr_address(pub_spend, pub_view, net_byte=18)
        return {
            "label": label,
            "network": "monero",
            "asset": "XMR",
            "asset_id": "xmr",
            "decimals": 12,
            "address": address,
            "mnemonic": phrase,
            "private_spend_key": spend_scalar.hex(),
            "private_view_key": view_scalar.hex(),
        }


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
