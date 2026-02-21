import hashlib

import bech32
import ecdsa.rfc6979
from ecdsa import SECP256k1


def signcode_bitcoin_der(r, s, order):
    if s > order // 2:
        s = order - s
    return ecdsa.util.sigencode_der(r, s, order)


def sign_preimage_hash(sighash_preimage: bytes, private_key: int) -> bytes:
    sk = ecdsa.SigningKey.from_secret_exponent(
        secexp=private_key, curve=SECP256k1, hashfunc=hashlib.sha256
    )

    signature_preimage = sk.sign_digest_deterministic(
        digest=sighash_preimage, sigencode=signcode_bitcoin_der
    )
    sighash_flag = bytes([1])
    signature_preimage += sighash_flag
    # print(f"Signature: {signature_preimage}")
    return signature_preimage


def bitcoin_address_to_hash160(bitcoin_address: str) -> bytes:
    if not (bitcoin_address.startswith("bc") or bitcoin_address.startswith("tb")):
        raise ValueError("Bitcoin addre shoud start by 'bc' or 'tb'")
    witness_version, hash160_source_addr = bech32.decode(
        bitcoin_address[:2], bitcoin_address
    )
    return bytes(hash160_source_addr)


def double_sha256(data_to_hash: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data=data_to_hash).digest()).digest()


def tagged_hash(tag: bytes, msg: bytes):
    tag_hash = hashlib.sha256(data=tag).digest()
    return hashlib.sha256(data=tag_hash + tag_hash + msg).digest()
