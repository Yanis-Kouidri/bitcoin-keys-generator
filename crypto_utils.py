import hashlib

import bech32
import ecdsa.rfc6979
from ecdsa import SECP256k1


def sign_preimage_hash(sighash_preimage: bytes, private_key: int) -> bytes:
    sk = ecdsa.SigningKey.from_secret_exponent(
        secexp=private_key, curve=SECP256k1, hashfunc=hashlib.sha256
    )

    signature_preimage = sk.sign_digest_deterministic(
        digest=sighash_preimage, sigencode=ecdsa.util.sigencode_der
    )
    signature_preimage += bytes([1])
    # print(f"Signature: {signature_preimage}")
    return signature_preimage


def bitcoin_address_to_hash160(hrp: str, bitcoin_address: str) -> bytes:
    witness_version, hash160_source_addr = bech32.decode(hrp, bitcoin_address)
    return bytes(hash160_source_addr)


def double_sha256(data_to_hash: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data=data_to_hash).digest()).digest()
