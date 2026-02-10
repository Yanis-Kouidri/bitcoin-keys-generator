import hashlib
import hmac
import secrets
from typing import Literal, Tuple

import bech32m
import bip39
import ecdsa

BYTE_ORDER: Literal["big", "little"] = "big"
HMAC_DIGEST_ALGO = "sha512"
HMAC_DIGEST_ITERATIONS = 2048
HMAC_DIGEST_SALT = b"mnemonic"
HRP = "bc"
TAPROOT_WITNESS_VERSION = 1


def compute_binary_seed(bip39_phrase: str) -> bytes:
    binary_seed = hashlib.pbkdf2_hmac(
        HMAC_DIGEST_ALGO,
        bip39_phrase.encode(),
        HMAC_DIGEST_SALT,
        HMAC_DIGEST_ITERATIONS,
    )
    return binary_seed


def generate_binary_seed() -> bytes:
    entropy = secrets.randbits(256)

    # bip39.encode_byte add automatically the checksum
    bip39_phrase = bip39.encode_bytes(entropy.to_bytes(32, BYTE_ORDER))
    print(bip39_phrase)
    return compute_binary_seed(bip39_phrase)


def derive_binary_seed(binary_seed: bytes) -> Tuple[bytes, bytes]:
    master_node = hmac.digest(
        key=b"Bitcoin seed", msg=binary_seed, digest=HMAC_DIGEST_ALGO
    )
    master_private_key = master_node[0:32]
    master_chain_code = master_node[32:64]
    return master_private_key, master_chain_code


def derive_child_key(
    parent_private_key: bytes, parent_chain_code: bytes, is_hardened: bool, index: int
) -> Tuple[bytes, bytes]:
    if is_hardened:
        padding = bytes([0])
        hardened_index = index + 2**31
        message = padding + parent_private_key + hardened_index.to_bytes(4, BYTE_ORDER)
    else:
        message = compute_compressed_public_key(
            int.from_bytes(parent_private_key, BYTE_ORDER)
        ) + index.to_bytes(4, BYTE_ORDER)

    child_node = hmac.digest(
        key=parent_chain_code, msg=message, digest=HMAC_DIGEST_ALGO
    )
    child_private_key = (
        int.from_bytes(parent_private_key, BYTE_ORDER)
        + int.from_bytes(child_node[32:64], BYTE_ORDER)
    ) % ecdsa.SECP256k1.order

    child_chain_code = child_node[32:64]

    return child_chain_code, child_private_key.to_bytes(32, BYTE_ORDER)


def compute_compressed_public_key(private_key: int):
    pubkey_point: ecdsa.ellipticcurve.PointJacobi = (
        private_key * ecdsa.SECP256k1.generator
    )
    parity_prefix = 0x02 if pubkey_point.y() % 2 == 0 else 0x03
    compressed_pub_key = parity_prefix.to_bytes(
        1, BYTE_ORDER
    ) + pubkey_point.x().to_bytes(32, BYTE_ORDER)
    return compressed_pub_key


def compute_final_pub_key(
    private_key: int,
) -> Tuple[int, ecdsa.ellipticcurve.PointJacobi]:
    pubkey_point: ecdsa.ellipticcurve.PointJacobi = (
        private_key * ecdsa.SECP256k1.generator
    )
    if pubkey_point.y() % 2 == 0:
        return private_key, pubkey_point.x()
    else:
        new_private_key = ecdsa.SECP256k1.order - private_key
        return new_private_key, pubkey_point


def compute_tweak(public_key: int):
    tap_tweak_hash = hashlib.sha256(b"TapTweak").digest()
    pre_final_result = (
        tap_tweak_hash + tap_tweak_hash + public_key.to_bytes(32, BYTE_ORDER)
    )
    return int.from_bytes(hashlib.sha256(pre_final_result).digest(), BYTE_ORDER)


def compute_output_key(private_key: int):
    new_private_key, q_point = compute_final_pub_key(private_key)
    tweak = compute_tweak(q_point.x())
    ajusted_key = q_point + tweak * ecdsa.SECP256k1.generator
    witness_program = ajusted_key.x().to_bytes(32, BYTE_ORDER)
    final_pub_key = bech32m.encode(HRP, TAPROOT_WITNESS_VERSION, witness_program)
    return final_pub_key
