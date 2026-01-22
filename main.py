import argparse
import hashlib
import hmac
import secrets
from typing import Literal

import bech32
import bip39
import ecdsa

BYTE_ORDER: Literal["big", "little"] = "big"
HMAC_DIGEST_ALGO = "sha512"
# 0 = Mainnet, 1 = Testnet
COIN_TYPE = 1

# Human Readable Part : bc = mainnet, tb = testnet
HRP_PREFIX = "tb"


def compute_compressed_pub_key(private_key: bytes) -> bytes:
    public_key = int.from_bytes(private_key, BYTE_ORDER) * ecdsa.SECP256k1.generator
    x = public_key.x()
    prefix = 0x02 if public_key.y() % 2 == 0 else 0x03
    compressed_pub_key = int.to_bytes(prefix, 1, BYTE_ORDER) + int.to_bytes(x, 32, BYTE_ORDER)
    return compressed_pub_key


def compute_child_keys(parent_private_key: bytes, parent_chain_code: bytes, child_index: int, is_hardened: bool) -> \
        tuple[bytes, bytes]:
    if is_hardened:
        control_byte = int.to_bytes(0, 1, byteorder=BYTE_ORDER)
        hardened_index = int.to_bytes(2 ** 31 + child_index, 4, byteorder=BYTE_ORDER)
        message = control_byte + parent_private_key + hardened_index

    else:
        compressed_pub_key = compute_compressed_pub_key(parent_private_key)
        message = compressed_pub_key + int.to_bytes(child_index, 4, BYTE_ORDER)

    product_hmac = hmac.digest(key=parent_chain_code, msg=message, digest=HMAC_DIGEST_ALGO)
    child_private_key = (
            (int.from_bytes(product_hmac[0:32], BYTE_ORDER) + int.from_bytes(parent_private_key, BYTE_ORDER))
            % ecdsa.SECP256k1.order).to_bytes(32, BYTE_ORDER)
    child_chain_code = product_hmac[32:64]
    return child_private_key, child_chain_code


def generate_binary_seed() -> bytes:
    entropy = secrets.randbits(256)

    bip39_phrase = bip39.encode_bytes(entropy.to_bytes(32, BYTE_ORDER))
    print(bip39_phrase)
    return compute_binary_seed(bip39_phrase)


def compute_binary_seed(bip39_phrase: str) -> bytes:
    binary_seed = hashlib.pbkdf2_hmac(HMAC_DIGEST_ALGO, bip39_phrase.encode(), b"mnemonic", 2048)
    return binary_seed


def compute_master_keys(binary_seed: bytes) -> tuple[bytes, bytes]:
    master = hmac.digest(key=b"Bitcoin seed", msg=binary_seed, digest=HMAC_DIGEST_ALGO)
    master_private_key = master[0:32]
    master_chain_code = master[32:64]
    return master_private_key, master_chain_code


def compute_seg_wit_native_bitcoin_address(level4_private_key: bytes) -> str:
    level4_public_key = compute_compressed_pub_key(level4_private_key)
    sha256_level4_pub_key = hashlib.sha256(level4_public_key).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_level4_pub_key)
    hash160_pub_key = ripemd160.digest()
    print("Pub key len " + str(len(hash160_pub_key)))

    # data_5bit = bech32.convertbits(hash160_pub_key, 8, 5)
    final_pub_key = bech32.encode(HRP_PREFIX, 0, list(hash160_pub_key))
    return final_pub_key


def main(bip39_phrase: str):
    if bip39_phrase:
        print(f"Provided bip 39 phrase: {bip39_phrase}")
        binary_seed = compute_binary_seed(bip39_phrase)
    else:
        binary_seed = generate_binary_seed()

    master_private_key, master_chain_code = compute_master_keys(binary_seed)
    # Level 0 Purpose
    level0_private_key, level0_chain_code = compute_child_keys(master_private_key, master_chain_code, 84, True)

    # Level 1 Coin Type
    level1_private_key, level1_chain_code = compute_child_keys(level0_private_key, level0_chain_code, COIN_TYPE, True)

    # Level 2 Account
    level2_private_key, level2_chain_code = compute_child_keys(level1_private_key, level1_chain_code, 0, True)

    # Level 3 Change
    level3_private_key, level3_chain_code = compute_child_keys(level2_private_key, level2_chain_code, 0, False)

    # Level 4 Index
    level4_private_key_1, level4_chain_code_1 = compute_child_keys(level3_private_key, level3_chain_code, 0, False)
    level4_private_key_2, level4_chain_code_2 = compute_child_keys(level3_private_key, level3_chain_code, 1, False)

    seg_wit_native_addr1 = compute_seg_wit_native_bitcoin_address(level4_private_key_1)
    seg_wit_native_addr2 = compute_seg_wit_native_bitcoin_address(level4_private_key_2)
    print(f"Bitcoin address 1: {seg_wit_native_addr1}")
    print(f"Public key address 1: {compute_compressed_pub_key(level4_private_key_1).hex()}")
    print(f"Private key address 1: {level4_private_key_1.hex()}")
    print(f"Bitcoin address 2: {seg_wit_native_addr2}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Bitcoin key generator", description="A generator of bitcoin key")
    parser.add_argument('-b', '--bip39-phrase', required=False)
    args = parser.parse_args()
    main(args.bip39_phrase)
