import hashlib

import bech32
import ecdsa.rfc6979
from ecdsa import SECP256k1


def sign_preimage_hash(sighash_preimage: bytes, private_key: int) -> bytes:
    sk = ecdsa.SigningKey.from_secret_exponent(secexp=private_key, curve=SECP256k1,
                                               hashfunc=hashlib.sha256)

    signature_preimage = sk.sign_digest_deterministic(digest=sighash_preimage, sigencode=ecdsa.util.sigencode_der)
    signature_preimage += bytes([1])
    # print(f"Signature: {signature_preimage}")
    return signature_preimage


def main():
    # Input
    source_bitcoin_addr = "tb1q7ylvrllmxd88sse7ersf9hnar42wm2rz2ax8kg"
    source_private_key = int("625c8f2699c2d98f864ecab6e73be3f582c47af4dd38999266a5587f7a6b2b1d", 16)
    source_public_key = bytes.fromhex("025add5dbe1143d41509168e228b527586f90e5e92eeae6507190e6fdd6fd6949c")
    something, hash160_source_addr = bech32.decode("tb", source_bitcoin_addr)

    txid = int("03478e13d05487a29a5412cab9daaa4be7316056ff14982662927aa7038d3f52", 16).to_bytes(32, "little")
    vout = int.to_bytes(1, 4, 'little')
    sequence = int("ffffffff", 16).to_bytes(4, "big")

    # Output
    destination_addr = "tb1qud84z5507jwdtkz2kwpphpjjv04awt84ejqumc"
    something2, hash160_dest_addr = bech32.decode("tb", destination_addr)

    input_amount = int(1000).to_bytes(8, "little")
    output_amount = int(800).to_bytes(8, "little")

    # Transaction
    version = int("02000000", 16).to_bytes(4, "big")
    marker_n_flag = int("0001", 16).to_bytes(2, "big")
    input_count = int(1).to_bytes(1, "big")
    script_sig = int(0).to_bytes(1, "big")
    output_count = int(1).to_bytes(1, "big")
    script_size = int(22).to_bytes(1, "big")  # octets
    lock = int("0014", 16).to_bytes(2, "big")
    lock_time = int.to_bytes(0, 4, "little")
    hash_type = bytes.fromhex("01000000")

    header = (version +
              marker_n_flag)

    inputs = (input_count +
              txid +
              vout +
              script_sig +
              sequence)

    # print(inputs.hex())

    outputs = (output_count +
               output_amount +
               script_size +
               lock +
               bytes(hash160_dest_addr))

    # Sighash Preimage

    prevouts = txid + vout
    pre_hash_prevouts = hashlib.sha256(prevouts).digest()
    hash_prevouts = hashlib.sha256(pre_hash_prevouts).digest()

    pre_hash_sequence = hashlib.sha256(sequence).digest()
    hash_sequence = hashlib.sha256(pre_hash_sequence).digest()

    outpoint = txid + vout

    script_code = bytes.fromhex("1976a914") + bytes(hash160_source_addr) + bytes.fromhex("88ac")
    actual_outputs = output_amount + script_size + lock + bytes(hash160_dest_addr)
    pre_hash_outputs = hashlib.sha256(actual_outputs).digest()
    hash_outputs = hashlib.sha256(pre_hash_outputs).digest()

    preimage = (version + hash_prevouts +
                hash_sequence + outpoint + script_code +
                input_amount + sequence + hash_outputs +
                lock_time + hash_type)

    pre_sighash_preimage = hashlib.sha256(preimage).digest()
    sighash_preimage = hashlib.sha256(pre_sighash_preimage).digest()

    preimage_signature = sign_preimage_hash(sighash_preimage, source_private_key)
    pub_key_size = bytes([len(source_public_key)])
    sig_size = bytes([len(preimage_signature)])
    witness_item_count = bytes([2])  # Constant

    witness_data = (witness_item_count +
                    sig_size +
                    preimage_signature +
                    pub_key_size +
                    source_public_key
                    )

    transaction = header + inputs + outputs + witness_data + lock_time
    print("Transaction: ")
    print(transaction.hex())


if __name__ == '__main__':
    main()
