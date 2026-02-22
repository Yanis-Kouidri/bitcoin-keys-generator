from hashlib import sha256
from typing import Final

from bitcoin.utils.crypto_utils import tagged_hash


class Input:
    SCRIPT_SIG: Final[bytes] = bytes.fromhex("00")
    SEQUENCE: Final[bytes] = bytes.fromhex("ff ff ff ff")
    txid: bytes
    vout: bytes
    amount: bytes
    script_pub_key: bytes  # scriptPubKey of the output that I spend (look on mempool)
    TXID_FIELD_LENGTH: int = 32
    VOUT_FIELD_LENGTH: int = 4
    AMOUNT_FIELD_LENGTH: int = 8

    def __init__(self, txid: str, vout: int, amount: int, script_pub_key: str):
        self.txid = int(txid, 16).to_bytes(self.TXID_FIELD_LENGTH, "little")
        self.vout = vout.to_bytes(self.VOUT_FIELD_LENGTH, "little")
        self.amount = amount.to_bytes(self.AMOUNT_FIELD_LENGTH, "little")
        if len(script_pub_key) > 254 * 2:
            raise ValueError("Scipt pub key should be lower than 254 bytes")
        self.script_pub_key = bytes.fromhex(script_pub_key)

    def serialization(self):
        return self.txid + self.vout + self.SCRIPT_SIG + self.SEQUENCE


class Output:
    value: bytes
    output_key: bytes  # 32 bytes
    SCRIPT_PUB_KEY_LENGTH: Final[bytes] = bytes.fromhex(
        "22"
    )  # = len (Witness versio + witness size + output key)
    WITNESS_VERSION: Final[bytes] = bytes.fromhex("51")  # OP_1
    WITNESS_SIZE: Final[bytes] = bytes.fromhex("20")  # OP_PUSH32

    VALUE_FIELD_LENGTH: int = 8

    def __init__(self, value: int, output_key: str):
        self.value = value.to_bytes(self.VALUE_FIELD_LENGTH, "little")
        output_key_byte = bytes.fromhex(output_key)

        if len(output_key_byte) != 32:
            raise ValueError(
                f"The output key Q must be 32 bytes. Received: {len(output_key_byte)} bytes"
            )
        self.output_key = output_key_byte

    def serialization(self):
        return (
            self.value
            + self.SCRIPT_PUB_KEY_LENGTH
            + self.WITNESS_VERSION
            + self.WITNESS_SIZE
            + self.output_key
        )


class Transaction:
    inputs: list[Input]
    outputs: list[Output]
    n_lock_time: bytes

    N_VERSION: Final[bytes] = bytes.fromhex("02 00 00 00")
    FLAG: Final[bytes] = bytes.fromhex("00 01")
    EPOCH: Final[bytes] = bytes.fromhex("00")
    SIGHASH_TYPE: Final[bytes] = bytes.fromhex("00")  # SIGHASH_DEFAULT
    SPEND_TYPE: Final[bytes] = bytes.fromhex("00")  # Key path spend

    LOCK_TIME_FIELD_LENGTH: int = 4
    SIGHASH_INPUT_INDEX_FIELD_LENGTH: int = 4

    def __init__(self, lock_time: int = 0):
        self.inputs = []
        self.outputs = []
        self.n_lock_time = lock_time.to_bytes(self.LOCK_TIME_FIELD_LENGTH, "little")

    def add_input(self, input_to_add: Input):
        self.inputs.append(input_to_add)

    def add_output(self, output_to_add: Output):
        self.outputs.append(output_to_add)

    def compute_witnesses(self):
        print()

    def compute_witness_i(self, index: int):
        nb_of_element = 1
        schnorr_sig_size = 64

    def compute_tap_sighash(self, input_index: int) -> bytes:
        sighash_message = (
            self.EPOCH
            + self.SIGHASH_TYPE
            + self.N_VERSION
            + self.n_lock_time
            + self.compute_hash_prevouts()
            + self.compute_hash_amounts()
            + self.compute_hash_script_pub_keys()
            + self.compute_hash_sequences()
            + self.compute_hash_outputs()
            + self.SPEND_TYPE
            + input_index.to_bytes(self.SIGHASH_INPUT_INDEX_FIELD_LENGTH, "little")
        )

        return tagged_hash(b"TapSighash", sighash_message)

    def compute_hash_prevouts(self) -> bytes:
        outpoints_concat = bytes()  # TXID + VOUT of all inputs
        for tx_input in self.inputs:
            outpoints_concat += tx_input.txid + tx_input.vout
        return sha256(outpoints_concat).digest()

    def compute_hash_amounts(self) -> bytes:
        amounts_concat = bytes()
        for tx_input in self.inputs:
            amounts_concat += tx_input.amount
        return sha256(amounts_concat).digest()

    def compute_hash_script_pub_keys(self) -> bytes:
        script_pub_keys_concat = bytes()
        for tx_input in self.inputs:
            script_pub_keys_length = len(tx_input.script_pub_key)
            script_pub_keys_concat += (
                script_pub_keys_length.to_bytes(1, "little") + tx_input.script_pub_key
            )
        return sha256(script_pub_keys_concat).digest()

    def compute_hash_sequences(self) -> bytes:
        sequences_concat = bytes()
        for tx_input in self.inputs:
            sequences_concat += tx_input.SEQUENCE
        return sha256(sequences_concat).digest()

    def compute_hash_outputs(self) -> bytes:
        outputs_concat = bytes()
        for tx_output in self.outputs:
            outputs_concat += tx_output.serialization()
        return sha256(outputs_concat).digest()
