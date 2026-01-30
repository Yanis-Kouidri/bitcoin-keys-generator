from dataclasses import dataclass

from crypto_utils import bitcoin_address_to_hash160

from bitcoin_segwit.crypto_utils import double_sha256, sign_preimage_hash

SIGHASH_ALL = bytes.fromhex("01000000")


@dataclass()
class NativeSegWitInput:
    txid: bytes
    vout: bytes
    sequence: bytes
    script_length: bytes
    source_bitcoin_address: bytes
    value: int  # In satoshi
    private_key: int
    public_key: bytes

    def __init__(
        self,
        txid: str,
        vout: int,
        bitcoin_address: str,
        value: int,
        private_key: str,
        public_key: str,
    ):
        self.txid = int(txid, 16).to_bytes(32, "little")
        self.vout = vout.to_bytes(4, "little")
        self.sequence = bytes.fromhex("f" * 8)
        self.script_length = bytes([0])  # No script in Native SegWit
        self.source_bitcoin_address = bitcoin_address_to_hash160(bitcoin_address)
        self.value = value
        self.private_key = int(private_key, 16)
        self.public_key = bytes.fromhex(public_key)

    def serialization(self) -> bytes:
        return self.txid + self.vout + self.script_length + self.sequence

    def get_outpoint(self) -> bytes:
        return self.txid + self.vout


@dataclass()
class NativeSegWitOutput:
    value: int
    destination_addr: str
    witness_version: int

    def __init__(self, value: int, destination_addr: str):
        self.value = value
        self.destination_addr = destination_addr
        self.witness_version = 0

    def get_addr_hash(self) -> bytes:
        return bitcoin_address_to_hash160(self.destination_addr)

    def serialization(self) -> bytes:
        return (
            self.value.to_bytes(length=8, byteorder="little")
            + (len(self.get_addr_hash()) + 2).to_bytes(
                1, byteorder="little"
            )  # +2 for witness version and
            + self.witness_version.to_bytes(1, "little")
            + (len(self.get_addr_hash())).to_bytes(1, byteorder="little")
            + self.get_addr_hash()
        )


class NativeSegWitBitcoinTransaction:
    version: bytes
    flag: bytes
    inputs: list[NativeSegWitInput]
    outputs: list[NativeSegWitOutput]
    lock_time: bytes

    def __init__(self, lock_time: int):
        self.version = int(2).to_bytes(4, "little")
        self.lock_time = lock_time.to_bytes(4, "little")
        self.inputs = []
        self.outputs = []
        self.flag = bytes.fromhex("0001")  # Constant

    def add_input(
        self,
        txid: str,
        vout: int,
        bitcoin_addr: str,
        value: int,
        private_key: str,
        public_key,
    ):
        new_input = NativeSegWitInput(
            txid, vout, bitcoin_addr, value, private_key, public_key
        )
        self.inputs.append(new_input)

    def add_output(self, value: int, destination_addr: str):
        new_output = NativeSegWitOutput(value, destination_addr)
        self.outputs.append(new_output)

    def get_tx_in_count(self) -> bytes:
        return len(self.inputs).to_bytes(1, "little")

    def get_tx_in_serialization(self) -> bytes:
        all_tx_in = bytes()
        for tx_in in self.inputs:
            all_tx_in += tx_in.serialization()
        return all_tx_in

    def get_tx_out_serialization(self) -> bytes:
        all_tx_out = bytes()
        for tx_out in self.outputs:
            all_tx_out += tx_out.serialization()
        return all_tx_out

    def get_tx_out_count(self) -> bytes:
        return len(self.outputs).to_bytes(1, "little")

    def compute_hash_prevouts(self) -> bytes:
        prevouts = bytes()
        for tx_input in self.inputs:
            prevouts += tx_input.txid + tx_input.vout
        return double_sha256(prevouts)

    def compute_hash_sequence(self) -> bytes:
        sequences = bytes()
        for tx_input in self.inputs:
            sequences += tx_input.sequence
        return double_sha256(sequences)

    def get_outpoint(self, utxo_index: int) -> bytes:
        return self.inputs[utxo_index].get_outpoint()

    def get_p2wpkh_script_code(self, utxo_index: int) -> bytes:
        return (
            bytes.fromhex("1976a914")
            + self.inputs[utxo_index].source_bitcoin_address
            + bytes.fromhex("88ac")
        )

    def compute_hash_outputs(self) -> bytes:
        concat_tx_outputs = bytes()
        for tx_output in self.outputs:
            concat_tx_outputs += tx_output.serialization()
        return double_sha256(concat_tx_outputs)

    def compute_sighash(self, input_index: int):
        sighash_preimage = (
            self.version
            + self.compute_hash_prevouts()
            + self.compute_hash_sequence()
            + self.get_outpoint(input_index)  # Sign only the first input
            + self.get_p2wpkh_script_code(input_index)
            + self.inputs[input_index].value.to_bytes(8, "little")
            + self.inputs[input_index].sequence
            + self.compute_hash_outputs()
            + self.lock_time
            + SIGHASH_ALL
        )
        return double_sha256(sighash_preimage)

    def compute_witness_data_p2wpkh(self) -> bytes:
        item_count = bytes([2])
        signature = sign_preimage_hash(
            self.compute_sighash(0), self.inputs[0].private_key
        )
        sig_length = len(signature).to_bytes(1, "little")
        pub_key = self.inputs[0].public_key
        pub_key_length = len(pub_key).to_bytes(1, "little")
        return item_count + sig_length + signature + pub_key_length + pub_key

    def serialization(self) -> str:
        transaction = (
            self.version
            + self.flag
            + self.get_tx_in_count()
            + self.get_tx_in_serialization()
            + self.get_tx_out_count()
            + self.get_tx_out_serialization()
            + self.compute_witness_data_p2wpkh()
            + self.lock_time
        )
        return transaction.hex()
