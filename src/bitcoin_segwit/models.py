from dataclasses import dataclass

from crypto_utils import bitcoin_address_to_hash160


@dataclass()
class NativeSegWitInput:
    txid: bytes
    vout: bytes
    sequence: bytes
    script_length: bytes

    def __init__(self, txid: str, vout: int):
        self.txid = int(txid, 16).to_bytes(32, "little")
        self.vout = vout.to_bytes(4, "little")
        self.sequence = bytes.fromhex("f" * 8)
        self.script_length = bytes([0])  # No script in Native SegWit

    def serialization(self) -> bytes:
        return self.txid + self.vout + self.script_length + self.sequence


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
                byteorder="little"
            )  # +2 for witness version and
            + self.witness_version.to_bytes(1, "little")
            + (len(self.get_addr_hash())).to_bytes(byteorder="little")
            + self.get_addr_hash()
        )


class NativeSegWitBitcoinTransaction:
    version: int
    flag: int
    inputs: list[NativeSegWitInput]
    outputs: list[NativeSegWitOutput]

    def __init__(self, lock_time: int):
        self.version = 2
        self.lock_time = lock_time
        self.inputs = []
        self.outputs = []

    def add_input(self, txid: str, vout: int):
        new_input = NativeSegWitInput(txid, vout)
        self.inputs.append(new_input)

    def add_output(self, value: int, destination_addr: str):
        new_output = NativeSegWitOutput(value, destination_addr)
        self.outputs.append(new_output)

    def get_tx_in_count(self) -> int:
        return len(self.inputs)

    def get_tx_out_count(self) -> int:
        return len(self.outputs)
