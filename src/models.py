from dataclasses import dataclass


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


class NativeSegWitBitcoinTransaction:
    inputs: list[NativeSegWitInput]

    def __init__(self, lock_time: int):
        self.version = 2
        self.lock_time = lock_time
        self.inputs = []
        self.outputs = []

    def add_input(self, txid: str, vout: int):
        new_input = NativeSegWitInput(txid, vout)
        self.inputs.append(new_input)
