from typing import Final


class Input:
    SCRIPT_SIG: Final[bytes] = bytes.fromhex("00")
    SEQUENCE: Final[bytes] = bytes.fromhex("ff ff ff ff")
    txid: bytes
    vout: bytes

    def __init__(self, txid: str, vout: int):
        self.txid = int(txid, 16).to_bytes(36, "little")
        self.vout = vout.to_bytes(4, "little")

    def serialization(self):
        return self.txid + self.vout + self.SCRIPT_SIG + self.SEQUENCE


class Output:
    value: bytes
    WITNESS_VERSION: Final[bytes] = bytes.fromhex("51")


class Transaction:
    N_VERSION: Final[bytes] = bytes.fromhex("02 00 00 00")
    FLAG: Final[bytes] = bytes.fromhex("00 01")

    def __init__(self):
        self.inputs = []
        self.outputs = []
        self._n_lock_time = 0
