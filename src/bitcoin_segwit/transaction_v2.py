from bitcoin_segwit.models import NativeSegWitBitcoinTransaction, NativeSegWitOutput

transaction = NativeSegWitBitcoinTransaction(0)

transaction.add_input(
    "0b9c9aa7cb5e4c63d7978547a60399f6d7ec067b74670ae2a8eb6940f0a6719f",
    0,
    "tb1qud84z5507jwdtkz2kwpphpjjv04awt84ejqumc",
    1800,
    "9b11962f5ae09a3d9db5b1185943e651e65745d31d03c9821700eecc36bc890c",
    "029e4c6b1f068ac589c57ab82e0117b532f65fe702f8788f33c30638238a0c9361",
)

# output = NativeSegWitOutput(800, "tb1qud84z5507jwdtkz2kwpphpjjv04awt84ejqumc")
transaction.add_output(1600, "tb1qx2zx3v55x2jpygf8qfzlrcjszzx9ygen0hgcyq")

# print(output.serialization().hex())
# print(len(output.get_addr_hash()).to_bytes(byteorder="little").hex())
print(transaction.serialization())
