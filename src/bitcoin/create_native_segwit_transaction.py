import argparse

from bitcoin.native_segwit_tx_models import NativeSegWitBitcoinTransaction


def main():
    parser = argparse.ArgumentParser(
        prog="Create native segwit bitcoin transaction",
        description="Pass argument to create a valid and ready to send native segwit bitcoin transaction",
    )
    # Input
    parser.add_argument(
        "--in-txid", required=True, help="Input transaction ID in hex", type=str
    )
    parser.add_argument(
        "--in-vout", required=True, help="Input transaction output index", type=int
    )
    parser.add_argument(
        "--in-value",
        required=True,
        help="Value of the transaction output in satoshi",
        type=int,
    )
    parser.add_argument(
        "--in-bitcoin-address",
        required=True,
        help="Bitcoin address of the sender",
        type=str,
    )
    parser.add_argument(
        "--in-private-key",
        required=True,
        help="Bitcoin private key of the sender",
        type=str,
    )
    parser.add_argument(
        "--in-public-key",
        required=True,
        help="Bitcoin public key of the sender",
        type=str,
    )

    # Output
    parser.add_argument(
        "--output-value",
        required=True,
        type=int,
        help="Amount of satoshis to send to this output",
    )
    parser.add_argument(
        "--output-bitcoin-address",
        required=True,
        help="Bitcoin address to send the satoshis",
    )

    # Others
    parser.add_argument(
        "--locktime",
        type=int,
        required=False,
        default=0,
        help="Time before the transaction to be valid",
    )

    args = parser.parse_args()

    transaction = NativeSegWitBitcoinTransaction(args.locktime)
    transaction.add_input(
        args.in_txid,
        args.in_vout,
        args.in_bitcoin_address,
        args.in_value,
        args.in_private_key,
        args.in_public_key,
    )
    transaction.add_output(args.output_value, args.output_bitcoin_address)

    print(f"Transaction: {transaction.serialization()}")


if __name__ == "__main__":
    main()
