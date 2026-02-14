import argparse

from taproot_key_generator import (
    derive_binary_seed,
    derive_child_key,
    generate_binary_seed,
)

from bitcoin.taproot_key_generator import (
    compute_bitcoin_addr,
    mnemonic_phrase_to_binary_seed,
)

PURPOSE_INDEX: int = 86
COIN_INDEX: int = 1  # 0 for mainnet, 1 for testnet
ACCOUNT_INDEX: int = 0
RECEPTION_INDEX: int = 0  # 0 for reception, 1 for change
INDEX_TO_PRINT: int = 5


def print_index_addr(index_private_key: bytes, index: int, is_testnet: bool):
    bitcoin_addr, private_key, pub_key = compute_bitcoin_addr(
        private_key=int.from_bytes(index_private_key), is_mainnet=not is_testnet
    )
    network = "Testnet" if is_testnet else "Mainnet"
    print(f"----------Index {index} ({network})------------------")
    print(f"Bitcoin Taproot address: {bitcoin_addr}")
    print(f"Public key: {pub_key:0x}")
    print(f"Private key: {private_key:0x}")
    print("-" * 25)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="Bitcoin Taproot keys generator",
        description="A generator of bitcoin Taproot keys",
    )
    parser.add_argument(
        "-b",
        "--bip39-phrase",
        required=False,
        type=str,
        help="The 24 words of the mnemonic bip39 phrase",
    )
    parser.add_argument(
        "-t",
        "--testnet",
        required=False,
        action="store_true",
        help="Use this argument if you want to generate testnet address",
    )
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    if args.bip39_phrase:
        binary_seed = mnemonic_phrase_to_binary_seed(args.bip39_phrase)
    else:
        binary_seed = generate_binary_seed()

    master_private_key, master_chain_code = derive_binary_seed(binary_seed)
    purpose_private_key, purpose_chain_code = derive_child_key(
        master_private_key, master_chain_code, True, PURPOSE_INDEX
    )
    coin_private_key, coin_chain_code = derive_child_key(
        purpose_private_key, purpose_chain_code, True, COIN_INDEX
    )
    account_private_key, account_chain_code = derive_child_key(
        coin_private_key, coin_chain_code, True, ACCOUNT_INDEX
    )
    reception_private_key, reception_chain_code = derive_child_key(
        account_private_key, account_chain_code, False, RECEPTION_INDEX
    )

    for i in range(INDEX_TO_PRINT):
        index_i_private_key, _ = derive_child_key(
            reception_private_key, reception_chain_code, False, i
        )
        print_index_addr(index_i_private_key, i, args.testnet)


if __name__ == "__main__":
    main()
