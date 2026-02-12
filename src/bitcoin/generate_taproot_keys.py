from taproot_key_generator import (
    derive_binary_seed,
    derive_child_key,
    generate_binary_seed,
)

from bitcoin.taproot_key_generator import (
    compute_bitcoin_addr,
    compute_tweak,
)


def main():
    binary_seed = generate_binary_seed()

    master_private_key, master_chain_code = derive_binary_seed(binary_seed)
    purpose_private_key, purpose_chain_code = derive_child_key(
        master_private_key, master_chain_code, True, 86
    )
    coin_private_key, coin_chain_code = derive_child_key(
        purpose_private_key, purpose_chain_code, True, 0
    )
    account_private_key, account_chain_code = derive_child_key(
        coin_private_key, coin_chain_code, True, 0
    )
    reception_private_key, reception_chain_code = derive_child_key(
        account_private_key, account_chain_code, False, 0
    )
    pre_final_private_key_1, final_chain_code_1 = derive_child_key(
        reception_private_key, reception_chain_code, False, 0
    )

    bitcoin_addr, private_key, pub_key = compute_bitcoin_addr(
        private_key=int.from_bytes(pre_final_private_key_1)
    )
    print(f"Bitcoin Taproot address: {bitcoin_addr}")
    print(f"Public key: {pub_key:0x}")
    print(f"Private key: {private_key:0x}")


if __name__ == "__main__":
    main()
