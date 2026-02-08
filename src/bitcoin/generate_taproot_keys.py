from taproot_key_generator import (
    compute_compressed_public_key,
    derive_binary_seed,
    derive_child_key,
    generate_binary_seed,
)


def main():
    binary_seed = generate_binary_seed()
    master_private_key, master_chain_code = derive_binary_seed(binary_seed)
    purpose_private_key, purpose_chain_code = derive_child_key(
        master_private_key, master_chain_code, True, 86
    )
    compute_compressed_public_key(54564564564)


if __name__ == "__main__":
    main()
