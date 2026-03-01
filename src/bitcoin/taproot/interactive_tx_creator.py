import bech32m
import questionary
from bech32m import HrpDoesNotMatch, DecodeError

from bitcoin.taproot.tx_models import Transaction, Input, Output

TXID_LENGTH = 32
PRIVATE_KEY_LENGTH = 32
SCRIPT_PUB_KEY_LENGTH = 34


def is_positive_number(user_input: str) -> bool:
    return user_input.isdecimal() and int(user_input) >= 0


def is_correct_hex_input(user_input: str, expected_length: int) -> bool:
    try:
        int(user_input, 16)
        return len(user_input) == expected_length * 2  # *2 because 2 hex char = 1 byte
    except ValueError:
        return False


def is_correct_bitcoin_addr(user_input: str) -> bool:
    try:
        bech32m.decode(user_input[0:2], user_input)
        return True
    except (HrpDoesNotMatch, DecodeError):
        return False


def ask_inputs(tx: Transaction):
    input_number: int = 1
    while True:
        print(f"--- Tx input {input_number} ---")
        input_questionary = questionary.form(txid=questionary.text(message="What is the txid ?",
                                                                   validate=lambda user_input: is_correct_hex_input(
                                                                       user_input, TXID_LENGTH)),
                                             vout=questionary.text(message="Which vout of this tx you went to spend ?",
                                                                   validate=lambda user_input: is_positive_number(
                                                                       user_input)),
                                             amount=questionary.text(
                                                 message="What is the exact amount in satoshi of this UTXO ?",
                                                 validate=lambda user_input: is_positive_number(user_input)),
                                             script_pub_key=questionary.text(
                                                 message="What is the script pub key of this UTXO ?",
                                                 validate=lambda user_input: is_correct_hex_input(user_input,
                                                                                                  SCRIPT_PUB_KEY_LENGTH)),
                                             private_key=questionary.password(
                                                 message="What is the private key of this input ?",
                                                 validate=lambda user_input: is_correct_hex_input(user_input,
                                                                                                  PRIVATE_KEY_LENGTH)))
        input_data = input_questionary.ask()
        new_input: Input = Input(
            input_data["txid"],
            int(input_data["vout"]),
            int(input_data["amount"]),
            input_data["script_pub_key"],
            input_data["private_key"]
        )
        tx.add_input(new_input)

        is_finish = not questionary.confirm(message="Do you want to add another input ?", default=False).ask()
        if is_finish:
            break
        input_number += 1


def ask_output(tx: Transaction):
    output_number: int = 1
    remaining_satoshis_to_spend: int = tx.get_available_satoshis_to_spend()
    while True:
        print(f"--- Tx output {output_number} ---")
        print(f"Remaining satoshis to spend: {remaining_satoshis_to_spend}")
        output_questionary = questionary.form(
            taproot_addr=questionary.text(message="What is the bitcoin address of the receiver ?",
                                          validate=lambda user_input: is_correct_bitcoin_addr(user_input)),
            amount=questionary.text(message="How many satoshi you want to send to this address ?",
                                    validate=lambda user_input: is_positive_number(user_input)))
        output_data = output_questionary.ask()
        new_output: Output = Output(output_data["taproot_addr"], int(output_data["amount"]))
        tx.add_output(new_output)

        remaining_satoshis_to_spend -= int(output_data["amount"])

        is_finish = not questionary.confirm(message="Do you want to add another output ?", default=False).ask()
        if is_finish:
            print(f"{remaining_satoshis_to_spend} will be used as fee for this tx")
            break
        output_number += 1


def main():
    print("---- Interactive taproot Bitcoin transaction creator ----")
    lock_time: str = questionary.text(message="What is the locktime of this transaction ?", default="0",
                                      validate=lambda user_input: is_positive_number(user_input)).ask()
    new_tx = Transaction(int(lock_time))
    ask_inputs(new_tx)
    ask_output(new_tx)

    print(f"Transaction: {new_tx.serialization()}")


if __name__ == '__main__':
    main()
