import questionary

from bitcoin_segwit.models import NativeSegWitBitcoinTransaction


def main():
    transaction = NativeSegWitBitcoinTransaction(0)

    while True:
        bitcoin_input_form = questionary.form(
            in_txid=questionary.text("What is your first txid ?"),
            in_vout=questionary.text(
                "Which vout of this txid use ?",
                validate=lambda text: True
                if text.isdigit()
                else "Please provide an int",
            ),
            in_bitcoin_address=questionary.text("What is the source bitcoin address ?"),
            in_value=questionary.text("How many satoshis this output has ?"),
            in_private_key=questionary.password(
                "What is the private key of this input ?"
            ),
            in_public_key=questionary.text("What is the public key of this input ?"),
        )

        bitcoin_input_answer = bitcoin_input_form.ask()
        transaction.add_input(
            bitcoin_input_answer["in_txid"],
            int(bitcoin_input_answer["in_vout"]),
            bitcoin_input_answer["in_bitcoin_address"],
            int(bitcoin_input_answer["in_value"]),
            bitcoin_input_answer["in_private_key"],
            bitcoin_input_answer["in_public_key"],
        )

        is_finish = not questionary.confirm("Do you want to add another input ?").ask()
        if is_finish:
            break

    while True:
        bitcoin_output_form = questionary.form(
            out_address=questionary.text(
                "What is the bitcoin address of the receiver ?"
            ),
            out_amount=questionary.text("How many satoshis you want to send ?"),
        )

        bitcoin_output_answer = bitcoin_output_form.ask()
        transaction.add_output(
            int(bitcoin_output_answer["out_amount"]),
            bitcoin_output_answer["out_address"],
        )
        is_finish = not questionary.confirm("Do you want to add another output ?").ask()
        if is_finish:
            break

    print(f"Transaction: {transaction.serialization()}")


if __name__ == "__main__":
    main()
