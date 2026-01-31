import questionary

from bitcoin_segwit.models import NativeSegWitBitcoinTransaction


def main():
    answers = questionary.form(
        in_txid=questionary.text("What is your first txid ?"),
        in_vout=questionary.text(
            "Which vout of this txid use ?",
            validate=lambda text: True if text.isdigit() else "Please provide an int",
        ),
        in_bitcoin_address=questionary.text("What is the source bitcoin address ?"),
        in_value=questionary.text("How many satoshis this output has ?"),
        in_private_key=questionary.password("What is the private key of this input ?"),
        in_public_key=questionary.text("What is the public key of this input ?"),
        out_address=questionary.text("What is the bitcoin address of the receiver ?"),
        out_amount=questionary.text("How many satoshis you want to send ?"),
    ).ask()

    print(answers)

    transaction = NativeSegWitBitcoinTransaction(0)
    transaction.add_input(
        answers["in_txid"],
        int(answers["in_vout"]),
        answers["in_bitcoin_address"],
        int(answers["in_value"]),
        answers["in_private_key"],
        answers["in_public_key"],
    )
    transaction.add_output(int(answers["out_amount"]), answers["out_address"])

    print(f"Transaction: {transaction.serialization()}")


if __name__ == "__main__":
    main()
