import httpx
import questionary

from bitcoin.native_segwit.tx_models import NativeSegWitBitcoinTransaction

TEST_NET4_URL = "https://mempool.space/testnet4/api/tx"


def main():
    transaction = NativeSegWitBitcoinTransaction(0)

    while True:
        bitcoin_input_form = questionary.form(
            in_txid=questionary.text("What is the txid ?"),
            in_vout=questionary.text(
                "Which vout of this txid use ?",
                validate=lambda text: True
                if text.isdigit()
                else "Please provide an int",
            ),
            in_value=questionary.text("How many satoshis this output has ?"),
            in_bitcoin_address=questionary.text("What is the source bitcoin address ?"),
            in_public_key=questionary.text("What is the public key of this input ?"),
            in_private_key=questionary.password(
                "What is the private key of this input ?"
            ),
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

        is_finish = not questionary.confirm(
            message="Do you want to add another input ?", default=False
        ).ask()
        if is_finish:
            break

    satoshis_to_spend = 0
    for tx_input in transaction.inputs:
        satoshis_to_spend += tx_input.value
    print(f"You have {satoshis_to_spend} satoshis to spend")

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
        satoshis_to_spend -= int(bitcoin_output_answer["out_amount"])

        is_finish = not questionary.confirm(
            message="Do you want to add another output ?", default=False
        ).ask()
        if is_finish:
            print(f"Fees for this transaction will be: {satoshis_to_spend} satoshis")
            break
        print(
            f"You still have {satoshis_to_spend} satoshis to spend, the rest will be used as fees"
        )

    print(f"Transaction: {transaction.serialization()}")
    send_tx = questionary.confirm(
        message="Do you want to send the transaction to the testnet4 ?", default=True
    ).ask()
    if send_tx:
        httpx.post(url=TEST_NET4_URL, content=transaction.serialization())


if __name__ == "__main__":
    main()
