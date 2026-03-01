from bitcoin.taproot.tx_models import Transaction, Input, Output

my_tx = Transaction()
my_input = Input("35ad632141af00c6860e809b9225e059cd26d880d23f43fbd1d9c10f71745e54", 0, 126256,
                 "512029dd2539f1ef9a05e285326eba24be2c30c26d6678f13faf86f9f224d8f14294",
                 "c4a9bf032685b2087a1aaa9be844ad1476effca22435154e0af41451e042aa56")
my_tx.add_input(my_input)

my_output = Output("tb1p5xyg3vpgmt3zw7arc4avxnjthtlcaxx4yfafxztj966jh8mz0q3s7w8k9x", 126256 - 1000)
my_tx.add_output(my_output)
print(my_tx.serialization())
