from bitcoin.taproot.tx_models import Transaction, Input

my_tx = Transaction()
my_input = Input("5742303e4781e0464591b86932b447db70370d52ceefe84429a4c2eb0061931b", 1, 1000,
                 "00143db162b73cc9b50b1562415a86837909992435f7",
                 "d21d9788fa18d68fcfba20e745b74c528d1512f4d96870253b15711988dee5eb")
my_tx.add_input(my_input)

my_tx.compute_witness_i(0)
