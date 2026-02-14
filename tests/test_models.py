import pytest

from bitcoin.native_segwit.tx_models import NativeSegWitInput

SEGWIT_INPUT_SIZE = 41


@pytest.fixture
def classic_input():
    return NativeSegWitInput(
        txid="2a851f390702a04c8179e962b0678b0086138205e09df850096e3953810cb2b7", vout=1
    )


def test_size(classic_input):
    assert len(classic_input.serialization()) == SEGWIT_INPUT_SIZE
