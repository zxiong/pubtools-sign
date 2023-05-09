import pytest

from pubtools._sign import signers


def test_load_config():
    signer_instance = signers.Signer()
    with pytest.raises(NotImplementedError):
        signer_instance.load_config({})
