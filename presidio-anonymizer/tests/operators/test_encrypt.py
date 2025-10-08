from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher, OperatorType
from presidio_anonymizer.entities import InvalidParamError


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

@mock.patch.object(AESCipher, "is_valid_key_size")
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid):
    mock_is_valid.return_value = False

    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})


def test_operator_name():
    """Ensure operator_name returns the expected string."""
    assert Encrypt().operator_name() == "encrypt"


def test_operator_type():
    """Ensure operator_type returns OperatorType.Anonymize."""
    assert Encrypt().operator_type() == OperatorType.Anonymize


@pytest.mark.parametrize(
    "key",[
        "1" * 16,
        "1" * 24,
        "1" * 32,
        b"1" * 16,
        b"1" * 24,
        b"1" * 32,
    ],
)
def test_valid_keys(key):
    """Black-box test: validate should accept valid-size keys (128/192/256 bits)."""
    Encrypt().validate(params={"key": key})