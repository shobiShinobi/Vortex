"""Round-trip and failure tests for the crypto layer."""

import pytest

from vortex.crypto import (
    CryptoError,
    decrypt,
    decrypt_text,
    encrypt,
    encrypt_text,
    pack_for_embedding,
    unpack_from_embedding,
)


def test_encrypt_decrypt_bytes():
    payload = encrypt(b"secret payload", "correct-horse")
    assert decrypt(payload.data, "correct-horse") == b"secret payload"


def test_encrypt_decrypt_text():
    blob = encrypt_text("hello vortex", "passw0rd").data
    assert decrypt_text(blob, "passw0rd") == "hello vortex"


def test_wrong_password_fails():
    blob = encrypt(b"hidden", "right").data
    with pytest.raises(CryptoError):
        decrypt(blob, "wrong")


def test_tamper_detection():
    blob = bytearray(encrypt(b"hidden", "key").data)
    blob[-1] ^= 0xFF
    with pytest.raises(CryptoError):
        decrypt(bytes(blob), "key")


def test_pack_unpack_for_embedding():
    payload = encrypt(b"bits for stego", "pw")
    packed = pack_for_embedding(payload)
    recovered = unpack_from_embedding(packed)
    assert decrypt(recovered, "pw") == b"bits for stego"


def test_empty_password_rejected():
    with pytest.raises(CryptoError):
        encrypt(b"x", "")
