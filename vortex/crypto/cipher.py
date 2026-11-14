"""AES-256-GCM helpers with password-derived keys."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# Format: magic (4) | version (1) | salt (16) | nonce (12) | ciphertext+tag
MAGIC = b"VRTX"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
KDF_ITERATIONS = 200_000


class CryptoError(Exception):
    """Raised when encryption or decryption fails."""


@dataclass(frozen=True)
class EncryptedPayload:
    """Raw encrypted blob ready to be embedded by the stego layer."""

    data: bytes

    def __len__(self) -> int:
        return len(self.data)


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise CryptoError("password must not be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: bytes, password: str) -> EncryptedPayload:
    """Encrypt plaintext with AES-256-GCM using a password-derived key."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CryptoError("plaintext must be bytes")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), None)

    blob = MAGIC + bytes([VERSION]) + salt + nonce + ciphertext
    return EncryptedPayload(data=blob)


def decrypt(blob: bytes, password: str) -> bytes:
    """Decrypt a Vortex payload. Raises CryptoError on tamper or bad password."""
    min_len = 4 + 1 + SALT_LEN + NONCE_LEN + 16  # tag is 16 bytes
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < min_len:
        raise CryptoError("ciphertext is truncated or invalid")

    if blob[:4] != MAGIC:
        raise CryptoError("unrecognized payload format")

    version = blob[4]
    if version != VERSION:
        raise CryptoError(f"unsupported payload version: {version}")

    offset = 5
    salt = blob[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = blob[offset:]

    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:  # cryptography raises InvalidTag
        raise CryptoError("decryption failed: wrong password or tampered data") from exc


def encrypt_text(message: str, password: str) -> EncryptedPayload:
    """Convenience wrapper for UTF-8 text messages."""
    return encrypt(message.encode("utf-8"), password)


def decrypt_text(blob: bytes, password: str) -> str:
    """Decrypt and decode a UTF-8 text message."""
    return decrypt(blob, password).decode("utf-8")


def payload_bit_length(payload: EncryptedPayload) -> int:
    """Number of bits the stego layer needs to embed (includes a 32-bit length header)."""
    return 32 + len(payload.data) * 8


def pack_for_embedding(payload: EncryptedPayload) -> bytes:
    """Prepend a big-endian length so the extractor knows when to stop."""
    return struct.pack(">I", len(payload.data)) + payload.data


def unpack_from_embedding(raw: bytes) -> bytes:
    """Split length-prefixed bytes produced by pack_for_embedding."""
    if len(raw) < 4:
        raise CryptoError("embedded stream too short")
    (length,) = struct.unpack(">I", raw[:4])
    body = raw[4 : 4 + length]
    if len(body) != length:
        raise CryptoError("embedded stream length mismatch")
    return body
