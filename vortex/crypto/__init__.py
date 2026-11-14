"""Password-based AES-256-GCM encryption for Vortex payloads."""

from .cipher import (
    CryptoError,
    EncryptedPayload,
    decrypt,
    decrypt_text,
    encrypt,
    encrypt_text,
    pack_for_embedding,
    payload_bit_length,
    unpack_from_embedding,
)

__all__ = [
    "CryptoError",
    "EncryptedPayload",
    "decrypt",
    "decrypt_text",
    "encrypt",
    "encrypt_text",
    "pack_for_embedding",
    "payload_bit_length",
    "unpack_from_embedding",
]
