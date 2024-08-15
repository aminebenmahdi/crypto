from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
)

def encrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, msg, None)


def decrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, msg, None)
