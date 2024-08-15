from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    # implementer le chiffrement en utilisant la classe aesgcm
    return AESGCM(key).encrypt(nonce, msg, None)


def decrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    # implementer le dechiffrement en utilisant la classe aesgcm
    return AESGCM(key).decrypt(nonce, msg, None)
