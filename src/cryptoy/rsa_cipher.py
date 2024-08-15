from math import gcd
from cryptoy.utils import (
    draw_random_prime,
    int_to_str,
    modular_inverse,
    pow_mod,
    str_to_int
)

def keygen() -> dict:
    e = 65537
    p = draw_random_prime()
    q = draw_random_prime()
    phi = (p - 1) * (q - 1)
    d = modular_inverse(e, phi)
    N = p * q
    return {"public_key": (e, N), "private_key": d}

def encrypt(msg: str, public_key: tuple) -> int:
    e, N = public_key
    msg_int = str_to_int(msg)
    if msg_int >= N:
        raise ValueError("Message is too large for the key size")
    encrypted_msg = pow_mod(msg_int, e, N)
    return encrypted_msg

def decrypt(msg: int, key: dict) -> str:
    e, N = key["public_key"]
    d = key["private_key"]
    decrypted_int = pow_mod(msg, d, N)
    decrypted_msg = int_to_str(decrypted_int)
    return decrypted_msg
