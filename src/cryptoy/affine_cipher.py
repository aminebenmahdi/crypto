

from math import gcd

from cryptoy.utils import str_to_unicodes, unicodes_to_str

# TP: Affine Cipher

def compute_permutation(a: int, b: int, n: int) -> list[int]:
    permutation = [(a * i + b) % n for i in range(n)]
    return permutation

def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    perm = compute_permutation(a, b, n)
    inverse_perm = [0] * n
    for idx in range(n):
        inverse_perm[perm[idx]] = idx
    return inverse_perm

def encrypt(msg: str, a: int, b: int) -> str:
    unicode_vals = str_to_unicodes(msg)
    perm = compute_permutation(a, b, 0x110000)
    encrypted_vals = [perm[val] for val in unicode_vals]
    return unicodes_to_str(encrypted_vals)

def encrypt_optimized(msg: str, a: int, b: int) -> str:
    unicode_vals = str_to_unicodes(msg)
    encrypted_vals = [(a * val + b) % 0x110000 for val in unicode_vals]
    return unicodes_to_str(encrypted_vals)

def decrypt(msg: str, a: int, b: int) -> str:
    unicode_vals = str_to_unicodes(msg)
    inv_perm = compute_inverse_permutation(a, b, 0x110000)
    decrypted_vals = [inv_perm[val] for val in unicode_vals]
    return unicodes_to_str(decrypted_vals)

def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    unicode_vals = str_to_unicodes(msg)
    decrypted_vals = [(a_inverse * (val - b)) % 0x110000 for val in unicode_vals]
    return unicodes_to_str(decrypted_vals)

def compute_affine_keys(n: int) -> list[int]:
    valid_keys = [k for k in range(1, n) if gcd(k, n) == 1]
    return valid_keys

def compute_affine_key_inverse(a: int, affine_keys: list[int], n: int) -> int:
    for key in affine_keys:
        if (a * key) % n == 1:
            return key
    raise RuntimeError(f"No inverse found for {a}")

def attack() -> tuple[str, tuple[int, int]]:
    encrypted_sample = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡԿՊեԯՊ؇ԯրՊրր"
    for a in compute_affine_keys(0x110000):
        decrypted_msg = decrypt(encrypted_sample, a, 58)
        if "bombe" in decrypted_msg:
            return decrypted_msg, (a, 58)
    raise RuntimeError("Attack failed")

def attack_optimized() -> tuple[str, tuple[int, int]]:
    encrypted_sample = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )

    affine_keys = compute_affine_keys(0x110000)
    for a in affine_keys:
        a_inverse = compute_affine_key_inverse(a, affine_keys, 0x110000)
        for b in range(1, 10000):
            decrypted_msg = decrypt_optimized(encrypted_sample, a_inverse, b)
            if "bombe" in decrypted_msg:
                return decrypted_msg, (a, b)
    raise RuntimeError("Attack failed")
