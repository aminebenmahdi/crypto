from math import gcd

from cryptoy.utils import str_to_unicodes, unicodes_to_str

# TP: Affine Cipher Encryption and Decryption

def calculate_permutation(a: int, b: int, n: int) -> list[int]:
    perm = [(a * i + b) % n for i in range(n)]
    return perm

def calculate_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    perm = calculate_permutation(a, b, n)
    inverse_perm = [0] * n
    for idx, val in enumerate(perm):
        inverse_perm[val] = idx
    return inverse_perm

def encrypt(message: str, a: int, b: int) -> str:
    perm = calculate_permutation(a, b, 0x110000)
    unicode_vals = str_to_unicodes(message)
    encrypted_unicode = [perm[val] for val in unicode_vals]
    return unicodes_to_str(encrypted_unicode)

def encrypt_efficient(message: str, a: int, b: int) -> str:
    unicode_vals = str_to_unicodes(message)
    encrypted_unicode = [(a * val + b) % 0x110000 for val in unicode_vals]
    return unicodes_to_str(encrypted_unicode)

def decrypt(encrypted_message: str, a: int, b: int) -> str:
    inverse_perm = calculate_inverse_permutation(a, b, 0x110000)
    encrypted_unicode_vals = str_to_unicodes(encrypted_message)
    decrypted_unicode = [inverse_perm[val] for val in encrypted_unicode_vals]
    return unicodes_to_str(decrypted_unicode)

def decrypt_efficient(encrypted_message: str, a_inverse: int, b: int) -> str:
    encrypted_unicode_vals = str_to_unicodes(encrypted_message)
    decrypted_unicode = [(a_inverse * (val - b)) % 0x110000 for val in encrypted_unicode_vals]
    return unicodes_to_str(decrypted_unicode)

def find_affine_keys(n: int) -> list[int]:
    valid_keys = [a for a in range(1, n) if gcd(a, n) == 1]
    return valid_keys

def find_affine_key_inverse(a: int, valid_keys: list[int], n: int) -> int:
    for key in valid_keys:
        if (a * key) % n == 1:
            return key
    raise RuntimeError(f"No inverse key found for {a}")

def attack_cipher() -> tuple[str, tuple[int, int]]:
    encrypted_sample = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Կஞїᣍફ௯ஞૡΚր\u05ecՊՊԿஞૡԿՊեԯՊ؇ԯրՊրր"
    for a in find_affine_keys(0x110000):
        decrypted_msg = decrypt(encrypted_sample, a, 58)
        if "bombe" in decrypted_msg:
            return (decrypted_msg, (a, 58))
    raise RuntimeError("Attack failed")

def attack_cipher_efficient() -> tuple[str, tuple[int, int]]:
    encrypted_sample = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )

    affine_keys = find_affine_keys(0x110000)
    for a in affine_keys:
        a_inverse = find_affine_key_inverse(a, affine_keys, 0x110000)
        for b in range(1, 10000):
            decrypted_msg = decrypt_efficient(encrypted_sample, a_inverse, b)
            if "bombe" in decrypted_msg:
                return decrypted_msg, (a, b)

    raise RuntimeError("Attack failed")

