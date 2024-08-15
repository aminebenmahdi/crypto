from math import gcd
from cryptoy.utils import str_to_unicodes, unicodes_to_str

# TP: Chiffrement affine

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
    permutation = compute_permutation(a, b, 0x110000)
    encoded_message = [permutation[x] for x in str_to_unicodes(msg)]
    return unicodes_to_str(encoded_message)

def encrypt_optimized(msg: str, a: int, b: int) -> str:
    encoded_message = [(a * x + b) % 0x110000 for x in str_to_unicodes(msg)]
    return unicodes_to_str(encoded_message)

def decrypt(msg: str, a: int, b: int) -> str:
    inverse_perm = compute_inverse_permutation(a, b, 0x110000)
    decoded_message = [inverse_perm[x] for x in str_to_unicodes(msg)]
    return unicodes_to_str(decoded_message)

def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    decoded_message = [(a_inverse * (y - b)) % 0x110000 for y in str_to_unicodes(msg)]
    return unicodes_to_str(decoded_message)

def compute_affine_keys(n: int) -> list[int]:
    return [a for a in range(1, n) if gcd(a, n) == 1]

def compute_affine_key_inverse(a: int, affine_keys: list[int], n: int) -> int:
    for key in affine_keys:
        if (a * key) % n == 1:
            return key
    raise RuntimeError(f"{a} has no inverse")

def attack() -> tuple[str, tuple[int, int]]:
    encrypted_message = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊԿஞૡΚՊեԯՊ؇ԯրՊրր"
    for a in compute_affine_keys(0x110000):
        decrypted_message = decrypt(encrypted_message, a, 58)
        if "bombe" in decrypted_message:
            return decrypted_message, (a, 58)

    raise RuntimeError("Failed to attack")

def attack_optimized() -> tuple[str, tuple[int, int]]:
    encrypted_message = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    affine_keys = compute_affine_keys(0x110000)
    for a in affine_keys:
        a_inverse = compute_affine_key_inverse(a, affine_keys, 0x110000)
        for b in range(1, 10000):
            decrypted_message = decrypt_optimized(encrypted_message, a_inverse, b)
            if "bombe" in decrypted_message:
                return decrypted_message, (a, b)

    raise RuntimeError("Failed to attack")
