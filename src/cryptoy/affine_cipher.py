from math import gcd
from cryptoy.utils import str_to_unicodes, unicodes_to_str

# tp: chiffrement affine

def compute_permutation(a: int, b: int, n: int) -> list[int]:
    # implementer la permutation affine
    # en sortie, on doit avoir une liste result telle que result[i] == (a * i + b) % n
    return [(a * i + b) % n for i in range(n)]


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    # implementer la permutation inverse
    # appeler compute_permutation(a, b, n) et calculer la permutation inverse
    # result telle que: perm[i] == j implique result[j] == i
    perm = compute_permutation(a, b, n)
    result = [0] * n
    for i in range(n):
        result[perm[i]] = i
    return result


def encrypt(msg: str, a: int, b: int) -> str:
    # implementer le chiffrement affine en utilisant compute_permutation, str_to_unicodes et unicodes_to_str
    perm = compute_permutation(a, b, 0x110000)
    return unicodes_to_str([perm[code] for code in str_to_unicodes(msg)])


def encrypt_optimized(msg: str, a: int, b: int) -> str:
    # implementer le chiffrement affine sans utiliser compute_permutation
    return unicodes_to_str([(a * code + b) % 0x110000 for code in str_to_unicodes(msg)])


def decrypt(msg: str, a: int, b: int) -> str:
    # implementer le dechiffrement affine en utilisant compute_inverse_permutation, str_to_unicodes et unicodes_to_str
    inverse_perm = compute_inverse_permutation(a, b, 0x110000)
    return unicodes_to_str([inverse_perm[code] for code in str_to_unicodes(msg)])


def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    # implementer le dechiffrement affine sans utiliser compute_inverse_permutation
    # on suppose que a_inverse a ete precalcule en utilisant compute_affine_key_inverse et passe a la fonction
    return unicodes_to_str([(a_inverse * (code - b)) % 0x110000 for code in str_to_unicodes(msg)])


def compute_affine_keys(n: int) -> list[int]:
    # calculer l'ensemble des nombres a entre 1 et n tels que gcd(a, n) == 1
    return [a for a in range(1, n) if gcd(a, n) == 1]


def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    # trouver a_inverse dans affine_keys tel que a * a_inverse % n == 1 et le renvoyer
    for a_inverse in affine_keys:
        if (a * a_inverse) % n == 1:
            return a_inverse
    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    # trouver msg, a et b tels que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" est present dans msg et b == 58
    for a in compute_affine_keys(0x110000):
        msg = decrypt(s, a, 58)
        if "bombe" in msg:
            return msg, (a, 58)
    raise RuntimeError("failed to attack")


def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    # trouver msg, a et b tels que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" est present dans msg
    affine_keys = compute_affine_keys(0x110000)
    for a in affine_keys:
        a_inverse = compute_affine_key_inverse(a, affine_keys, 0x110000)
        for b in range(1, 10000):
            msg = decrypt_optimized(s, a_inverse, b)
            if "bombe" in msg:
                return msg, (a, b)
    raise RuntimeError("failed to attack")
