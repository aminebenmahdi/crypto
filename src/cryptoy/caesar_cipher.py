from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# tp: chiffrement de césar

def encrypt(msg: str, shift: int) -> str:
    """
    chiffre un message en utilisant le chiffrement de césar.

    :param msg: le message a chiffrer.
    :param shift: le decalage a appliquer pour chaque caractere.
    :return: le message chiffre.
    """
    res = [(char_code + shift) % 0x110000 for char_code in str_to_unicodes(msg)]
    return unicodes_to_str(res)


def decrypt(msg: str, shift: int) -> str:
    """
    dechiffre un message en utilisant le chiffrement de césar.

    :param msg: le message a dechiffrer.
    :param shift: le decalage a appliquer (inverse du chiffrement).
    :return: le message dechiffre.
    """
    return encrypt(msg, -shift)


def attack() -> tuple[str, int]:
    """
    attaque pour dechiffrer un message chiffre en utilisant une connaissance partielle du texte en clair.

    :return: un couple contenant le message dechiffre et le decalage utilise pour le chiffrement.
    :raises RuntimeError: si aucun decalage valide n'est trouve.
    """
    s = "恱恪恸急恪恳恳恪恲恮恸急恦恹恹恦恶恺恪恷恴恳恸急恵恦恷急恱恪急恳恴恷恩怱急恲恮恳恪恿急恱恦急恿恴恳恪"
    for shift in range(0x110000):
        decrypted_msg = decrypt(s, shift)
        if 'enemies' in decrypted_msg:
            return decrypted_msg, shift
    raise RuntimeError("failed to attack")
