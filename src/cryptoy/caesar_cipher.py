from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement de César

def encrypt(msg: str, shift: int) -> str:
    return unicodes_to_str([(code + shift) % 0x110000 for code in str_to_unicodes(msg)])

def decrypt(msg: str, shift: int) -> str:
    return encrypt(msg, -shift)

def attack() -> tuple[str, int]:
    s = "恱恪恸急恪恳恳恪恲恮恸急恦恹恹恦恶恺恪恷恴恳恸急恵恦恷急恱恪急恳恴恷恩怱急恲恮恳恪恿急恱恦急恿恴恳恪"
    for shift in range(0x110000):
        msg = decrypt(s, shift)
        if 'ennemis' in msg:
            return msg, shift
    raise RuntimeError("Failed to attack")
