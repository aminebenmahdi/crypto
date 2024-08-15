import random
import sys
from cryptoy.utils import pow_mod

# augmenter la limite de recursion pour permettre des calculs d'exposants eleves avec pow_mod
sys.setrecursionlimit(5000)


def keygen(prime_number: int, generator: int) -> dict[str, int]:
    """
    genere une paire de cles diffie-hellman.

    :param prime_number: le nombre premier utilise pour le modulo.
    :param generator: le generateur utilise pour la cle publique.
    :return: un dictionnaire contenant la cle publique ('public_key') et la cle privee ('private_key').
    """
    private_key = random.randint(2, prime_number - 1)
    public_key = pow_mod(generator, private_key, prime_number)
    return {"public_key": public_key, "private_key": private_key}


def compute_shared_secret_key(public: int, private: int, prime_number: int) -> int:
    """
    calcule la cle secrete partagee a partir de la cle publique de l'autre participant et de la cle privee.

    :param public: la cle publique de l'autre participant.
    :param private: la cle privee de l'utilisateur.
    :param prime_number: le nombre premier utilise pour le modulo.
    :return: la cle secrete partagee.
    """
    return pow_mod(public, private, prime_number)
