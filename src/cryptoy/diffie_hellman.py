import random
import sys

from cryptoy.utils import pow_mod

sys.setrecursionlimit(5000)  # Necessary for large exponentiation in pow_mod

def keygen(prime_number: int, generator: int) -> dict[str, int]:
    pr = random.randint(2, prime_number - 1)
    pu = pow_mod(generator, pr, prime_number)
    return {"public_key": pu, "private_key": pr}

def compute_shared_secret_key(public: int, private: int, prime_number: int) -> int:
    return pow_mod(public, private, prime_number)
