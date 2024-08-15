import hashlib
import os
from random import Random
import names


def hash_password(password: str) -> str:
    """Hash a password using SHA3-256."""
    return hashlib.sha3_256(password.encode()).hexdigest()


def random_salt() -> str:
    """Generate a random salt of 32 bytes, hex-encoded."""
    return os.urandom(32).hex()


def hash_password_with_salt(salt: str, password: str) -> str:
    """Generate a salted hash for the given password."""
    return hashlib.sha3_256((salt + password).encode()).hexdigest()


def generate_users_and_password_hashes(
    passwords: list[str], count: int = 32
) -> dict[str, str]:
    """
    Generate a dictionary of users with their hashed passwords.

    :param passwords: List of possible passwords.
    :param count: Number of users to generate.
    :return: Dictionary mapping user names to hashed passwords.
    """
    rng = Random()  # noqa: S311

    return {
        names.get_full_name(): hash_password(rng.choice(passwords))
        for _ in range(count)
    }


def attack(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, str]:
    """
    Perform a dictionary attack to retrieve passwords from their hashes.

    :param passwords: List of possible passwords.
    :param passwords_database: Dictionary mapping user names to hashed passwords.
    :return: Dictionary mapping user names to their cracked passwords.
    """
    hash_to_password = {hash_password(pwd): pwd for pwd in passwords}

    return {
        user: hash_to_password[pwd_hash]
        for user, pwd_hash in passwords_database.items()
        if pwd_hash in hash_to_password
    }


def fix(
    passwords: list[str], passwords_database: dict[str, str]
) -> dict[str, dict[str, str]]:
    """
    Fix the passwords database by adding salt to each password.

    :param passwords: List of possible passwords.
    :param passwords_database: Dictionary mapping user names to hashed passwords.
    :return: New database with salted password hashes.
    """
    users_and_passwords = attack(passwords, passwords_database)

    new_database = {
        user: {
            "password_hash": hash_password_with_salt((salt := random_salt()), password),
            "password_salt": salt,
        }
        for user, password in users_and_passwords.items()
    }

    return new_database


def authenticate(
    user: str, password: str, new_database: dict[str, dict[str, str]]
) -> bool:
    """
    Authenticate a user against the new database.

    :param user: User name.
    :param password: Password provided by the user.
    :param new_database: Database with salted password hashes.
    :return: True if authentication is successful, False otherwise.
    """
    if user in new_database:
        salt = new_database[user]["password_salt"]
        password_hash = new_database[user]["password_hash"]
        return password_hash == hash_password_with_salt(salt, password)
    return False
