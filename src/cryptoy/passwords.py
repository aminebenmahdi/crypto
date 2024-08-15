import hashlib
import os
from random import Random

import names

def hash_password(password: str) -> str:
    # Hash the given password using SHA-3-256
    password_encoded = password.encode()
    hashed = hashlib.sha3_256(password_encoded).hexdigest()
    return hashed

def hash_password_with_salt(salt: str, password: str) -> str:
    # Hash the concatenated salt and password using SHA-3-256
    combined = salt + password
    combined_encoded = combined.encode()
    hashed = hashlib.sha3_256(combined_encoded).hexdigest()
    return hashed

def random_salt() -> str:
    # Generate a random salt of 32 bytes and return it as a hexadecimal string
    random_bytes = os.urandom(32)
    salt_hex = random_bytes.hex()
    return salt_hex

def generate_users_and_password_hashes(passwords: list[str], count: int = 32) -> dict[str, str]:
    rng = Random()  # Create an instance of Random for selecting passwords

    # Generate user names and hash their passwords
    users_and_password_hashes = {
        names.get_full_name(): hash_password(rng.choice(passwords))
        for _ in range(count)
    }
    return users_and_password_hashes

def attack(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, str]:
    # Create a dictionary mapping password hashes to passwords
    hash_to_password = {hash_password(pwd): pwd for pwd in passwords}

    # Match passwords from the database with the hash-to-password mapping
    users_and_passwords = {}
    for user, pwd_hash in passwords_database.items():
        if pwd_hash in hash_to_password:
            users_and_passwords[user] = hash_to_password[pwd_hash]

    return users_and_passwords

def fix(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, dict[str, str]]:
    # Upgrade passwords in the database to include salt and hash
    users_and_passwords = attack(passwords, passwords_database)

    new_database = {}
    for user, password in users_and_passwords.items():
        salt = random_salt()
        password_hash = hash_password_with_salt(salt, password)
        new_database[user] = {
            "password_hash": password_hash,
            "password_salt": salt
        }

    return new_database

def authenticate(user: str, password: str, new_database: dict[str, dict[str, str]]) -> bool:
    # Verify user credentials against the upgraded database
    if user in new_database:
        salt = new_database[user]["password_salt"]
        expected_hash = new_database[user]["password_hash"]
        actual_hash = hash_password_with_salt(salt, password)
        return actual_hash == expected_hash
    return False


