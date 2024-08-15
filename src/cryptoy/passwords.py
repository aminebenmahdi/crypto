import hashlib
import os
from random import Random

import names

def hash_password(password: str) -> str:
    # Hash the password using SHA-3-256
    return hashlib.sha3_256(password.encode()).hexdigest()

def hash_password_with_salt(salt: str, password: str) -> str:
    # Hash the concatenated salt and password using SHA-3-256
    combined = salt + password
    return hashlib.sha3_256(combined.encode()).hexdigest()

def random_salt() -> str:
    # Generate a random 32-byte salt and convert it to a hexadecimal string
    return os.urandom(32).hex()

def generate_users_and_password_hashes(passwords: list[str], count: int = 32) -> dict[str, str]:
    rng = Random()  # Create a random number generator instance

    # Generate a dictionary with random names and hashed passwords
    user_password_hashes = {
        names.get_full_name(): hash_password(rng.choice(passwords))
        for _ in range(count)
    }
    return user_password_hashes

def attack(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, str]:
    # Create a dictionary mapping password hashes to passwords
    hash_to_password = {hash_password(pwd): pwd for pwd in passwords}

    # Map users to their passwords if the hash matches
    found_passwords = {}
    for user, pwd_hash in passwords_database.items():
        if pwd_hash in hash_to_password:
            found_passwords[user] = hash_to_password[pwd_hash]

    return found_passwords

def fix(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, dict[str, str]]:
    # Upgrade password storage with salt and hashed password
    found_passwords = attack(passwords, passwords_database)

    upgraded_db = {}
    for user, password in found_passwords.items():
        salt = random_salt()
        salted_hash = hash_password_with_salt(salt, password)
        upgraded_db[user] = {"password_hash": salted_hash, "password_salt": salt}

    return upgraded_db

def authenticate(user: str, password: str, new_database: dict[str, dict[str, str]]) -> bool:
    # Verify if the provided credentials match the stored credentials
    if user in new_database:
        salt = new_database[user]["password_salt"]
        hashed_password = new_database[user]["password_hash"]
        return hashed_password == hash_password_with_salt(salt, password)
    return False

