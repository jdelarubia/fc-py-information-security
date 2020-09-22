import hashlib

# Setup
SALTS = "known-salts.txt"
PASSWORDS = "top-10000-passwords.txt"


def get_salts() -> str:
    """Reads the content of known-salts.txt file, and return all its content
    appended as a string"""
    with open(SALTS) as fh:
        content = fh.readlines()
        return content


def hash_and_compare(word: str, hash: str) -> bool:
    """Hash word and compare it with hash"""
    hashed_word = hashlib.sha1(word.encode())
    return hashed_word.hexdigest() == hash


def crack_sha1_hash(hash: str, use_salts: bool = False) -> str:
    with open(PASSWORDS) as file_handler:
        dictionary = file_handler.readlines()

    salts = get_salts()

    for word in dictionary:
        word = word.strip()

        if use_salts:
            for salt in salts:
                salt = salt.strip()
                salt_variations = [word + salt, salt + word]

                for salted_word in salt_variations:
                    if hash_and_compare(salted_word, hash):
                        return word

        else:

            if hash_and_compare(word, hash):
                return word

    return "PASSWORD NOT IN DATABASE"
