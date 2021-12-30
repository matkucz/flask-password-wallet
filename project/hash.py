"""
Module used to compute hashes (MD5, SHA512 and HMAC) and generate random string
used in salt and pepper.
"""

import hashlib
import random
import string
from os import getenv
from Cryptodome.Hash import HMAC, SHA512


def generate_random_string(
    size=16,
    chars = (
        string.ascii_lowercase +
        string.ascii_lowercase +
        string.digits +
        string.ascii_uppercase
    )
):
    """
    Function generates string with size and chars given in
    arguments.
    """
    return ''.join(random.choice(chars) for _ in range(size))


def calculate_sha512(text):
    '''
    Calculate sha512 hash.\n
    text -> string
    '''
    text = text.encode()
    message_digest = hashlib.sha512()
    message_digest.update(text)
    return message_digest.hexdigest()


def calculate_hmac(text, key):
    '''
    Calculate HMAC with SHA512 as algoritm.\n
    text -> string\n
    key -> string
    '''
    text = text.encode()
    key = key.encode()
    password_hash = HMAC.new(key, digestmod=SHA512)
    password_hash.update(text)
    return password_hash.hexdigest()


def calculate_md5(text):
    """
    Calculate MD5 hash.
    text -> string
    """
    text = text.encode()
    message_digest = hashlib.md5()
    message_digest.update(text)
    return message_digest.hexdigest()


def verify_hashed_text(text, salt, password_hash, is_hash):
    """
    Function verifies text from agrument. Password hash
    is calculated with hash from arguments and compared
    to password_hash. If is_hash is True, sha512 hashes are
    compared, else hmac.
    """
    if is_hash:
        pepper = str(getenv("HASH_PEPPER"))
        password = calculate_sha512(text + salt + pepper)
        if password_hash != password:
            raise ValueError("Hashes doesn't match.")
    else:
        key = salt.encode()
        hmac = HMAC.new(key, digestmod=SHA512)
        # text must be binary not string
        text = text.encode()
        hmac.update(text)
        hmac.hexverify(password_hash)
