"""
Module used for encrypting and decrypting text.
"""
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from project.hash import calculate_md5

def encrypt(data, key):
    '''
    key -> password after md5, type: bytes
    data -> data to encrypt, type: str
    '''
    data = data.encode()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    ciphertext = b64encode(ct_bytes).decode("utf-8")
    init_vec = b64encode(cipher.iv).decode("utf-8")
    return f"{ciphertext} {init_vec}"


def decrypt(data, key):
    '''
    key -> password after md5, type: bytes
    data -> data to encrypt, type: str
    '''
    try:
        ciphertext, init_vec = data.split()
        ciphertext, init_vec = b64decode(ciphertext), b64decode(init_vec)
        cipher = AES.new(key, AES.MODE_CBC, init_vec)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except (ValueError, KeyError):
        print("Error, message corrupted or key incorrect")
    return plaintext


def generate_key(password):
    """
    Function used to generate cryptographic key (string).
    """
    hashed_pass = calculate_md5(password)
    return hashed_pass.encode()
