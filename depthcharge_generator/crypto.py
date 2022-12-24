#begone cryptobros

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def get_aes_cipher(key):
    iv = bytearray(16)
    algorithm = algorithms.AES(key)
    return Cipher(algorithm, mode=modes.CBC(initialization_vector=iv))


def encrypt_data(data, key):
    while (len(data) % 16) != 0:
        data += b"\0"
    cipher = get_aes_cipher(key)
    encryptor = cipher.encryptor()
    data_enc = encryptor.update(data)
    return data_enc


def decrypt_data(data, key):
    cipher = get_aes_cipher(key)
    decryptor = cipher.decryptor()
    data_dec = decryptor.update(data)
    return data_dec


def encrypt_verify(data, key):
    encrypted = encrypt_data(data, key)
    if encrypted == data:
        raise Exception("Error encrypting data!")
    decrypted = decrypt_data(encrypted, key)
    if decrypted != data:
        raise Exception("Error decrypting encrypted data!")
    return encrypted


def hash_aes_cmac(data, key):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()
