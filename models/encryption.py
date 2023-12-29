import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives import hashes


def encrypt_asy(body: bytes, public_key) -> bytes:
    """Encrypt a plain text with a public key."""
    return public_key.encrypt(
        body,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_asy(body: bytes, private_key) -> bytes:
    """Decrypt a cipher text with a private key."""
    return private_key.decrypt(
        body,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def encrypt_sym(body: bytes, key, iv) -> bytes:
    """

    :param body: Original text
    :param key: symmetric_key
    :param iv:
    :return:
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    block_size = cipher.algorithm.block_size // 8
    padder = pad.PKCS7(block_size * 8).padder()
    padded_body = padder.update(body) + padder.finalize()
    ciphertext = encryptor.update(padded_body) + encryptor.finalize()
    return ciphertext


def decrypt_sym(body: bytes, key, iv) -> bytes:
    """

    :param body: Ciphertext
    :param key: symmetric_key
    :param iv:
    :return:
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    block_size = cipher.algorithm.block_size // 8
    unpadder = pad.PKCS7(block_size * 8).unpadder()
    padded_plain_text = decryptor.update(body) + decryptor.finalize()
    plain_text = unpadder.update(padded_plain_text) + unpadder.finalize()
    return plain_text


def gen_symmetric_key() -> tuple[bytes, bytes]:
    """Generate a key and an iv."""
    symmetric_key = os.urandom(32)
    iv = os.urandom(16)
    return symmetric_key, iv
