import os
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES

PBKDF2_ITERATIONS = 200000
KEY_SIZE = 32  # 256 bits for AES-256
SALT_SIZE = 16 # 128 bits
NONCE_SIZE = 16 # 128 bits
STEGO_HEADER = b"STEGO"

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit encryption key using PBKDF2 with SHA256.

    Args:
        password (str): The password (seed phrase or private key) to derive the key from.
        salt (bytes): A random salt to use for key derivation.

    Returns:
        bytes: The derived 256-bit encryption key.
    """
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

def generate_salt() -> bytes:
    """
    Generates a random salt of SALT_SIZE bytes.

    Returns:
        bytes: A random salt.
    """
    return get_random_bytes(SALT_SIZE)

def encrypt_payload(key: bytes, payload: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts the payload using AES-GCM with a 'STEGO' header.

    Args:
        key (bytes): The 256-bit encryption key.
        payload (bytes): The data to be encrypted.

    Returns:
        tuple[bytes, bytes, bytes]: A tuple containing (nonce, ciphertext, tag).
    """
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(STEGO_HEADER)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return cipher.nonce, ciphertext, tag

def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Decrypts the payload using AES-GCM and verifies the 'STEGO' header and tag.

    Args:
        key (bytes): The 256-bit encryption key.
        nonce (bytes): The nonce used during encryption.
        ciphertext (bytes): The encrypted data.
        tag (bytes): The authentication tag.

    Returns:
        bytes: The decrypted payload.

    Raises:
        ValueError: If the authentication tag is invalid or the 'STEGO' header is missing.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(STEGO_HEADER)
    try:
        decrypted_payload = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_payload
    except ValueError as e:
        raise ValueError(f"Decryption failed: {e}")