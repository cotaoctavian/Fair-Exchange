import pickle
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5

BLOCK_SIZE = 16


# K -> AES key
def generate_k():
    return get_random_bytes(16)


def get_session_id():
    return get_random_bytes(16)


def aes_encryption(key, message):
    aes_cipher = AES.new(key, AES.MODE_ECB)
    k_encrypted_message = aes_cipher.encrypt(pad(message, BLOCK_SIZE))

    return k_encrypted_message


def aes_decryption(key, message):
    aes_cipher = AES.new(key, AES.MODE_ECB)
    k_decrypted_message = unpad(aes_cipher.decrypt(message), BLOCK_SIZE)

    return k_decrypted_message


def rsa_encryption(key, rsa_key):
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    rsa_encrypted_message = rsa_cipher.encrypt(key)
    return rsa_encrypted_message


def rsa_decryption(key, rsa_key):
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    rsa_decrypted_message = rsa_cipher.decrypt(key)
    return rsa_decrypted_message


def proceed_signature(data, private_key):
    digest = SHA256.new()
    digest.update(data)

    signer = PKCS1_v1_5.new(private_key)
    sign = signer.sign(digest)
    return sign


def verify_signature(data, public_key, signature):
    digest = SHA256.new()
    digest.update(data)
    signer = PKCS1_v1_5.new(public_key)

    if signer.verify(digest, signature):
        return True
    return False
