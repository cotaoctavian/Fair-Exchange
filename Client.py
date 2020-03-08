import socket
import pickle
import utils
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad

BLOCK_SIZE = 16


def hybrid_encryption(message, rsa_pub_key):
    k = utils.generate_k()
    rsa_cipher = PKCS1_OAEP.new(rsa_pub_key)
    rsa_encrypted_message = rsa_cipher.encrypt(k)

    aes_cipher = AES.new(k, AES.MODE_ECB)
    k_encrypted_message = aes_cipher.encrypt(pad(message, BLOCK_SIZE))

    data = {
        "rsa_encryption": rsa_encrypted_message,
        "k_encryption": k_encrypted_message
    }

    return data


class Client:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey().exportKey()
        self.merchant_public_key = None
        self.session_id = None
        self.session_signature = None

    def connect_to_merchant(self, host, port):
        self.socket.connect((host, port))

        # Setup protocol
        self.get_merchant_public_key()
        payload = hybrid_encryption(self.public_key, self.merchant_public_key)
        self.socket.send(pickle.dumps(payload))

        data = self.socket.recv(8192)
        payload = pickle.loads(data)

        encrypted_aes_key = payload['k_encryption']
        decrypted_aes_key = utils.rsa_decryption(encrypted_aes_key, self.private_key)

        self.session_id = utils.aes_decryption(decrypted_aes_key, payload['session_id'])
        self.session_signature = utils.aes_decryption(decrypted_aes_key, payload['sid_signature'])

    def get_merchant_public_key(self):
        f = open("public/merchant_public_key.pem", "rb")
        self.merchant_public_key = RSA.importKey(f.read())
        f.close()


if __name__ == '__main__':
    client = Client()
    client.connect_to_merchant("127.0.0.1", 3000)
