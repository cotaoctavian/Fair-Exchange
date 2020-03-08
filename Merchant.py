import socket
import pickle
import utils
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad

BLOCK_SIZE = 16


# Message from client (setup protocol)
def hybrid_decryption(received_data, rsa_private_key):
    rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
    rsa_decrypted_message = rsa_cipher.decrypt(received_data["rsa_encryption"])

    aes_cipher = AES.new(rsa_decrypted_message, AES.MODE_ECB)
    k_decrypted_message = unpad(aes_cipher.decrypt(received_data["k_encryption"]), BLOCK_SIZE)

    return rsa_decrypted_message, k_decrypted_message


class Merchant:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.HOST = "127.0.0.1"
        self.port = 3000
        self.connection = None
        self.address = None
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        self.public_client_key = None

    def establish_connection(self):
        self.socket.bind((self.HOST, self.port))
        self.socket.listen(1)
        self.connection, self.address = self.socket.accept()
        print("Connected address: ", self.address)

    def post_public_key(self):
        f = open("public/merchant_public_key.pem", "wb")
        f.write(self.public_key.exportKey('PEM'))
        f.close()

    def setup(self):
        print("The merchant is running on port: 3000.")
        print("\n -------------------------------------------------------------------------------------------- \n")
        print("Setup sub-protocol:")
        data = self.connection.recv(4096)
        payload = pickle.loads(data)
        self.public_client_key = hybrid_decryption(payload, self.private_key)
        print(f"Client's AES key: {self.public_client_key[0]}")
        print(f"Client's public key: {self.public_client_key[1]}")

        session_id = utils.get_session_id()
        client_signature = utils.proceed_signature(session_id, self.private_key)

        print(session_id)
        print(client_signature)

        k = utils.generate_k()
        encrypted_session_id = utils.aes_encryption(k, session_id)
        encrypted_client_signature = utils.aes_encryption(k, client_signature)

        encrypted_k = utils.rsa_encryption(k, RSA.importKey(self.public_client_key[1]))

        prepared_payload = {
            "session_id": encrypted_session_id,
            "sid_signature": encrypted_client_signature,
            "k_encryption": encrypted_k
        }

        self.connection.send(pickle.dumps(prepared_payload))

        self.connection.close()


if __name__ == '__main__':
    merchant = Merchant()
    merchant.post_public_key()
    merchant.establish_connection()
    merchant.setup()
