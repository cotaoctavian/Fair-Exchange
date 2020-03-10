import socket
import pickle
import utils
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import random

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
        self.pg_public_key = None
        self.session_id = None
        self.session_signature = None

    def get_merchant_public_key(self):
        f = open("public/merchant_public_key.pem", "rb")
        self.merchant_public_key = RSA.importKey(f.read())
        f.close()

    def get_pg_public_key(self):
        f = open("public/pg_public_key.pem", "rb")
        self.pg_public_key = RSA.importKey(f.read())
        f.close()

    def connect_to_merchant(self, host, port):
        self.socket.connect((host, port))

        # -------------------------------------- Setup protocol -------------------------------------------

        # 1
        self.get_merchant_public_key()

        # Encrypt client key with AES symmetric key + AES symmetric key encrypted with merchant rsa public key
        payload = hybrid_encryption(self.public_key, self.merchant_public_key)
        self.socket.send(pickle.dumps(payload))

        # Received data from Merchant. (Session id and SigM(Sid))
        data = self.socket.recv(8192)
        payload = pickle.loads(data)

        encrypted_aes_key = payload['k_encryption']
        decrypted_aes_key = utils.rsa_decryption(encrypted_aes_key, self.private_key)

        self.session_id = utils.aes_decryption(decrypted_aes_key, payload['session_id'])
        self.session_signature = utils.aes_decryption(decrypted_aes_key, payload['sid_signature'])

        if utils.verify_signature(self.session_id, self.merchant_public_key, self.session_signature):
            print(f"[RECEIVED] Session id: \n{self.session_id}\n")
            print(f"[RECEIVED] Session signature: \n{self.session_signature}\n")
        else:
            print("[ERROR] Invalid signature")
            exit(0)

        # ------------------------------------------- Exchange -------------------------------------------

        self.get_pg_public_key()
        nonce = random.getrandbits(16)
        order_description = "Omen by HP 15-dc0018nq"
        amount = 3000

        # PO signature
        po_client_signature = utils.proceed_signature(pickle.dumps([order_description, self.session_id, amount, nonce]),
                                                      self.private_key)

        # payment order
        po = {
            "OrderDesc": order_description,
            "SID": self.session_id,
            "Amount": amount,
            "NC": nonce,
            "SigC": po_client_signature
        }

        # payment information
        pi = {
            "CardN": "4034783123305160",
            "CardExp": "04/2025",
            "CCode": "627",
            "SID": self.session_id,
            "Amount": amount,
            "PubKC": self.public_key,
            "NC": nonce,
            "M": "Amazon"
        }

        print(f"[CREATE] PO: \n{po}\n")
        print(f"[CREATE] PI: \n{pi}\n")

        # PI client signature
        pi_client_signature = utils.proceed_signature(pickle.dumps(pi), self.private_key)

        print(f"[CREATE] PI Client Signature: \n{pi_client_signature}\n")

        # Encrypt PI, SigC(PI) with PG RSA public key
        k = utils.generate_k()
        encrypted_pi = utils.aes_encryption(k, pickle.dumps([pi, pi_client_signature]))
        encrypted_key = utils.rsa_encryption(k, self.pg_public_key)

        pm = {
            "encrypted_data": encrypted_pi,  # encrypted_data = PI, SigC(PI)
            "encrypted_key": encrypted_key
        }

        print(f"[CREATE] PM: \n{pm}\n")

        # Encrypt PM, PO with M rsa public key
        k = utils.generate_k()
        encrypted_pm_po = utils.aes_encryption(k, pickle.dumps([pm, po]))
        encrypted_pm_po_key = utils.rsa_encryption(k, self.merchant_public_key)

        payload = {
            "pm_po": encrypted_pm_po,
            "pm_po_key": encrypted_pm_po_key
        }

        # 3.
        print(f"[SENT] PM, PO: \n{payload}\n")
        self.socket.send(pickle.dumps(payload))

        # 6.
        # Receive payload Resp, Sid, SigPG(Resp, Sid, Amount, NC)
        data = self.socket.recv(4096)
        payload = pickle.loads(data)
        print(f"[RECEIVED] Resp, Sid, SigPG(Resp, Sid, Amount, NC): \n{payload}\n")

        # Decrypt data
        decrypted_payload_key = utils.rsa_decryption(payload["encrypted_key"], self.private_key)
        decrypted_payload = pickle.loads(utils.aes_decryption(decrypted_payload_key, payload["encrypted_payload"]))

        # Verify signature and session id
        if self.session_id == decrypted_payload["SID"]:
            if utils.verify_signature(
                    pickle.dumps([decrypted_payload["Resp"], self.session_id, pi["Amount"], pi["NC"]]),
                    self.pg_public_key, decrypted_payload["SigPG"]):

                print(f"[RECEIVED] Response of transaction: \n{decrypted_payload['Resp']}\n")
                self.socket.close()

            else:
                print(f"[ERROR] Invalid signature")
        else:
            print(f"[ERROR] Invalid session id")


if __name__ == '__main__':
    client = Client()
    client.connect_to_merchant("127.0.0.1", 3000)
