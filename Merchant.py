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
        self.pg_public_key = None
        self.pg_socket = None

    def establish_connection(self):
        self.socket.bind((self.HOST, self.port))
        self.socket.listen(1)
        self.connection, self.address = self.socket.accept()
        print("Connected address: ", self.address)

    def post_public_key(self):
        f = open("public/merchant_public_key.pem", "wb")
        f.write(self.public_key.exportKey('PEM'))
        f.close()

    def get_pg_public_key(self):
        f = open("public/pg_public_key.pem", "rb")
        self.pg_public_key = RSA.importKey(f.read())
        f.close()

    def setup(self):
        print("The merchant is running on port: 3000.")
        print("\n -------------------------------------------------------------------------------------------- \n")

        # -------------------------------------- Setup protocol ----------------------------------------
        print("Setup sub-protocol: \n")

        # 2
        # receive data
        data = self.connection.recv(4096)

        # deserialize data
        payload = pickle.loads(data)

        # Hybrid decryption of AES and RSA client's key
        k, self.public_client_key = hybrid_decryption(payload, self.private_key)
        print(f"[RECEIVED] Client's AES key: \n{k}\n")
        print(f"[RECEIVED] Client's public key: \n{self.public_client_key}\n")

        # Create session id and digital signature using private merchant RSA key
        session_id = utils.get_session_id()
        client_signature = utils.proceed_signature(session_id, self.private_key)

        print(f"[CREATE] Session id: \n{session_id}\n")
        print(f"[CREATE] Client signature: \n{client_signature}\n")

        # Encrypt data with AES key
        k = utils.generate_k()
        encrypted_session_id = utils.aes_encryption(k, session_id)
        encrypted_client_signature = utils.aes_encryption(k, client_signature)

        # Encrypt AES key with client's RSA public key
        encrypted_k = utils.rsa_encryption(k, RSA.importKey(self.public_client_key))

        # Send payload to client
        prepared_payload = {
            "session_id": encrypted_session_id,
            "sid_signature": encrypted_client_signature,
            "k_encryption": encrypted_k
        }

        print(f"[SENT] Encrypted session id: \n{encrypted_session_id}\n")
        print(f"[SENT] Encrypted client signature: \n{encrypted_client_signature}\n")
        self.connection.send(pickle.dumps(prepared_payload))

        # ---------------------------------- Exchange protocol -----------------------------------------

        print("\n -------------------------------------------------------------------------------------------- \n")
        print("Exchange protocol:\n")
        # receive data
        data = self.connection.recv(4096)

        # deserialize data
        second_payload = pickle.loads(data)

        # decrypt
        pm_po_key = utils.rsa_decryption(second_payload["pm_po_key"], self.private_key)
        pm_po = utils.aes_decryption(pm_po_key, second_payload["pm_po"])

        # deserialize PM, PO
        loaded_pm_po = pickle.loads(pm_po)
        pm, po = loaded_pm_po[0], loaded_pm_po[1]

        print(f"[RECEIVED] PM: \n{pm}\n")
        print(f"[RECEIVED] PO: \n{po}\n")

        # verify signature
        if utils.verify_signature(pickle.dumps([po["OrderDesc"], po["SID"], po["Amount"], po["NC"]]),
                                  RSA.importKey(self.public_client_key), po["SigC"]):

            # 4.
            # Create signature for pg using merchant private key (SigM(SID, Amount, PubKC))
            merchant_signature = utils.proceed_signature(
                pickle.dumps([po["SID"], po["Amount"], self.public_client_key]),
                self.private_key)

            print(f"[CREATE] Merchant signature: \n{merchant_signature}\n")

            # Encrypt data (PM, SigM) and AES symmetric key
            k = utils.generate_k()
            encrypted_pm = utils.aes_encryption(k, pickle.dumps([pm, merchant_signature]))
            encrypted_pm_k = utils.rsa_encryption(k, self.pg_public_key)

            # Prepare payload
            prepared_pg_payload = {
                "encrypted_pm": encrypted_pm,
                "encrypted_pm_k": encrypted_pm_k
            }

            # Connecting to PG server
            self.pg_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.pg_socket.connect(("127.0.0.1", 3001))

            # Send data to PG (PM + SigM(Sid, PubKC, Amount))
            print(f"[SENT] Encrypted PM + SigM(Sid, PubKC, Amount): \n{encrypted_pm}\n")
            self.pg_socket.send(pickle.dumps(prepared_pg_payload))

            # 5
            # Receive data from PG (Resp, Sid, SigPG(Resp, Sid, Amount, NC))
            data = self.pg_socket.recv(4096)
            pg_payload = pickle.loads(data)

            decrypted_pg_key = utils.rsa_decryption(pg_payload[1], self.private_key)
            decrypted_pg_payload = utils.aes_decryption(decrypted_pg_key, pg_payload[0])
            deserialized_pg_payload = pickle.loads(decrypted_pg_payload)

            print(f"[RECEIVED] Resp, Sid, SigPG(Resp, Sid, Amount, NC): \n{deserialized_pg_payload}\n")

            # 6
            # Verify PG signature and session id.
            if session_id == deserialized_pg_payload["SID"]:
                if utils.verify_signature(
                        pickle.dumps([deserialized_pg_payload["Resp"], po["SID"], po["Amount"], po["NC"]]),
                        self.pg_public_key, deserialized_pg_payload["SigPG"]):

                    # Encrypt data (Resp, Sid, SigPG(Resp, Sid, Amount, NC)) with client's public key
                    k = utils.generate_k()
                    encrypted_merchant_payload = utils.aes_encryption(k, decrypted_pg_payload)
                    encrypted_merchant_key = utils.rsa_encryption(k, RSA.importKey(self.public_client_key))

                    prepared_payload = {
                        "encrypted_payload": encrypted_merchant_payload,
                        "encrypted_key": encrypted_merchant_key
                    }

                    print(f"[SENT] Resp, Sid, SigPG(Resp, Sid, Amount, NC): \n{prepared_payload}\n")
                    self.connection.send(pickle.dumps(prepared_payload))

                else:
                    print(f"[ERROR] Invalid signature")
                    exit(2)
            else:
                print(f"[ERROR] Invalid session id")
                exit(1)

        else:
            print("[ERROR] Invalid signature")
            exit(0)

        self.connection.close()


if __name__ == '__main__':
    merchant = Merchant()
    merchant.post_public_key()
    merchant.get_pg_public_key()
    merchant.establish_connection()
    merchant.setup()
