import socket
import pickle
import utils
import json
from Cryptodome.PublicKey import RSA

BLOCK_SIZE = 16

bank = json.load(open("bank/accounts.json", "r"))


class PaymentGateway:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.HOST = "127.0.0.1"
        self.port = 3001
        self.connection = None
        self.address = None
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        self.merchant_public_key = None

    def post_public_key(self):
        f = open("public/pg_public_key.pem", "wb")
        f.write(self.public_key.exportKey('PEM'))
        f.close()

    def get_merchant_public_key(self):
        f = open("public/merchant_public_key.pem", "rb")
        self.merchant_public_key = RSA.importKey(f.read())
        f.close()

    def establish_connection(self):
        self.socket.bind((self.HOST, self.port))
        self.socket.listen(1)
        self.connection, self.address = self.socket.accept()
        print("Connected address: ", self.address)

    def run(self):
        # -------------------------------------- Exchange protocol ------------------------------------------------
        print("\nExchange protocol: \n")
        data = self.connection.recv(4096)
        payload = pickle.loads(data)

        # Decrypt PM from merchant
        decrypted_pm_key = utils.rsa_decryption(payload["encrypted_pm_k"], self.private_key)
        decrypted_pm = utils.aes_decryption(decrypted_pm_key, payload["encrypted_pm"])

        deserialized_pm = pickle.loads(decrypted_pm)  # contains PM, merchant signature.

        # Decrypt PI, SigC(PI)
        decrypted_pi_key = utils.rsa_decryption(deserialized_pm[0]["encrypted_key"], self.private_key)
        decrypted_pi = utils.aes_decryption(decrypted_pi_key, deserialized_pm[0]["encrypted_data"])

        # PI
        pi = pickle.loads(decrypted_pi)[0]

        # SigC(PI)
        pi_client_signature = pickle.loads(decrypted_pi)[1]

        # Decrypted merchant signature SigM(Sid, PubKC, Amount)
        decrypted_merchant_signature = deserialized_pm[1]

        print(f"[RECEIVED] PI: \n{pi}\n")
        print(f"[RECEIVED] SigC(PI): \n{pi_client_signature}\n")
        print(f"[RECEIVED] SigM(Sid, PubKC, Amount): \n{decrypted_merchant_signature}\n")

        self.get_merchant_public_key()

        # Verify merchant's signature SigM(Sid, Amount, PubKC)
        if utils.verify_signature(pickle.dumps([pi["SID"], pi["Amount"], pi["PubKC"]]),
                                  self.merchant_public_key, decrypted_merchant_signature):

            # Verify client's signature SigC(PI)
            if utils.verify_signature(pickle.dumps(pi), RSA.importKey(pi["PubKC"]), pi_client_signature):
                response = None
                for i in range(len(bank)):
                    item = bank[i]
                    if item["CardN"] == pi["CardN"] and item["CardExp"] == pi["CardExp"] and \
                            item["CCode"] == pi["CCode"]:

                        if pi["Amount"] <= item["Balance"]:
                            item["Balance"] -= pi["Amount"]
                            response = "Transaction accepted"
                            bank[i] = item
                            json.dump(bank, open("bank/accounts.json", "w"))
                        else:
                            response = "Transaction refused"

                        # 5.
                        # Creating PG signature SigPG(Resp, Sid, Amount, NC)
                        pg_signature = utils.proceed_signature(
                            pickle.dumps([response, pi["SID"], pi["Amount"], pi["NC"]]),
                            self.private_key)

                        print(f"[CREATE] Payment gateway signature: \n{pg_signature}\n")

                        # Preparing payload to be sent to merchant.
                        prepared_payload = {
                            "Resp": response,
                            "SID": pi["SID"],
                            "SigPG": pg_signature
                        }

                        # Hybrid encryption using merchant's public key
                        k = utils.generate_k()
                        encrypted_payload = utils.aes_encryption(k, pickle.dumps(prepared_payload))
                        encrypted_payload_key = utils.rsa_encryption(k, self.merchant_public_key)

                        # Send data to merchant (Resp, Sid, SigPG(Resp, Sid, Amount, NC))
                        print(f"[SENT] Resp, Sid, SigPG(Resp, Sid, Amount, NC): "
                              f"\n{pickle.dumps([encrypted_payload_key, encrypted_payload])}\n")

                        self.connection.send(pickle.dumps([encrypted_payload, encrypted_payload_key]))
            else:
                print(f"[ERROR] Invalid signature")
                exit(1)
        else:
            print(f"[ERROR] Invalid signature")
            exit(0)

        self.connection.close()


if __name__ == '__main__':
    pg = PaymentGateway()
    pg.post_public_key()
    pg.establish_connection()
    pg.run()
