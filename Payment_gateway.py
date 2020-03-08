import socket
from Cryptodome.PublicKey import RSA


class PaymentGateway:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.HOST = "127.0.0.1"
        self.port = 3001
        self.connection = None
        self.address = None
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def establish_connection(self):
        self.socket.bind((self.HOST, self.port))
        self.socket.listen(1)
        self.connection, self.address = self.socket.accept()

    def run(self):
        while True:
            data = self.connection.recv(100).decode("UTF-8")
            if len(data) > 0:
                print(data)

            if "exit" in data:
                break

        self.connection.close()


if __name__ == '__main__':
    pg = PaymentGateway()
    pg.establish_connection()
    pg.run()
