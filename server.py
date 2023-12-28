# This is a simple file server for SUSTech CS305 Computer Network
import socket
import argparse
import threading
import base64

from auth_core import AuthCore
from http_model import Response, Request
from request_handler import RequestHandler
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pad


class HTTPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.shutdown_flag = threading.Event()
        self.auth_core = AuthCore()
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.client_symmetric_key = {}
        self.client_ivs = {}

        self.tmp_cnt = 0

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow reuse of socket address
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)  # Number of connections to queue
        print('-------------------------------')
        print("🥳Encryption Keys Generation Completed")

        print(f"Server is now listening on {self.host}: {self.port}")
        print("Press Ctrl+C to stop the server")
        print('-------------------------------\n')

        try:
            while not self.shutdown_flag.is_set():
                client_socket, client_address = self.socket.accept()
                print(f"Client connected {client_address[0]}:{client_address[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                )
                client_thread.daemon = True
                # set daemon so main thread can exit when receives ctrl-c
                client_thread.start()
        except KeyboardInterrupt:
            exit()

    def handle_client(self, client_socket):
        while True:
            request = Request.from_socket(client_socket)
            if request is None:
                client_socket.close()
                break
            print('-----------------------')
            request.info()
            print('-----------------------')
            handler = RequestHandler(self, request)
            response = handler.handle()

            client_socket.sendall(response.generate_response_bytes())
            if request.headers.get("Connection") == "close":
                client_socket.close()
                break

    def encryption_handle(self, request, response, client_socket):
        # 这个部分处理encryption的过程
        print("encryption handle")
        if request.url == "/public_key":
            client_socket.sendall(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            return False
        elif request.url == "/encrypted_symmetric_key":
            # reivce encrypted symmetric key
            encrypted_symmetric_key = request.headers.get("encrypted_symmetric_key")
            encrypted_symmetric_key = base64.b64decode(encrypted_symmetric_key)
            # decrypt symmetric key
            print("client encrypted symmetric key", encrypted_symmetric_key)
            symmetric_key = self.private_key.decrypt(
                encrypted_symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # store symmetric key
            self.client_symmetric_key[client_socket] = symmetric_key
            print("client symmetric key", symmetric_key)
            # send encrypted response
            response.set_strbody("encrypted response")
            client_socket.sendall(response.generate_response_bytes())
            return False
        elif request.url == "/encrypted_iv":
            # receive encrypted iv
            encrypted_iv = request.headers.get("encrypted_iv")
            encrypted_iv = base64.b64decode(encrypted_iv)
            # decrypt iv
            iv = self.private_key.decrypt(
                encrypted_iv,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # store iv
            self.client_ivs[client_socket] = iv
            print("client iv", iv)
            # send encrypted response
            response.set_strbody("encrypted response")
            client_socket.sendall(response.generate_response_bytes())
            return False
        else:
            if client_socket not in self.client_symmetric_key or client_socket not in self.client_ivs:
                # not encrypted symmetric key
                response.status_code = 401
                client_socket.sendall(response.generate_response_bytes())
                return False
            # use symmetric key to decrypt request body
            symmetric_key = self.client_symmetric_key[client_socket]
            iv = self.client_ivs[client_socket]
            body = request.body
            print("symmetric key", symmetric_key)
            # decrypt body
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            body = decryptor.update(base64.b64decode(body.encode('utf-8'))) + decryptor.finalize()
            # update body
            # request.body = base64.b64encode(body).decode('utf-8')
            block_size = cipher.algorithm.block_size // 8
            unpadder = pad.PKCS7(block_size * 8).unpadder()
            request.body = unpadder.update(body) + unpadder.finalize()
            request.body = request.body.decode('utf-8')
            # print("decrypted body", request.body)
            return True


if __name__ == "__main__":
    # Create the argument parser
    parser = argparse.ArgumentParser(description="File Server")
    # Add the arguments, input ip addr and port
    parser.add_argument("-i", "--ip", type=str)
    parser.add_argument("-p", "--port", type=int)
    args = parser.parse_args()

    # Start the server and pass the ip and port
    print("🚀Start Encryption Keys Generation")
    server = HTTPServer(args.ip, args.port)
    server.start()
