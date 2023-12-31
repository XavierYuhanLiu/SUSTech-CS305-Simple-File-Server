import socket

from cryptography.hazmat.primitives import serialization

from modules.encryption import *
from modules.http_model import Request

ENC = 'ENCRYPTION/1.1'
POST = 'POST'
GET = 'GET'


def get_response_body(sock: socket.socket) -> bytes:
    data = sock.recv(4096)

    content_length = None
    parts = data.split(b'\r\n\r\n', 1)
    for line in parts[0].split(b'\r\n')[1:]:
        key, val = line.split(b':', 1)
        if key == b'Content-Length':
            content_length = int(val)


    partial_body = b'' if len(parts) == 1 else parts[1]
    body = partial_body

    unreceived_data_bytes = content_length - len(partial_body)
    while unreceived_data_bytes > 0:
        body += sock.recv(512)
        unreceived_data_bytes -= 512
    return body


class Client:
    def __init__(self):
        self.key, self.iv = gen_symmetric_key()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(('127.0.0.1', 8080))

    def exchange_info(self):
        public_key = self.get_public_key()
        print(f'Received public key. Size: {public_key.key_size}')

        encrypted_key = encrypt_asy(self.key, public_key)
        encrypted_iv = encrypt_asy(self.iv, public_key)
        self.send_encrypted_key_iv(encrypted_key, encrypted_iv)

    def get_public_key(self):
        request = Request('GET', '/public_key', {}, b'', 'PREENCRYPTION')
        self.socket.sendall(request.to_bytes())

        response = self.socket.recv(4096)
        public_key = response.split(b'\r\n\r\n', 1)[-1]
        public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )
        return public_key

    def send_encrypted_key_iv(self, encrypted_key, encrypted_iv):
        request = Request('POST', '/encrypted_symmetric_key', {}, encrypted_key, 'PREENCRYPTION')
        request.headers['Content-Length'] = len(encrypted_key)
        self.socket.sendall(request.to_bytes())
        response = self.socket.recv(4096)
        print(response.decode('utf-8'))
        print()

        request = Request('POST', '/encrypted_iv', {}, encrypted_iv, 'PREENCRYPTION')
        request.headers['Content-Length'] = len(encrypted_iv)
        self.socket.sendall(request.to_bytes())
        response = self.socket.recv(4096)
        print(response.decode('utf-8'))

    def run(self):
        print('--------Start-Communication--------')
        body = b''
        url = '/client1/a.txt'
        ciphertext = self.get(url, body)
        self.show_enc_process(ciphertext)

        body = b''
        url = '/client1?SUSTech-HTTP=1'
        ciphertext = self.get(url, body)
        self.show_enc_process(ciphertext)

        url = '/delete?path=client2/tommy.jpg'
        # This will fail because user in auth is client1
        ciphertext = self.post(url, body)
        self.show_enc_process(ciphertext)

    def get(self, url, body):
        headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
        enc_body = encrypt_sym(body, self.key, self.iv)
        request = Request(GET, url, headers, enc_body, ENC)
        self.socket.sendall(request.to_bytes())
        return get_response_body(self.socket)

    def post(self, url, body):
        enc_body = encrypt_sym(body, self.key, self.iv)

        headers = {
                   "Content-Length": len(enc_body), "Authorization": "Basic Y2xpZW50MToxMjM="
                   }

        request = Request(POST, url, headers, enc_body, ENC)
        self.socket.sendall(request.to_bytes())
        return get_response_body(self.socket)

    def show_enc_process(self, ciphertext):
        print(f'This is the ciphertext:\n{ciphertext}')
        print('After decryption:')
        print(decrypt_sym(ciphertext, self.key, self.iv).decode('utf-8'))
        print()


if __name__ == '__main__':
    client = Client()
    client.exchange_info()
    client.run()