# This is a simple file server for SUSTech CS305 Computer Network
import socket
import argparse
import threading

from modules.auth_core import AuthCore
from modules.http_model import Request
from modules.request_handler import RequestHandler
from modules.util import display_some


class HTTPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.shutdown_flag = threading.Event()
        self.auth_core = AuthCore()

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
        print('-------------------------------')

        try:
            while not self.shutdown_flag.is_set():
                client_socket, _ = self.socket.accept()
                print(f"Client {client_socket.getpeername()} connected.\n")
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                )
                client_thread.daemon = True
                # set daemon so main thread can exit when receives ctrl-c
                client_thread.start()
        except KeyboardInterrupt:
            exit()

    def handle_client(self, client_socket: socket.socket):
        handler = RequestHandler(self)
        while True:
            try:
                request = Request.from_socket(client_socket)
                if request is None:
                    client_socket.close()
                    return
                response = handler.handle_request(request)
                res_bytes = response.to_bytes()
                print('--Response:')
                display_some(res_bytes)
                print('--EOF-Response--\n')
                client_socket.sendall(res_bytes)
                if 'Connection' in request.headers and request.headers['Connection'] == 'close':
                    client_socket.close()
                    return
            except SyntaxError:
                pass


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
