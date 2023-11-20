# This is a simple file server for SUSTech CS307 Computer Network
import socket
import argparse
import threading

class Request:
    # a simple request class containing method, path and headers
    def __init__(self, method: str, path: str, headers: {str: str}):
        self.method = method # GET, POST, PUT, DELETE
        self.path = path # e.g. /index.html
        self.headers = headers

    @classmethod
    def from_socket(cls, sock: socket.socket) -> "Request":
        # read the request from socket
        request_data = sock.recv(1024).decode("ascii")
        if not request_data:
            return None

        request_lines = request_data.split("\r\n")
        request_line = request_lines[0]
        method, path, _ = request_line.split(" ")

        headers = {}
        for line in request_lines[1:]:
            if not line:
                break
            header, value = line.split(":", 1)
            headers[header.strip()] = value.strip()

        return cls(method, path, headers)
    
    def __repr__(self) -> str:
        # output request
        request = "{} {} HTTP/1.1\r\n".format(self.method, self.path)
        request += "\r\n".join("{}: {}".format(k, v) for k, v in self.headers.items())
        request += "\r\n\r\n"
        return request
    
class Response:
    # a simple response class containing status code, headers and body
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body

    def generate_status_line(self):
        status_line = ""
        code = self.status_code
        if code == 200:
            status_line = "HTTP/1.1 200 OK"
        elif code == 404:
            status_line = "HTTP/1.1 404 Not Found"
        return status_line

    def generate_headers(self):
        # generate headers for response
        # including content length and content type
        headers = {}
        headers["Content-Length"] = len(self.body)
        headers["Content-Type"] = "text/html"
        return headers

    def generate_response_bytes(self):
        response = self.generate_status_line()
        response += "\r\n".join("{}: {}".format(k, v) for k, v in self.generate_headers().items())
        response += "\r\n\r\n"
        response += self.body
        return response.encode("ascii")

class HTTPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.shutdown_flag = threading.Event()

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow reuse of socket address
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)  # Number of connections to queue

        print(f"Server is now listening on {self.host}:{self.port}")
        print("Press Ctrl+C to stop the server")

        try:
            while not self.shutdown_flag.is_set():
                client_socket, client_address = self.socket.accept()
                print(f"Client connected {client_address[0]}:{client_address[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                )
                client_thread.start()
        except KeyboardInterrupt:
            self.shutdown()

    def handle_client(self, client_socket):
        request = Request.from_socket(client_socket)
        print(request)
        response = Response(200, "<h1>Hello World</h1>")
        client_socket.sendall(response.generate_response_bytes())
        if request.headers.get("Connection") == "keep-alive":
            client_socket.close()

    def shutdown(self):
        self.shutdown_flag.set()
        self.socket.close()

    

if __name__ == "__main__":
    # Create the argument parser
    parser = argparse.ArgumentParser(description="File Server")
    # Add the arguments, input ip addr and port
    parser.add_argument("-i", "--ip", type=str)
    parser.add_argument("-p", "--port", type=int)
    args = parser.parse_args()

    # Start the server and pass the ip and port
    server = HTTPServer(args.ip, args.port)
    server.start()


