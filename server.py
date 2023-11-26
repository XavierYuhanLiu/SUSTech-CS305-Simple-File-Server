# This is a simple file server for SUSTech CS305 Computer Network
import socket
import argparse
import struct
import threading
import os
import json

status_codes = {
    200: '200 OK',
    206: '206 Partial Content',
    301: '301 Redirect',
    400: '400 Bad Request',
    401: '401 Unauthorized',
    403: '403 Forbidden',
    404: '404 Not Found',
    405: '405 Method Not Allowed',
    416: '416 Range Not Satisfiable',
    502: '502 Bad Gateway',
    503: '503 Service Temporarily Unavailable'
}

root_dir = os.curdir + '/data'

HTML = "text/html"
FILE = "application/octet-stream"


def decode_path(path):
    relative_path = '/'.join(path.split('/')[3:])
    des_path = root_dir + '/' + relative_path
    if os.path.exists(des_path):
        return des_path
    else:
        return None


def build_file_bytes(path):
    body = b''
    with open(path, 'rb') as f:
        for line in f:
            body += line
    return body


def gen_html(root):
    port = 9000
    heading = f'Directory listing for {root}'
    table = ''
    if os.path.exists(root):
        cur_dir = '/'.join(root.split('/')[2:])
        parent = '/'.join(cur_dir.split('/')[:-1])

        table += f'  <li><a href="http://localhost:{port}/{cur_dir}">/</a></li>\n'
        table += f'  <li><a href="http://localhost:{port}/{parent}">../</a></li>\n'
        for file in os.listdir(root):
            if file == '.DS_Store':
                continue
            ref = cur_dir + f'/{file}'
            href = f'<a href="http://localhost:{port}/{ref.strip("/")}">'
            table += rf'  <li>{href}{file}' + (
                '/' if os.path.isdir(os.path.join(root, file)) else '') + r'</a></li>' + '\n'
    else:
        raise NotImplementedError

    return f"""<!DOCTYPE html>
<html>
<head> 
<meta charset="utf-8"> 
<title>Files</title> 
</head> 
<body>

<h1>{heading}</h1>
<hr>
<ul>
{table}
</ul>
<hr>

</body>
</html>"""


def send_file(conn, path):
    file_name = path.split('/')[-1]
    header_dic = {'filename': file_name,
                  'file_size': os.path.getsize(path)}

    header_json = json.dumps(header_dic)
    header_bytes = header_json.encode('utf-8')
    conn.send(struct.pack('i', len(header_bytes)))
    conn.send(header_bytes)
    with open(path, 'rb') as f:
        for line in f:
            conn.send(line)


class Request:
    # a simple request class containing method, path and headers
    def __init__(self, method: str, path: str, headers: {str: str}):
        self.method = method  # GET, POST, PUT, DELETE
        self.path = path  # e.g. /index.html
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
    def __init__(self, status_code: int):
        self.status_code = status_code
        self.body = b"Default body."
        self.headers = {}

    def generate_status_line(self):
        status_line = "HTTP/1.1 "
        return status_line + status_codes[self.status_code]

    def set_strbody(self, body):
        """
        Set the body from a str content.
        :param body: In str format.
        """
        self.body = body.encode("utf-8")

    def set_bbody(self, body):
        """
        Set the body from a bytes content.
        :param body: In bytes format.
        """
        self.body = body

    def set_content_type(self, content_type):
        self.headers["Content-Type"] = content_type

    def set_header(self, header, content):
        self.headers[header] = content

    def generate_response_bytes(self):
        self.headers["Content-Length"] = len(self.body)

        response = self.generate_status_line() + '\r\n'
        response += "\r\n".join("{}: {}".format(k, v) for k, v in self.headers.items())
        response += "\r\n\r\n"
        # response += self.body
        return response.encode("utf-8") + self.body


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
        print(request.path)
        path = root_dir + request.path
        response = Response(200)
        response.set_content_type(HTML)
        if os.path.isdir(path):
            response.set_strbody(gen_html(path))
        elif os.path.isfile(path):
            response.set_content_type(FILE)
            response.set_bbody(build_file_bytes(path))
        else:
            response.set_strbody("<h1>Hello World</h1>")

        client_socket.sendall(response.generate_response_bytes())
        if request.headers.get("Connection") == "keep-alive":
            pass
            # client_socket.close()

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
