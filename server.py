# This is a simple file server for SUSTech CS305 Computer Network
import socket
import argparse
import struct
import threading
import os
import json
import base64

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
TEXT = "text/plain"

conn_pool = []


# store connection pool


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
        table += f'  <li><a href="http://localhost:{port}/{cur_dir}?SUSTech-HTTP=0">/</a></li>\n'
        table += f'  <li><a href="http://localhost:{port}/{parent}?SUSTech-HTTP=0">../</a></li>\n'

        for file in os.listdir(root):
            if file == '.DS_Store':
                continue
            ref = cur_dir + f'/{file}'
            href = f'<a href="http://localhost:{port}/{ref.strip("/")}?SUSTech-HTTP=0">'
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


def gen_txt(path):
    items = os.listdir(path)
    # Generate an HTML page displaying the directory contents
    content = "<html><body>"
    content += f"<h1>Index of {path}</h1>"
    content += "<ul>"
    for item in items:
        item_path = os.path.join(path, item)
        if os.path.isdir(item_path):
            item += "/"
        content += f'<li><a href="{item}">{item}</a></li>'
    content += "</ul>"
    content += "</body></html>"
    return content


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
    # a simple request class containing method, url and headers
    def __init__(self, method: str, url: str, headers: {str: str}, request_data: str):
        self.method = method  # GET, POST, PUT, DELETE
        self.url = url  # e.g. /index.html
        self.headers = headers
        self.request_data = request_data

    @classmethod
    def from_socket(cls, sock: socket.socket) -> "Request":
        # read the request from socket
        # get method, url and headers
        request_data = sock.recv(1024).decode("utf-8")
        if not request_data:
            return None

        request_lines = request_data.split("\r\n")
        request_line = request_lines[0]
        method, url, _ = request_line.split(" ")

        headers = {}
        for line in request_lines[1:]:
            if not line:
                break
            parts = line.split(":", 1)
            # If the header is not in the format of "key: value", ignore it
            if len(parts) != 2:
                break
            headers[parts[0].strip()] = parts[1].strip()

        print(f"request method: {method}")
        print(f"request url: {url}")
        return cls(method, url, headers, request_data)

    def __repr__(self) -> str:
        # output request
        request = "{} {} HTTP/1.1\r\n".format(self.method, self.url)
        request += "\r\n".join("{}: {}".format(k, v) for k, v in self.headers.items())
        request += "\r\n\r\n"
        return request

    def extract_data(self):
        content_length = int(self.headers.get("Content-Length"))
        data_start = self.request_data.find("\r\n\r\n") + 4
        data = self.request_data[data_start:data_start + content_length]
        return data


def authenticate(authorized_users, request):
    # Get the username and password from the Authorization header
    # As the info is encoded in base64, we need to decode it first
    base64_string = request.headers.get("Authorization").split(" ")[1]
    base64_bytes = base64_string.encode("ascii")
    authorization = base64.b64decode(base64_bytes).decode("ascii")
    username, password = authorization.split(":")
    # Check if the username and password are valid
    if username in authorized_users and authorized_users[username] == password:
        return True
    else:
        return False


class Response:
    # a simple response class containing status code, headers and body
    def __init__(self):
        self.status_code = 200
        self.body = b"Default body."
        self.headers = {"Connection": "keep-alive"}
        # The connection will be closed only when the client sends a "Connection: close" header.

    def generate_status_line(self):
        return "HTTP/1.1 " + status_codes[self.status_code]

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

    def set_unauthorized(self):
        self.status_code = 401
        self.set_header("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
        self.set_strbody("<h1>401 Unauthorized</h1>")

    def set_status(self):
        if self.status_code == 401:
            self.set_header("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
            self.set_strbody("<h1>401 Unauthorized</h1>")
        elif self.status_code == 400:
            self.set_strbody("<h1>400 Bad Request</h1>")
        elif self.status_code == 403:
            self.set_strbody("<h1>403 Forbidden</h1>")
        elif self.status_code == 404:
            self.set_strbody("<h1>404 Not Found</h1>")
        elif self.status_code == 405:
            self.set_strbody("<h1>405 Method Not Allowed</h1>")
        elif self.status_code == 416:
            self.set_strbody("<h1>416 Range Not Satisfiable</h1>")
        elif self.status_code == 502:
            self.set_strbody("<h1>502 Bad Gateway</h1>")
        elif self.status_code == 503:
            self.set_strbody("<h1>503 Service Temporarily Unavailable</h1>")

    def generate_response_bytes(self):
        if self.status_code != 200:
            self.set_status()
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
        self.authorized_users = {
            "11911922": "ok",
            "12111448": "ok"
        }

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow reuse of socket address
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)  # Number of connections to queue

        print(f"Server is now listening on {self.host}: {self.port}")
        print("Press Ctrl+C to stop the server")


        try:
            while not self.shutdown_flag.is_set():
                client_socket, client_address = self.socket.accept()
                print(f"Client connected {client_address[0]}:{client_address[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                )
                client_thread.setDaemon(True)
                # set daemon so main thread can exit when receives ctrl-c
                client_thread.start()
        except KeyboardInterrupt:
            self.shutdown()

    def handle_client(self, client_socket):
        while True:
            request = Request.from_socket(client_socket)
            if request is None:
                client_socket.close()
                break

            response = Response()
            response.set_content_type(HTML)

            # Check if the request includes valid Authorization header
            if request.headers.get("Authorization") is None:
                # No Authorization header
                response.status_code = 401
            else:
                if not authenticate(self.authorized_users, request):
                    # Invalid Authorization header
                    response.status_code = 401
                else:
                    # print(f"authorized user: {request.headers.get('Authorization')}")
                    if request.method == "POST":
                        self.handle_post(response, request, client_socket)
                    elif request.method == "GET":
                        # Handle GET request
                        self.handle_get(response, request)
                    else:
                        response.set_strbody("<h1>Hello World</h1>")
                        # Error handling
                        # response = Response(405)
                        # response.set_strbody("<h1>Method Not Allowed</h1>")

            client_socket.sendall(response.generate_response_bytes())
            if request.headers.get("Connection") == "close":
                client_socket.close()
                break

    def handle_get(self, response, request):
        # http://localhost:8080/[access_path]?SUSTech-HTTP=[01]
        # access_path is the relative path under the /data/ folder
        relative_path = request.url.split("?")[0]
        path = root_dir + relative_path
        if "SUSTech-HTTP" not in request.url:
            response.status_code = 400
            return

        # Check if the user is valid
        if relative_path != "/":
            username_in_path = request.url.split("?")[0].split("/")[1]
            print(f"username in path: {username_in_path}")
            base64_string = request.headers.get("Authorization").split(" ")[1]
            base64_bytes = base64_string.encode("ascii")
            authorization = base64.b64decode(base64_bytes).decode("ascii")
            username, password = authorization.split(":")
            if username != username_in_path or self.authorized_users[username] != password:
                response.status_code = 403
                return

        if relative_path.startswith("/upload") or relative_path.startswith("/delete"):
            response.status_code = 405
            return

        operation = request.url.split("=")[-1]
        if os.path.isdir(path):
            if operation == "0":
                response.set_content_type(HTML)
                response.set_strbody(gen_html(path))
            elif operation == "1":
                # response directory meta data
                response.set_content_type(TEXT)
                response.set_strbody(gen_txt(path))
        elif os.path.isfile(path):
            response.set_content_type(FILE)
            response.set_bbody(build_file_bytes(path))
        else:
            response.status_code = 404
            return

    def handle_post(self, response, request, client_socket):
        # Check if path is provided
        if "path=" not in request.url:
            response.status_code = 400
            return

        # Check if the user is valid
        username_in_path = request.url.split("/")[-1]  # path =  http://localhost:8080/upload?path=/11912113/
        base64_string = request.headers.get("Authorization").split(" ")[1]
        base64_bytes = base64_string.encode("ascii")
        authorization = base64.b64decode(base64_bytes).decode("ascii")
        username, password = authorization.split(":")
        if username != username_in_path or self.authorized_users[username] != password:
            response.status_code = 403
            return

        # Determine the operation
        if request.url.startswith("/upload?"):
            self.handle_upload(response, request, client_socket)
        elif request.url.startswith("/delete?"):
            self.handle_delete(response, request)
        else:
            response.status_code = 405
            return

    def handle_upload(self, response, request, client_socket):
        # upload url: http://localhost:8080/upload?path=/11912113/

        # Check if the target directory exist
        path = root_dir + request.url.split("=")[-1]  # root_dir = os.curdir + '/data'
        if not os.path.isdir(path):
            response.status_code = 404
            return

        # Upload the file
        # Get the file name
        filename = request.headers.get("Content-Disposition").split("=")[-1]
        filename = filename.replace('"', '')
        # Get the file content
        data = request.extract_data()
        # Store the file
        file_path = os.path.join(path, filename)
        with open(file_path, 'w') as file:
            file.write(data)
        return

    def handle_delete(self, response, request):
        # delete url: http://localhost:8080/delete?path=/11912113/abc.py
        # Check if the target file exist
        path = root_dir + request.url.split("=")[-1]
        if not os.path.isfile(path):
            response.status_code = 404
            return

        # Delete the file
        os.remove(path)

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
