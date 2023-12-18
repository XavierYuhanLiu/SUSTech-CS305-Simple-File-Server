# This is a simple file server for SUSTech CS305 Computer Network
import socket
import argparse
import struct
import threading
import os
import json
import base64

# HTTP status codes
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

# HTTP status code descriptions
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

root_dir = os.curdir + '/data'

HTML = "text/html"
FILE = "application/octet-stream"
TEXT = "text/plain"

conn_pool = []


# store connection pool

def decode_path(path: str):
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

# render html
def render(title: str, body: str, url: str):
    return f"""
<html>
    <head>
        <meta charset="utf-8"> 
        <title>{title}</title>
        <script src="https://cdn.bootcdn.net/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
    </head>
    <body>
        <h1>{title}</h1>
        <p>{body}</p>
    </body>""" + """
    <script>
        $(document).ready(function() {
            $('.send-request').on('click', function() {
                var listItem = $(this).closest('li');
                var itemText = listItem.find('span').text();

                // 发送 HTTP 请求
                $.ajax({
                url: '""" + url + """', // 替换为你的目标地址
                type: 'POST',
                data: { item: itemText },
                success: function(response) {
                    console.log('请求发送成功!');
                    // 在这里添加你的成功处理逻辑
                },
                error: function(xhr, status, error) {
                    console.error('请求发送失败:', error);
                    // 在这里添加你的错误处理逻辑
                }
                });
            });
        });


        function uploadFile() {
            var fileInput = document.getElementById('file-input');
            var file = fileInput.files[0];
            var formData = new FormData();
            formData.append('file', file);

            $.ajax({
                url: '"""+url+"""', // 替换为你的目标地址
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function(response) {
                console.log('文件上传成功!');
                // 在这里添加你的成功处理逻辑
                },
                error: function(xhr, status, error) {
                console.error('文件上传失败:', error);
                // 在这里添加你的错误处理逻辑
                }
            });
        }
    </script>
</html>
"""

# generate list page
def gen_page(root: str, port: int, url: str, enable: bool):
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
            if enable:
                table += rf'  <li>{href}{file}' + (
                    '/' if os.path.isdir(os.path.join(root, file)) else '') + r'</a><button class="send-request">delete</button></li>' + '\n'
            else:
                table += rf'  <li>{href}{file}' + (
                    '/' if os.path.isdir(os.path.join(root, file)) else '') + r'</a></li>' + '\n'
    else:
        raise NotImplementedError
    
    if enable:
        return render("Files", f"""
<h4>{heading}</h4>

<hr>
    <ul>
        {table}
    </ul>
<hr>

<input type="file" id="file-input">
<button onclick="uploadFile()">上传</button>
""", url)
    else:
                return render("Files", f"""
<h4>{heading}</h4>

<hr>
    <ul>
        {table}
    </ul>
<hr>
""", "")




def gen_txt(path):
    # Response with the name of all items in list under the target directory
    # `["123.png", "666/", "abc.py", "favicon.ico"]` in this case.
    items = os.listdir(path)
    # Convert list to str
    items = str(items)
    return items


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
    def __init__(self, method: str, url: str, headers: {str: str}, request_data: str, body:str):
        self.method = method  # GET, POST, PUT, DELETE
        self.url = url  # e.g. /index.html
        self.headers = headers
        self.request_data = request_data
        self.body = body

    @classmethod
    def from_socket(cls, sock: socket.socket) -> "Request":
        # read the request from socket
        # get method, url and headers
        request_data = sock.recv(4096).decode("utf-8")
        if not request_data:
            return None

        # http请求一般是用\r\n来分割的
        request_lines = request_data.split("\r\n")
        request_line = request_lines[0] # GET / HTTP/1.1 这种的
        print(f"request line: {request_line}")
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

        body = ''
        if 'Content-Length' in headers:
            content_length = int(headers.get("Content-Length"))
            # \r\n是用来分割header和body的
            # http经典规定
            data_start = request_data.find("\r\n\r\n") + 4
            body = request_data[data_start:data_start + content_length]

        print(f"request method: {method}")
        print(f"request url: {url}")

        # return the final result
        return cls(method, url, headers, request_data, body)

    def __repr__(self) -> str:
        # output request
        request = "{} {} HTTP/1.1\r\n".format(self.method, self.url)
        request += "\r\n".join("{}: {}".format(k, v) for k, v in self.headers.items())
        request += "\r\n\r\n"
        request += self.request_data.split("\r\n\r\n", 1)[1]  # Append file data
        return request

    


class Response:
    # a simple response class containing status code, headers and body
    def __init__(self):
        self.status_code = 200
        self.body = b"OK."
        self.headers = {"Connection": "keep-alive"}
        # The connection will be closed only when the client sends a "Connection: close" header.

    def generate_status_line(self):
        # 规定啊HTTp
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
        return response.encode("utf-8") + self.body


class HTTPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.shutdown_flag = threading.Event()
        self.authorized_users = {
            "client1": "123",
            "client2": "123",
            "client3": "123"
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
            elif self.check_method_allowance(request) is False:
                response.status_code = 405
            elif self.check_authorization(request) is False:
                # Invalid Authorization header: username and password not match
                response.status_code = 401
            else:
                # print(f"authorized user: {request.headers.get('Authorization')}")
                if request.method == "POST":
                    self.handle_post(response, request, client_socket)
                elif request.method == "GET":
                    # Handle GET request
                    self.handle_get(response, request)
                elif request.method == "HEAD":
                    # Handle HEAD request
                    response.set_strbody("<h1>Hello World</h1>")
                else:
                    # Error handling
                    response.status_code = 405
            client_socket.sendall(response.generate_response_bytes())
            if request.headers.get("Connection") == "close":
                client_socket.close()
                break


    def check_authorization(self, request):
        # Get the username and password from the Authorization header
        # As the info is encoded in base64, we need to decode it first
        base64_string = request.headers.get("Authorization").split(" ")[1]
        base64_bytes = base64_string.encode("utf-8")
        authorization = base64.b64decode(base64_bytes).decode("utf-8")
        username, password = authorization.split(":")
        # Check if the username and password are valid
        if username in self.authorized_users and self.authorized_users[username] == password:
            return True
        else:
            return False


    def check_method_allowance(self, request):
        if request.url.startswith("/upload?") or request.url.startswith("/delete?"):
            if request.method != "POST":
                return False
        elif request.url.startswith("/") and request.url != "/":
            if request.method != "GET":
                return False
        return True


    def handle_get(self, response, request):
        # http://localhost:8080/[access_path]?SUSTech-HTTP=[01]
        # access_path is the relative path under the /data/ folder
        # If the requested target is a folder, the SUSTech-HTTP parameter is OPTIONAL
        # If the requested target is a file, the SUSTech-HTTP parameter will be ignored
        relative_path = request.url.split("?")[0]
        path = root_dir + relative_path
        # if "SUSTech-HTTP" not in request.url:
        #     response.status_code = 400
        #     return

        # Check if the user is valid
        # if relative_path != "/":
        #     username_in_path = request.url.split("=")[-1].split("/")[0]
        #     print(f"username in path: {username_in_path}")
        #     base64_string = request.headers.get("Authorization").split(" ")[1]
        #     base64_bytes = base64_string.encode("utf-8")
        #     authorization = base64.b64decode(base64_bytes).decode("utf-8")
        #     username, password = authorization.split(":")
        #     # print(f"username: {username}, username in path: {username_in_path}")
        #     if username != username_in_path or self.authorized_users[username] != password:
        #         response.status_code = 403
        #         return

        enable = False


        operation = request.url.split("=")[-1]
        if os.path.isdir(path):
            if operation == "0" or "SUSTech-HTTP" not in request.url:
                response.set_content_type(HTML)
                response.set_strbody(gen_page(path, self.port, "http://localhost:8080/upload?path=", enable))
            elif operation == "1":
                # Response with the name of all items in list under the target directory
                response.set_content_type(TEXT)
                response.set_strbody(gen_txt(path))
        elif os.path.isfile(path):
            response.set_content_type(FILE)
            response.set_bbody(build_file_bytes(path))
        else:
            response.status_code = 404
            return

    def handle_upload(self, response, request):
        print("UPLOAD", "start")
        # upload url: http://localhost:8080/upload?path=11912113/

        # Check if the target directory exist
        path = root_dir + '/' +  request.url.split("=")[-1].strip('/')  # root_dir = os.curdir + '/data'
        if not os.path.isdir(path):
            response.status_code = 404
            return 

        print(request.body)
        print(request.request_data)
        # 格式如下

        # ------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n
        # Content-Disposition: form-data; name="firstfile"; filename="a.txt"\r\n
        # Content-Type: text/plain\r\n
        # \r\n
        # 123\r\n
        # ------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n

        # 其中------WebKitFormBoundary7MA4YWxkTrZu0gW是boundary，在request的header中
        # Content-Disposition: form-data; name="firstfile"; filename="a.txt"中的filename是文件名
        # \r\n\r\n之后的是文件内容, 即123\r\n

        lines = request.body.split("\r\n")
        body = request.body.split("\r\n\r\n")[1]
        filename = None
        boundary = lines[0]
        for line in lines:
            # 找到文件名
            if line.startswith("Content-Disposition"):
                    # this line contains information of file
                    # e.g. Content-Disposition: form-data; name="firstfile"; filename="a.txt"
                    filename = line.split("filename=")[1].strip('"')
        body_end = body.find(boundary)
        content = body[:body_end-4] # -4去掉最后的\r\n\r\n

        with open(f'{path}/{filename}', 'wb') as file:
            file.write(content.encode("utf-8"))
            file.close()
        return 


    def handle_delete(self, response, request):
        # delete url: http://localhost:8080/delete?path=/11912113/abc.py
        # Check if the target file exist
        path = root_dir + "/" + request.url.split("=")[-1].strip("/")
        if not os.path.isfile(path):
            response.status_code = 404
            return 

        # Delete the file
        os.remove(path)
        response.status_code = 200
        return 

    def handle_post(self, response, request, client_socket):
        # post = upload + delete
        if request.url.startswith("/upload?") or request.url.startswith("/delete?"):
            # Check if path is provided
            if "path=" not in request.url:
                response.status_code = 400
                return

            # Check if the user is valid

            # 首先获取用户名
            # qq群里消息有要求支持以下三种形式
            # ?path=/client1/  ?path=client1/ ?path=client1
            username_in_path = None
            # request.url.split("=")[-1] 获取 path=/client1/abc.py的=后面的部分
            # strip('/') 去掉path前后的 /
            path = request.url.split("=")[-1].strip('/')
            # 剩下的path可能是 client1/abc.py 或者 client1
            # 比如 delete?path=client1/abc.py 或者 upload?path=client1
            if '/' in path: # delete?path=client1/abc.py的形式
                username_in_path = path.split('/')[0]
            else: # e.g. upload?path=client1的形式
                username_in_path = path
            # path =  http://localhost:8080/upload?path=/11912113/
            base64_string = request.headers.get("Authorization").split(" ")[1]
            base64_bytes = base64_string.encode("utf-8")
            authorization = base64.b64decode(base64_bytes).decode("utf-8")
            username_in_authorization, password = authorization.split(":")
            # whether this user 可以上传文件到这个文件夹
            if username_in_authorization != username_in_path:
                # e.g. current user: 123 but the path is /upload?path=/123
                print("username in path", f"{username_in_path}")
                print("username in authorization", f"{username_in_authorization}")
                response.status_code = 403
                return
            

            if request.url.startswith("/upload?"):
                # this means the user would like to upload files
                self.handle_upload(response, request)
            else:
                # delete file
                self.handle_delete(response, request)
                
        else:
            response.set_strbody("<h1>Other POST</h1>")



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
