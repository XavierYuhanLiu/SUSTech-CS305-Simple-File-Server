from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from modules.auth_core import extract_usr_pass
from modules.code_template import render_page
from modules.encryption import *
from modules.http_model import Response, get_response_by_error_code, get_response_200
from modules.util import extract_url_and_args, get_boundary, extract_every_part, extract_from_part, gen_boundary

root_dir = os.curdir + '/data'

CRLF = b'\r\n'
MEGABYTE = 1024 * 1024
HTML = "text/html"
FILE = "application/octet-stream"
TEXT = "text/plain"


def is_method_allowed(url, method):
    if url.startswith('/upload?') or url.startswith('/delete?'):
        return method == 'POST'
    elif url.startswith('/') and url != '/':
        if method != 'GET' and method != 'HEAD':
            return False
    return True


def gen_txt(path):
    # Response with the name of all items in list under the target directory
    # `["123.png", "666/", "abc.py", "favicon.ico"]` in this case.
    items = os.listdir(path)
    # Convert list to str
    items = str(items)
    return items


def file2bytes(path: str) -> bytes:
    """
    Convert a file into a bytes object.
    :param path: Path to the file
    :return: Binary content of the file
    """
    body = b''
    with open(path, 'rb') as f:
        while True:
            some_bytes = f.read(64 * MEGABYTE)
            if not some_bytes:
                break
            body += some_bytes
    return body


def file2chunked_bytes(path: str) -> bytes:
    # start = time.time()
    body = b''
    # chunk_size = 512
    with open(path, 'rb') as f:
        while True:
            some_bytes = f.read(64 * MEGABYTE)
            if not some_bytes:
                break
            body += f'{len(some_bytes):X}\r\n'.encode('utf-8') + some_bytes + b'\r\n'
    body += b'0\r\n\r\n'
    # end = time.time()
    # print(end - start)
    return body


def get_filesize(path: str) -> int:
    # It's guaranteed the file exists
    return os.stat(path).st_size


def analyze_range(range_str: str, filesize: int):
    """Example formats:

    * 0-200
    * -200
    * 400-
    """
    range_list = range_str.split('-')
    if len(range_list) != 2:
        return None
    if '' in range_list:
        if range_list[0] == '':
            # -200
            ran = int(range_list[1])
            if ran > filesize or ran <= 0:
                return None
            return [filesize - ran, filesize]
        elif range_list[1] == '':
            # 400-
            ran = int(range_list[0])
            if ran < 0 or ran >= filesize:
                return None
            return [ran, filesize]
        else:
            return None
    else:
        l = int(range_list[0])
        r = int(range_list[1])
        if 0 <= l <= r < filesize:
            return [l, r + 1]
        else:
            return None


class RequestHandler:
    def __init__(self, server):
        self.server = server
        self.request = None
        self.response = None

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        self.symmetric_key = None
        self.iv = None

    def handle_request(self, request):
        self.request = request
        self.response = Response()

        response = self.handle()
        self.clear()
        return response

    def clear(self):
        self.request = None
        self.response = None

    def handle(self):
        if self.request.http_type == 'PREENCRYPTION':
            self.pre_encryption()
            return self.response

        if not self.is_proper_request():
            if self.request.http_type.startswith('ENCRYPTION'):
                self.response.set_bbody(encrypt_sym(self.response.body, self.symmetric_key, self.iv))
                return self.response
            else:
                return self.response
        if self.request.http_type.startswith('ENCRYPTION'):
            self.request.body = decrypt_sym(self.request.body, self.symmetric_key, self.iv)

        # Handle the request corresponding to its method
        method = self.request.method
        if method == 'POST':
            self.post()
        elif method == 'GET':
            self.get()
        elif method == 'HEAD':
            self.head()
        else:
            self.response = get_response_by_error_code(405)

        if self.request.http_type.startswith('ENCRYPTION'):
            self.response.set_bbody(encrypt_sym(self.response.body, self.symmetric_key, self.iv))
        return self.response

    def is_proper_request(self) -> bool:
        """False means Response starts with 4xx
        True means Response starts with 2xx"""
        # Whether the method is with a proper url, 405 if not
        if not is_method_allowed(self.request.url, self.request.method):
            self.response = get_response_by_error_code(405)
            return False

        # Authentication part
        auth_core = self.server.auth_core
        auth_res = auth_core.authenticate_headers(self.request.headers)
        # Pass
        if auth_res == 200:
            self.response.status_code = 200
            return True
        # Unauthorized
        elif auth_res == 401:
            self.response = get_response_by_error_code(401)
            return False
        # Pass, given a new session-id
        else:
            # Auth_res is the new session_id
            self.response.status_code = 200
            self.response.set_header('Set-Cookie', f'session-id={auth_res}')
            return True

    def pre_encryption(self):
        method = self.request.method
        url = self.request.url
        if url == '/public_key' and method == 'GET':
            # The client want to get the public key from the server.
            self.response.set_content_type(FILE)
            self.response.status_code = 200
            self.response.set_bbody(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        elif url == '/encrypted_symmetric_key' and method == 'POST':
            # The client is sending his/her encrypted key to the server.
            encrypted_symmetric_key = self.request.body
            self.symmetric_key = decrypt_asy(encrypted_symmetric_key, self.private_key)
            print('Symmetric key set.')
            body = '<h1>Received the symmetric key.</h1>'
            self.response = get_response_200(body.encode('utf-8'))
        elif url == '/encrypted_iv' and method == 'POST':
            # The client is sending his/her encrypted iv to the server.
            encrypted_iv = self.request.body
            self.iv = decrypt_asy(encrypted_iv, self.private_key)
            print('iv set.')
            body = '<h1>Received the iv.</h1>'
            self.response = get_response_200(body.encode('utf-8'))
        else:
            # The server replies with 400 Bad Request.
            self.response = get_response_by_error_code(400)

    def post(self):
        url, kargs = extract_url_and_args(self.request.url)
        if url.startswith('/upload') or url.startswith('/delete'):
            if 'path' not in kargs:
                self.response = get_response_by_error_code(400)
                return

            path = kargs['path'].strip('/')
            username = path.split('/')[0]

            base64str = self.request.headers['Authorization'].split(" ")[1]
            usr_in_auth, _ = extract_usr_pass(base64str)

            # username in path must correspond to usr_in_auth.
            if usr_in_auth != username:
                print('username in path', f'{username}')
                print('username in authorization', f'{usr_in_auth}')
                self.response = get_response_by_error_code(403)
                return

            if url.startswith('/upload'):
                # Upload
                self.upload(path)
            else:
                # Delete
                self.delete(path)
        else:
            self.response.set_strbody('<h1>Other POST</h1>')
        self.response.build_length_or_chunked()

    def get(self):
        # http://localhost:8080/[access_path]?SUSTech-HTTP=[01]
        # access_path is the relative path under the /data/ folder
        # If the requested target is a directory, parameter 'SUSTech-HTTP' will affect the display behavior
        # Parameter 'chunked' will be ignored

        # If the requested target is a file, parameter 'SUSTech-HTTP' will be ignored
        # Parameter 'chunked' decides whether to chunk the data
        relative_path, kargs = extract_url_and_args(self.request.url)
        path = root_dir + '/' + relative_path.strip('/')
        if os.path.isdir(path):
            if "SUSTech-HTTP" not in kargs or kargs["SUSTech-HTTP"] == '0':
                self.response.set_content_type(HTML)
                base64str = self.request.headers['Authorization'].split(" ")[1]
                usr_in_auth, _ = extract_usr_pass(base64str)
                self.response.set_strbody(render_page(path, self.server.port, usr_in_auth, base64str))
            elif kargs["SUSTech-HTTP"] == '1':
                # Response with the name of all items in list under the target directory
                self.response.set_content_type(TEXT)
                self.response.set_strbody(gen_txt(path))
        elif os.path.isfile(path):
            self.response.set_content_type(FILE)
            if 'chunked' in kargs and kargs['chunked'] == '1':
                self.response.set_bbody(file2chunked_bytes(path))
                self.response.set_header('Transfer-Encoding', 'chunked')
            elif 'Range' in self.request.headers:
                self.partial(self.request.headers['Range'], path)
            else:
                self.response.set_bbody(file2bytes(path))
        else:
            self.response = get_response_by_error_code(404)
        self.response.build_length_or_chunked()

    def head(self):
        self.get()
        self.response.set_bbody(b'')

    def upload(self, url):
        print('START UPLOADING')
        # upload url example: http://localhost:8080/upload?path=clientx/

        path = root_dir + '/' + url
        if not os.path.isdir(path):
            self.response = get_response_by_error_code(404)
            return

        # One possible format for multipart/form-data

        # ------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n
        # Content-Disposition: form-data; name="firstFile"; filename="a.txt"\r\n
        # Content-Type: text/plain\r\n
        # \r\n
        # 123\r\n
        # ------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n
        # Content-Disposition: form-data; name="secondFile"; filename="b.txt"\r\n
        # Content-Type: text/plain\r\n
        # \r\n
        # 456\r\n
        # ------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n

        # Warning: this form can contain multiple parts, please do NOT assume there are only TWO boundaries.

        boundary = get_boundary(self.request.headers['Content-Type'])
        print('The boundary of the form is: ', boundary)
        muti_parts = extract_every_part(self.request.body, boundary)
        print(f'This form contains {len(muti_parts)} file(s) in total.')
        # Extract every part, then extract the head and body, then write files.
        for part in muti_parts:
            headers, body = extract_from_part(part)
            if 'Content-Disposition' in headers:
                filename = headers['Content-Disposition'].split("filename=")[1].strip('"')
            else:
                filename = os.urandom(10)

            f = open(f'{path}/{filename}', 'wb')
            try:
                f.write(body)
                print(f'File [{filename}] uploaded successfully.')
            except Exception:
                print(f'Oops fails to upload file [{filename}].')
            finally:
                f.close()
        print()

    def delete(self, url):
        # delete url: http://localhost:8080/delete?path=/clientx/samplefile
        # Check if the target file exist
        path = root_dir + "/" + url
        if not os.path.isfile(path):
            self.response = get_response_by_error_code(404)
            return
            # Delete the file
        os.remove(path)
        print('FILE ' + path + ' has been removed successfully'.upper())

    def partial(self, head_range: str, path):
        all_ranges = head_range.split(',')
        if len(all_ranges) == 1:
            filesize = get_filesize(path)
            range_list = analyze_range(all_ranges[0], filesize)
            if range_list is None:
                self.response = get_response_by_error_code(416)
            else:
                file_bytes = file2bytes(path)
                content_range = f'bytes {range_list[0]}-{range_list[1] - 1}/{filesize}'
                self.response.status_code = 206
                self.response.set_header('Content-Range', content_range)
                self.response.set_bbody(file_bytes[range_list[0]:range_list[1]])
        else:
            filesize = get_filesize(path)
            range_list = []
            for range_str in all_ranges:
                ran = analyze_range(range_str, filesize)
                if ran is None:
                    self.response = get_response_by_error_code(416)
                    return
                range_list.append(ran)

            boundary = gen_boundary()
            self.response.set_content_type('multipart/byteranges; boundary=' + boundary)
            self.response.status_code = 206
            # self.response.set_bbody(b'Still working...')

            filebytes = file2bytes(path)
            body = b''
            for ran in range_list:
                first_line = b'--' + boundary.encode('utf-8')
                content_type = 'Content-Type: ' + FILE
                content_range = f'Content-Range: bytes {ran[0]}-{ran[1] - 1}/{filesize}'

                part_body = filebytes[ran[0]:ran[1]]
                body += first_line + CRLF + \
                    content_type.encode('utf-8') + CRLF + \
                    content_range.encode('utf-8') + CRLF + \
                    CRLF + \
                    part_body + CRLF
            body += b'--' + boundary.encode('utf-8') + b'--'
            self.response.set_bbody(body)
