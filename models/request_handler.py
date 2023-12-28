import os

from models.code_template import render_page
from models.http_model import Response, get_response_by_error_code
from models.util import extract_url_and_args, get_boundary, extract_every_part, extract_from_part
from models.auth_core import extract_usr_pass


root_dir = os.curdir + '/data'

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


class RequestHandler:
    def __init__(self, server, request):
        self.server = server
        self.request = request
        self.response = Response()
        self.response.set_content_type(HTML)
        self.chunked = False

    def handle(self):
        if self.request.http_type.startswith('ENCRYPTION'):
            # # 自定义 encryption 协议
            # # 好孩子不要这么做，违法哟～
            # # 我认真的！
            # if self.encryption_handle(request, response, client_socket):
            #     response.encryption = True
            #     response.symmetric_key = self.client_symmetric_key[client_socket]
            #     response.iv = self.client_ivs[client_socket]
            #     response.set_strbody("encrypted response")
            #     self.auth_handle(request.headers, response)
            pass
        else:
            # Whether the method is with a proper url, 405 if not
            if not is_method_allowed(self.request.url, self.request.method):
                return get_response_by_error_code(405)

            # Authentication part
            auth_core = self.server.auth_core
            auth_res = auth_core.authenticate_headers(self.request.headers)
            # Pass
            if auth_res == 200:
                self.response.status_code = 200
            # Unauthorized
            elif auth_res == 401:
                return get_response_by_error_code(401)
            # Pass, given a new session-id
            else:
                # Auth_res is the new session_id
                self.response.status_code = 200
                self.response.set_header('Set-Cookie', f'session-id={auth_res}')

        # Handle the request corresponding to its method
        method = self.request.method
        if method == 'POST':
            self.post()
        elif method == 'GET':
            self.get()
        elif method == 'HEAD':
            self.head()
        else:
            return get_response_by_error_code(405)
        return self.response

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
        enable = False

        relative_path, kargs = extract_url_and_args(self.request.url)
        path = root_dir + '/' + relative_path.strip('/')
        if os.path.isdir(path):
            if "SUSTech-HTTP" not in kargs or kargs["SUSTech-HTTP"] == '0':
                self.response.set_content_type(HTML)
                self.response.set_strbody(render_page(path, self.server.port, "http://localhost:8080/upload?path=", enable))
            elif kargs["SUSTech-HTTP"] == 1:
                # Response with the name of all items in list under the target directory
                self.response.set_content_type(TEXT)
                self.response.set_strbody(gen_txt(path))
        elif os.path.isfile(path):
            self.response.set_content_type(FILE)
            if 'chunked' in kargs and kargs['chunked'] == '1':
                self.response.set_bbody(file2chunked_bytes(path))
                self.response.set_header('Transfer-Encoding', 'chunked')
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