# HTTP status code descriptions
import random

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


def gen_boundary():
    alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    length = 32
    boundary = ''
    for _ in range(length):
        boundary += random.choice(alphabet)
    return boundary


def display_some(content):
    """Display the content, if the length exceeds 1024, we'll just display the first 1024 bytes."""
    if len(content) > 1024:
        print(content[:1024])
        print('...')
    else:
        print(content)


def extract_url_and_args(url: str):
    """Get url and args from GET request.

    For example, GET /some_url?user=abc&pass=123 will return some_url and {user: abc, pass: 123}
    """
    # For example, GET /{some_url}?user=abc&pass={123}
    parts = url.split('?')
    if len(parts) == 1:
        # This GET doesn't have any arguments.
        return parts[0], {}
    else:
        args_dict = {}
        args_part = parts[-1]
        key_vals = args_part.split('&')
        for key_val in key_vals:
            key, val = key_val.split('=')
            args_dict[key] = val
        return parts[0], args_dict


def extract_every_part(body: bytes, boundary:str) -> list[bytes]:
    """In a form body, there may be several parts seperated by the boundary.

    This method returns a list containing every part.
    """
    lines = body.split(b'\r\n')
    boundary_idxs = [i for i in range(len(lines)) if lines[i].find(boundary.encode('utf-8')) != -1]
    all_parts = []
    for i in range(len(boundary_idxs) - 1):
        all_parts.append([lines[j] for j in range(boundary_idxs[i] + 1, boundary_idxs[i + 1])])
    all_parts = [b'\r\n'.join(part) for part in all_parts]
    return all_parts


def extract_from_part(part: bytes) -> list[dict, bytes]:
    """In each part, we get the body and non-body part."""
    non_body, body = part.split(b'\r\n\r\n', 1)
    lines = non_body.split(b'\r\n')
    headers = {}
    for line in lines:
        key, val = line.split(b':', 1)
        headers[key.strip().decode('utf-8')] = val.strip().decode('utf-8')
    return headers, body


def get_boundary(content_type: str):
    """Extract boundary from a string."""
    idx = content_type.find('boundary=')
    return content_type[idx + 9:].strip('-')