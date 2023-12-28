# HTTP status code descriptions
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


def write_data(data: bytes):
    lines = data.split(b'\r\n')
    with open('log', 'wb') as f:
        f.write(data)


def extract_url_and_args(url: str):
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


def extract_every_part(body: bytes, boundary:str):
    lines = body.split(b'\r\n')
    boundary_idxs = [i for i in range(len(lines)) if lines[i].find(boundary.encode('utf-8')) != -1]
    print(boundary_idxs)
    all_parts = []
    for i in range(len(boundary_idxs) - 1):
        all_parts.append([lines[j] for j in range(boundary_idxs[i] + 1, boundary_idxs[i + 1])])
    all_parts = [b'\r\n'.join(part) for part in all_parts]
    return all_parts


def extract_from_part(part: bytes):
    non_body, body = part.split(b'\r\n\r\n', 1)
    lines = non_body.split(b'\r\n')
    headers = {}
    for line in lines:
        key, val = line.split(b':', 1)
        headers[key.strip().decode('utf-8')] = val.strip().decode('utf-8')
    return headers, body


def get_boundary(content_type: str):
    idx = content_type.find('boundary=')
    return content_type[idx + 9:]