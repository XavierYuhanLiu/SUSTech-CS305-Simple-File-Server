from server import Response

codes = [200, 206, 301, 400, 401, 403, 404, 405, 416, 502, 503]

for code in codes:
    response = Response(code, "<h1>Hello World!</h1>")
    print(response.generate_response_bytes())