import re
import socket
import traceback

HOST = 'cs5700fa20.ccs.neu.edu'  # Server hostname or IP address
PORT = 80  # Port


def generaterHeader(method, path):
    return ("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (method, path, HOST)).encode();


def getCookie():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (socket.gethostbyname(HOST), PORT)

    try:
        client_socket.connect(server_address)

        request_header = generaterHeader("GET", '/accounts/login/?next=/fakebook/')
        client_socket.sendall(request_header)

        response = []
        while True:
            recv = client_socket.recv(2048)
            if not recv:
                break
            response = recv.decode().split('\r\n\r\n')
            # print(recv.decode())

        csrfToken = re.findall('csrftoken=[^;]*', response[0])[0].split('=')[1]
        sessionId = re.findall('sessionid=[^;]*', response[0])[0].split('=')[1]

        # print(csrfToken)
        # print(sessionId)
        return csrfToken, sessionId
    except Exception:
        print(traceback.format_exc())

    finally:
        client_socket.close()


cookie = getCookie()
if cookie:
    csrfToken = cookie[0]
    sessionId = cookie[1]
    print(csrfToken)
    print(sessionId)
