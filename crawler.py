import re
import socket
import traceback

HOST = 'cs5700fa20.ccs.neu.edu'  # Server hostname or IP address
PORT = 80  # Port


def generaterHeader(method, path, cookie, data):
    if method == 'POST':
        prefix = "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded" \
                 "\r\nContent-Length: %s\r\n" % (method, path, HOST, len(data))
    else:
        prefix = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, HOST)

    if cookie and data:
        return ("%sCookie: %s\r\n\r\n%s" % (prefix, cookie, data)).encode();
    elif not data and cookie:
        return ("%sCookie: %s\r\n\r\n" % (prefix, cookie)).encode();

    elif data and not cookie:
        return ("%s\r\n%s" % (prefix, data)).encode();

    return ("%s\r\n" % prefix).encode();


def getCookie():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (socket.gethostbyname(HOST), PORT)

    try:
        client_socket.connect(server_address)

        request_header = generaterHeader("GET", '/accounts/login/?next=/fakebook/', None, None)
        client_socket.sendall(request_header)

        response = []
        while True:
            recv = client_socket.recv(2048)
            if not recv:
                break
            response = recv.decode().split('\r\n\r\n')
            print(recv.decode())

        csrfToken = re.findall('csrftoken=[^;]*;', response[0])[0]
        sessionId = re.findall('sessionid=[^;]*;', response[0])[0]

        # print(csrfToken)
        # print(sessionId)
        return csrfToken + sessionId
    except Exception:
        print(traceback.format_exc())

    finally:
        client_socket.close()


def login(cookie):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (socket.gethostbyname(HOST), PORT)
    try:
        client_socket.connect(server_address)

        # TODO: replace credentials
        request_header = generaterHeader("POST", '/accounts/login/', cookie, 'username=001445026&password=JHXZX0UI&next=%2Ffakebook%2F&csrfmiddlewaretoken='+ cookie.split(";")[0].split('=')[1])
        client_socket.sendall(request_header)

        response = []
        while True:
            recv = client_socket.recv(2048)
            if not recv:
                break
            response = recv.decode().split('\r\n\r\n')
            # print(recv.decode())

        # csrfToken = re.findall('csrftoken=[^;]*;', response[0])[0]
        sessionId = re.findall('sessionid=[^;]*;', response[0])[0]

        # print(csrfToken)
        print(sessionId)

        tmp = cookie.split(";")
        tmp[1] = sessionId[:-1]

        login_header = generaterHeader("GET", "/fakebook/", ';'.join(tmp), None)
        # login_header = ("GET /fakebook/ HTTP/1.1\r\nHost: cs5700fa20.ccs.neu.edu\r\n"
        #                 "DNT: 1\r\nReferer: http://cs5700.ccs.neu.edu/accounts/login/?next=/fakebook/\r\nCookie: "+';'.join(tmp)+"\r\nConnection: keep-alive\r\n\r\n").encode()
        print(login_header.decode())
        client_socket.sendall(login_header)

        while True:
            recv = client_socket.recv(2048)
            print(recv.decode())
            if not recv:
                print('no res')
                break
            response = recv.decode().split('\r\n\r\n')



    except Exception:
        print(traceback.format_exc())

    finally:
        client_socket.close()


cookie = getCookie()
if cookie:
    print(cookie)
    login(cookie)
