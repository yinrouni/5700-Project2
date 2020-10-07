import re
import socket
import sys
import traceback
try:
    import queue
except ImportError:
    import Queue as queue


HOST = 'cs5700fa20.ccs.neu.edu'  # Server hostname or IP address
PORT = 80  # Port
urls = set()
frontier = queue.Queue()


def generaterHeader(method, path, cookie, data):
    if method == 'POST':
        prefix = "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded" \
                 "\r\nContent-Length: %s\r\n" % (method, path, HOST, len(data))
    else:
        prefix = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, HOST)

    if cookie and data:
        return ("%sCookie: %s\r\n\r\n%s" % (prefix, cookie, data)).encode()
    elif not data and cookie:
        return ("%sCookie: %s\r\n\r\n" % (prefix, cookie)).encode()

    elif data and not cookie:
        return ("%s\r\n%s" % (prefix, data)).encode()

    return ("%s\r\n" % prefix).encode()


def getCookie():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (socket.gethostbyname(HOST), PORT)

    try:
        client_socket.connect(server_address)

        request_header = generaterHeader("GET", '/accounts/login/?next=/fakebook/', None, None)
        client_socket.sendall(request_header)

        while True:
            recv = client_socket.recv(2048)
            if not recv:
                continue
            response = recv.decode().split('\r\n\r\n')

            csrfToken = re.findall('csrftoken=[^;]*;', response[0])[0]
            sessionId = re.findall('sessionid=[^;]*;', response[0])[0]

            return csrfToken + sessionId
    except Exception:
        print(traceback.format_exc())

    finally:
        client_socket.close()


def login(cookie,username,password):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (socket.gethostbyname(HOST), PORT)
    str = '%2Ffakebook%2F'
    data = 'username=%s&password=%s&next=%s&csrfmiddlewaretoken=%s' % (username, password, str, cookie.split(";")[0].split('=')[1])
    try:
        client_socket.connect(server_address)                                             
        request_header = generaterHeader("POST", '/accounts/login/', cookie, data)
        client_socket.sendall(request_header)

        response = []
        while True:
            recv = client_socket.recv(2048)
            if not recv:
                continue
            response = recv.decode().split('\r\n\r\n')
            break

        cookie = renewCookie(cookie, response[0])
        frontier.put('/fakebook/')
        urls.add('/fakebook/')
        return cookie
    except Exception:
        print(traceback.format_exc())

    finally:
        client_socket.close()




def statusHandler(response):
    status = response.split('\r\n')[0]
    status = status.split(" ")[1]
    return status

def reDirectPath(response):
    path = response.split('\r\n')[0]
    path = path.split(" ")[6]
    path = path.split(HOST)[1]
    return path

def getRsponse(path, cookie):
     while True:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (socket.gethostbyname(HOST), PORT)
        response = []
        try:
                client_socket.connect(server_address)
                header = generaterHeader("GET", path, cookie, None)

                client_socket.sendall(header)
                while True:
                    recv = client_socket.recv(2048)
                    if not recv:
                        continue
                    response = recv.decode().split('\r\n\r\n')
                    break  
        except Exception:
            traceback.format_exc()
        finally:
            client_socket.close()
        if response:
            status = statusHandler(response[0])
            if status == "500":
                continue
            else:
                return response
        else:
            continue

def getLinks(response):
    links = re.findall('<a href="(/[^>]+)">', response)
    for path in links:
        if path in urls:
            continue
        frontier.put(path)
        urls.add(path)


def crawl(cookie):
    cnt = 0
    if frontier.empty():
        return

    while (not frontier.empty()) and cnt < 5:
        path = frontier.get()

        response = getRsponse(path,cookie)

        if len(response) == 0:
            return response

        status = statusHandler(response[0])
        if status == "200":
            cnt += getSecret(response[1])
            getLinks(response[1])
        elif status == "301":
            print("Status: 301 Moved Permanently, redirecting...")
            path = reDirectPath(response[0])
            response = getRsponse(path,cookie)
            getLinks(response[1])
        elif status == "404" or status == "403":
            print("Not found page, pass")
        elif status == "302":
            print("Please enter a correct username and password. Note that both fields are case-sensitive.")
        else:
            print(status)



def renewCookie(cookie, header):
    sessionId = re.findall('sessionid=[^;]*;', header)[0]
    tmp = cookie.split(";")
    tmp[1] = sessionId[:-1]
    return ';'.join(tmp)


def getSecret(content):
    cnt = 0
    for secret in re.findall('<h2 class=\'secret_flag\' style="color:red">FLAG: ([^<]+)</h2>', content):
        cnt += 1
        print(secret)
    return cnt


if __name__ == '__main__':
    username = sys.argv[1]
    password = sys.argv[2]

    # TODO: login using crendential
    cookie = getCookie()
    if cookie:
        cookie = login(cookie,username,password)
        crawl(cookie)

