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
urls = set() # The set that could add paths which is visited.
frontier = queue.Queue() # the queue that could add paths which is not visited.


def generaterHeader(method, path, cookie, data):
    """The function that generate HTTP Header
    Args:
        method: HTTP Methods 'GET','POST'.
        path: The web page path, e.g. /fakebook/.
        cookie: The data of csrfToken and sessionId.
        data: The data of user's information.
    Returns: 
        String return the encoded version of the HTTP Header
    """

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
    """The function that get HTTP cookie from server
    Returns: 
        String return csrfToken and sessionId
    """
    # Set the socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (socket.gethostbyname(HOST), PORT)

    try:
        client_socket.connect(server_address)                 # Try to connect the server

        request_header = generaterHeader("GET", '/accounts/login/?next=/fakebook/', None, None) 
        client_socket.sendall(request_header)                 # Send request

        while True:                                           # Get response
            recv = client_socket.recv(2048)
            if not recv:
                continue
            response = recv.decode().split('\r\n\r\n')

            # Using regex to get csrftoken and sessionid
            csrfToken = re.findall('csrftoken=[^;]*;', response[0])[0]
            sessionId = re.findall('sessionid=[^;]*;', response[0])[0]

            return csrfToken + sessionId
    except Exception:
        print(traceback.format_exc())

    finally:
        client_socket.close()


def login(cookie,username,password):
    """Login Fakebook by using username and password
    Args:
        cookie: The data of csrfToken and sessionId.
        username: Neu id
        password: login password
    Returns:
        String return the new cooike after successful login
    """
    
    # Set the socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (socket.gethostbyname(HOST), PORT)
    str = '%2Ffakebook%2F'
     # Set the data by using username and password
    data = 'username=%s&password=%s&next=%s&csrfmiddlewaretoken=%s' % (username, password, str, cookie.split(";")[0].split('=')[1])
    
    # Try to connect the server
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
        
        # Renew the HTTP cookie
        cookie = renewCookie(cookie, response[0])
        frontier.put('/fakebook/')
        urls.add('/fakebook/')
        return cookie
    except Exception:
        print(traceback.format_exc())

    finally:
        client_socket.close()

def statusHandler(response):
    """Get the HTTP status code
    Args:
        response: the information from server
    Returns:
        String return a status code e.g. '200', '500'.
    """
    status = re.findall(r'HTTP/1.1\s([0-9]*)',response) # Using regex to find the status code
    return status[0]

def reDirectPath(response):
    """Get the redirect path when status code is 301
    Args:
        response: the information from server
    Returns:
        String return a redirect path  
    """

    # Using regex to find new URL given by the server.
    path = re.findall(r'Location: http://cs5700fa20.ccs.neu.edu(.*)',response)
    if path:
        return path[0]
    else:
        return '/fakebook/' #If did not find the new path on Target Domain, return '/fakebook/'

def getRsponse(path, cookie):
    """Get the response by given path. 
    When status code is 500, it will re-try the request for the URL until the request is successful.
    
    Args:
        path: the path in the frontier
        cookie: HTTP cookie
    Returns:
        String return a response from server 
    """
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
    """Get the links on web page. 
    Go through all the links available on the page. But web pages may include 
    links that point to arbitrary domains. Crawler should only traverse URLs that
    point to pages on cs5700fa20.ccs.neu.edu by limit the links using regex /{path}/, 
    which must be paths in the target domain.
    
    Args:
        path: the path in the frontier
        cookie: HTTP cookie
    """
    links = re.findall('<a href="(/[^>]+)">', response)
    for path in links:
        if path in urls:
            continue
        frontier.put(path) 
        urls.add(path)


def crawl(cookie):
    """ Crawl the path which in the frontier
    Args:
        cookie: HTTP cookie
    """
    cnt = 0 # count the numbers of flags
    if frontier.empty():
        return

    while (not frontier.empty()) and cnt < 5:
        path = frontier.get()

        response = getRsponse(path,cookie) # Get response from server

        if len(response) == 0:
            return response

        status = statusHandler(response[0]) # Check the status code
        
        if status == "200":                 # if status is 200, find the vaild links and add to frontier and urls
            cnt += getSecret(response[1])
            getLinks(response[1])
        elif status == "301":               # if status is 301, find the redirect path and re-try the request
            path = reDirectPath(response[0])
            response = getRsponse(path,cookie)
            getLinks(response[1])
                                            # If status is 404 or 403, abandon the URL that generated the error code.
        elif status == "404" or status == "403":  
            pass
        


# Renew the cookie after successful login
def renewCookie(cookie, header):
    sessionId = re.findall('sessionid=[^;]*;', header)[0]
    tmp = cookie.split(";")
    tmp[1] = sessionId[:-1]
    return ';'.join(tmp)

# Get the secret flags on web page by using regex
def getSecret(content):
    cnt = 0
    for secret in re.findall('<h2 class=\'secret_flag\' style="color:red">FLAG: ([^<]+)</h2>', content):
        cnt += 1
        print(secret)
    return cnt


if __name__ == '__main__':
    username = sys.argv[1]
    password = sys.argv[2]

    cookie = getCookie()
    if cookie:
        cookie = login(cookie,username,password)
        crawl(cookie)

