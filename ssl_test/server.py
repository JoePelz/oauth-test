import socket
import ssl


# gen self-signed certificate:
# openssl req -x509 -sha256 -nodes -newkey rsa:2048 -days 365 -keyout localhost.key -out localhost.crt
# to use in firefox, install exception for localhost certificate. May need to restart server a few times while doing so.

example_response = \
"""HTTP/1.1 200 OK
Date: Sun, 18 Oct 2009 08:56:53 GMT
Server: Apache/2.2.14 (Win32)
Last-Modified: Sat, 20 Nov 2004 07:16:26 GMT
ETag: "10000000565a5-2c-3e94b66c2e680"
Accept-Ranges: bytes
Content-Length: 44
Connection: close
Content-Type: text/html
X-Pad: avoid browser bug

<html><body><h1>It works!</h1></body></html>"""


def do_something(connection_stream, data):
    print(" Do something ".center(50, '='))
    print(" dir(connection_stream) ".center(50, '-'))
    print(dir(connection_stream))
    print(" connection_stream ".center(50, '-'))
    print(connection_stream)
    print(" data ".center(50, '-'))
    print(data)
    print(" end ".center(50, '-'))
    connection_stream.sendall(example_response)


def deal_with_client(connection_stream):
    data = connection_stream.read()
    # null data means the client is finished with us
    while data:
        if not do_something(connection_stream, data):
            # we'll assume do_something returns False
            # when we're finished with client
            break
        data = connection_stream.read()
    # finished with client


def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="./localhost.crt", keyfile="./localhost.key")

    bindsocket = socket.socket()
    bindsocket.bind(('localhost', 8081))
    bindsocket.listen(5)

    while True:
        newsocket, fromaddr = bindsocket.accept()
        connection_stream = context.wrap_socket(newsocket, server_side=True)
        try:
            deal_with_client(connection_stream)
        finally:
            connection_stream.shutdown(socket.SHUT_RDWR)
            connection_stream.close()

if __name__ == "__main__":
    main()