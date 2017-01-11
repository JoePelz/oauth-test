import socket
import ssl


# gen certificate:
# openssl req -x509 -sha256 -nodes -newkey rsa:2048 -days 365 -keyout localhost.key -out localhost.crt

def do_something(connection_stream, data):
    print(" Do something ".center(50, '='))
    print(dir(connection_stream))
    print(connection_stream)
    print(data)


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
    context.load_cert_chain(certfile="mycertfile", keyfile="mykeyfile")

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