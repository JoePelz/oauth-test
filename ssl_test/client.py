import pprint
import socket
import ssl

context = ssl.create_default_context()
context.load_verify_locations("./localhost.crt")

conn = context.wrap_socket(socket.socket(socket.AF_INET),
                           server_hostname="localhost")
conn.connect(("localhost", 8081))
cert = conn.getpeercert()
pprint.pprint(cert)