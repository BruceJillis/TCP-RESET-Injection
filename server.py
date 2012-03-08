# simple TCP server example
import socket, sys
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(("localhost", 5000))
server_socket.listen(5)

sys.stderr.write("TCP Server binding to port 5000\n")

while 1:
    client_socket, address = server_socket.accept()
    sys.stderr.write("I got a connection from %s:%s\n" % address)
    while 1:
        client_socket.send('pong')
        data = client_socket.recv(512)
        sys.stderr.write(".")