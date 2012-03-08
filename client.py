# TCP client example
import socket, time, random, sys
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 5000))
while 1:
    data = client_socket.recv(512)
    sys.stderr.write(".")
    client_socket.send('ping')
    time.sleep(random.random() + 0.5)