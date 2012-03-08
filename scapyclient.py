# this script can connect to server.py and receive the first pong to check if everything is working

from scapy.all import *
conf.L3socket = L3RawSocket
s = conf.L3socket(iface="lo")

src = '127.0.0.1'
sport = 59152
dst = '127.0.0.1'
dport = 5000

# tcp 3 way handshake
ip=IP(src=src, dst=dst)
TCP_SYN=TCP(sport=sport, dport=dport, flags="S", seq=100)
SYN = ip/TCP_SYN
print SYN.show2()

TCP_SYNACK = sr1(SYN)
print TCP_SYNACK.summary()
print TCP_SYNACK[TCP].flags

TCP_ACK=TCP(sport=sport, dport=dport, flags="A", seq=TCP_SYNACK.ack, ack=TCP_SYNACK.seq + 1)
send(ip/TCP_ACK)

# receive first pong
p = s.recv(512)
print 'recv:', p.show()