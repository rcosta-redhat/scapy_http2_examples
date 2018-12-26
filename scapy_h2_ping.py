#!/bin/python

import scapy
from scapy.all import *
import scapy.contrib.http2
import random
import socket
import time
import sys
import thread

from scapy.contrib.http2 import *

from scapy_h2_utils import connect, fetch_h2_frame

MAGIC='PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

def do_h2ping(sock, rawdata, val):
    sock.send(MAGIC)
    h2ping=H2Frame()/H2PingFrame(opaque=val)

    sock.send(raw(h2ping))

    # fetch (and discard packages) until you get ping reply
    while True:
        ans_frm = fetch_h2_frame(sock)
        # flags must have ACK set
        if ans_frm.type == H2PingFrame.type_id and 'A' in ans_frm.flags:
                ping_reply = ans_frm.payload

                if ping_reply.opaque == h2ping.opaque:
                    return (h2ping, ans_frm)

if "__main__" == __name__:
    dst = 'arstechnica.com'
    port = 443
    val = random.getrandbits(8)

    sock = connect(dst, port)
    t1 = time.time()
    ping_req, ping_reply = do_h2ping(sock, dst, val)
    t2 = time.time()

    print("Ping delay: " + str(t2 - t1))

    print("Ping request display:")
    ping_req.show2()
    print("Ping reply display:")
    ping_reply.display()

    sock.close()
