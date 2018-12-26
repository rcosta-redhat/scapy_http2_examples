#!/bin/python

import scapy
import socket
import ssl
import struct

from scapy.all import *
from scapy.contrib.http2 import *

H2_H_LEN_FIELD_SIZE = 3
H2_H_SIZE = 9

# This is the most famous http2 magic number
MAGIC='PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

# Simple connection function. This time we use TLS to connect
def connect(dst, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Easiest alternative here is to use ssl, which encapsulates
    # OpenSSL
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    # It is REQUIRED to choose a protocol over ALPN, when using TLS,
    # according to HTTP/2 RFC (see section 3.3 from RFC7540 for more details)
    context.set_alpn_protocols(['h2'])

    # Finally wrap our socket with the openssl one. Note the latter was
    # created from the context we setup.
    conn = context.wrap_socket(sock, server_hostname = dst)

    # Usual connect call here
    rv = conn.connect_ex((dst, port))

    # According to ALPN, server must acknowledge client's choice, so let's
    # print it
    print("ALPN: " + str(conn.selected_alpn_protocol()))

    return conn

# Get the MSB and a the least significant half-word and merge them
# Note: this uses network byte order
def conv_barray_to_len(barray):
    msb = struct.unpack(">B", bytes(barray)[0])[0]
    lsh = struct.unpack(">H", barray[1:3])[0]

    return (msb << 2) | lsh

def fetch_h2_frame(sock):
    # Fetch just the size (3 bytes field)
    raw_pkg = bytearray(sock.recv(H2_H_LEN_FIELD_SIZE))

    frm_len = conv_barray_to_len(raw_pkg) # little hack here since struct
                                              # can't handle 3-bytes field

    # Read entire frame including 9-bytes header 3 were already read)
    frm_len += H2_H_SIZE
    while len(raw_pkg) < frm_len:
        raw_pkg.extend(sock.recv(frm_len - len(raw_pkg)))

    frame = H2Frame(raw_pkg) # delegates to Scapy to interpret. Gets a
                                 # filled H2Frame obj

    return frame
