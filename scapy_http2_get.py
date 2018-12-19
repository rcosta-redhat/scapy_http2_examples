#!/bin/python

import scapy
import socket
import struct

from scapy.all import *
from scapy.contrib.http2 import *

H2_H_LEN_FIELD_SIZE = 3
H2_H_SIZE = 9

# Simple connection function
def connect(dst, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rv = sock.connect_ex((dst, port))

    return sock

# Get the MSB and a the least significant half-word and merge them
# Note: this uses network byte order
def conv_barray_to_len(barray):
    msb = struct.unpack(">B", bytes(barray)[0])[0]
    lsh = struct.unpack(">H", barray[1:3])[0]

    return (msb << 2) | lsh

def fetch_http2_page(sock, dst):

    # Request info in text form. This will be converted to binary
    # form before being sent to server.
    txt_req =  b'''\
:method GET
:path /
:scheme http
:authority %s
user-agent: curl/7.61.1
accept: */*
''' % dst

    # This is the most famous http2 magic number
    MAGIC='PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    sock.send(MAGIC)

    # Create a settings frame and set (in order): max concurrent streams,
    # initial window size and disable push
    stg_frm=H2Frame()/H2SettingsFrame()
    stg_frm['H2SettingsFrame'].settings += [
            H2Setting(id=H2Setting.SETTINGS_MAX_CONCURRENT_STREAMS, value=100),
            H2Setting(id=H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=1073741824),
            H2Setting(id=H2Setting.SETTINGS_ENABLE_PUSH, value=0)]

    # Create a window update and set window size
    winupd_frm=H2Frame()/H2WindowUpdateFrame(scapy.utils.binascii.unhexlify('3fff0001'))

    # Create helper class and parse above text request, effectively
    # converting the request to binary form.
    hdrtbl = HPackHdrTable()
    h2seq = hdrtbl.parse_txt_hdrs(txt_req) # It generates a H2Seq for us

    # Add the setting frames above before the header frame
    h2seq.frames.insert(0, stg_frm)
    h2seq.frames.insert(1, winupd_frm)

    # Send package sequence over the TCP socket
    sock.send(raw(h2seq))

    # Now start receiving data and handling them. Must manually fetch
    # complete frames before delegating to Scapy to interpret them.
    # Arbitrary stop point here is a DATA frame with the 'End Stream'
    # flag set.
    fSeq = H2Seq()
    while True:
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

        fSeq.frames.append(frame) # Insert into the frame sequence which will be
                                  # provided as answer

        # Check if flag end stream is set
        if isinstance(frame, H2Frame) and 'ES' in frame.flags:
            break

    # return the sequence
    return fSeq


if "__main__" == __name__:
    dst = 'www.uol.com.br'
    port = 80

    sock = connect(dst, port)
    seq = fetch_http2_page(sock, dst)

    seq.display()

    sock.close()


